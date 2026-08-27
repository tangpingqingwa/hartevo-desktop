//! Mission-scoped, host-verified Skill Pack provider and model-context seam.
//!
//! This module is deliberately a protocol boundary. It validates an
//! attested package snapshot and composes model-visible instructions, recipes,
//! and typed capability requirements, but it never opens files, follows a
//! symlink, starts a runner, resolves a secret, or owns an Effect/Store/
//! keyring/Browser Profile authority. A host supplies a verified package and
//! a gateway supplies typed capability resolution.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, ConsumerKind, Digest, PluginDefinition,
    PluginDefinitionHandle, PluginError, PluginId, PluginLifecycle, PluginRuntime, PluginScope,
    PluginVersion, ProviderCardinality, ProviderDefinition, ProviderId, RegistrationReceipt,
    RevocationReceipt, ServiceAccess, ServiceDefinition, ServiceId, UnmountReceipt,
};

pub const SKILL_PACK_SERVICE_ID: &str = "skill.pack.service";
pub const SKILL_PACK_SERVICE_SCHEMA: &str = "hartevo.skill-pack-service/v1";
pub const SKILL_PACK_MANIFEST_SCHEMA: &str = "hartevo.skill-pack-manifest/v1";
pub const SKILL_PACK_SOURCE_SCHEMA: &str = "hartevo.skill-pack-source/v1";
pub const SKILL_PACK_VERIFICATION_SCHEMA: &str = "hartevo.skill-pack-verification/v1";
pub const SKILL_PACK_POLICY_SCHEMA: &str = "hartevo.skill-pack-policy/v1";
pub const SKILL_PACK_RECEIPT_SCHEMA: &str = "hartevo.skill-pack-receipt/v1";
pub const SKILL_PACK_AUDIT_SCHEMA: &str = "hartevo.skill-pack-audit/v1";
pub const SKILL_PACK_CONTEXT_SCHEMA: &str = "hartevo.skill-pack-context/v1";
pub const MAX_SKILL_PATH_BYTES: usize = 512;
pub const MAX_SKILL_TEXT_BYTES: usize = 512 * 1024;
pub const MAX_SKILL_FILES: usize = 512;

/// The single typed service seam exported by a Skill Pack provider.
///
/// The runtime owns registration and lifecycle only. It does not grant the
/// provider any host authority; required side effects remain typed gateway
/// capabilities in the package manifest.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SkillPackService;

impl SkillPackService {
    pub const ID: &'static str = SKILL_PACK_SERVICE_ID;

    pub fn definition() -> Result<ServiceDefinition, SkillPackError> {
        let id = ServiceId::new(Self::ID).map_err(SkillPackError::from)?;
        ServiceDefinition::read_only(
            id,
            PluginVersion::new(1, 0, 0),
            Digest::from_text(SKILL_PACK_SERVICE_SCHEMA),
            ProviderCardinality::Many,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(SkillPackError::from)
    }
}

fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serialized(value)
}

fn validate_digest(value: &Digest) -> Result<(), SkillPackError> {
    value.validate().map_err(SkillPackError::from)
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), SkillPackError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(|character| character == '\0')
    {
        return Err(SkillPackError::InvalidText);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackErrorCode {
    InvalidText,
    InvalidPath,
    InvalidDigest,
    InvalidSchema,
    InvalidIdentifier,
    InvalidPackage,
    UnknownFile,
    MissingFile,
    SymlinkEscape,
    PathDrift,
    SignatureUnavailable,
    Disconnected,
    DigestMismatch,
    HostApiMismatch,
    ScopeMismatch,
    GenerationMismatch,
    PolicyDenied,
    MissingCapability,
    CapabilityMismatch,
    Plugin,
    MountMissing,
    PluginRevoked,
    PluginUnmounted,
    SessionClosed,
    AuditCommitFailed,
    ContextReceiptInvalid,
    UpgradeMigrationRequired,
    UpgradeFailed,
    Crash,
    LateConsumer,
    HostReleaseFailed,
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SkillPackError {
    #[error("Skill Pack text is invalid")]
    InvalidText,
    #[error("Skill Pack path is invalid or escapes its package root")]
    InvalidPath,
    #[error("Skill Pack digest is invalid")]
    InvalidDigest,
    #[error("Skill Pack schema is invalid")]
    InvalidSchema,
    #[error("Skill Pack identifier is invalid")]
    InvalidIdentifier,
    #[error("Skill Pack package is invalid")]
    InvalidPackage,
    #[error("Skill Pack contains an unknown file")]
    UnknownFile,
    #[error("Skill Pack is missing a manifest file")]
    MissingFile,
    #[error("Skill Pack symlink would escape its package root")]
    SymlinkEscape,
    #[error("Skill Pack path or source drifted")]
    PathDrift,
    #[error("Skill Pack signature is unavailable")]
    SignatureUnavailable,
    #[error("Skill Pack host is disconnected")]
    Disconnected,
    #[error("Skill Pack digest does not match its verified contents")]
    DigestMismatch,
    #[error("Skill Pack host API version is incompatible")]
    HostApiMismatch,
    #[error("Skill Pack Project/Mission scope does not match")]
    ScopeMismatch,
    #[error("Skill Pack generation does not match")]
    GenerationMismatch,
    #[error("Skill Pack is denied by Mission policy")]
    PolicyDenied,
    #[error("Skill Pack requires a missing or disallowed capability")]
    MissingCapability,
    #[error("Skill Pack capability resolution is not exact")]
    CapabilityMismatch,
    #[error("plugin runtime rejected the Skill Pack mount")]
    Plugin(PluginError),
    #[error("Skill Pack mount is missing or inactive")]
    MountMissing,
    #[error("Skill Pack was revoked")]
    PluginRevoked,
    #[error("Skill Pack was unmounted")]
    PluginUnmounted,
    #[error("Skill Pack session is closed")]
    SessionClosed,
    #[error("Skill Pack durable audit commit failed")]
    AuditCommitFailed,
    #[error("Skill Pack context receipt is invalid")]
    ContextReceiptInvalid,
    #[error("Skill Pack upgrade has no verified migration")]
    UpgradeMigrationRequired,
    #[error("Skill Pack upgrade failed closed")]
    UpgradeFailed,
    #[error("Skill Pack host or consumer crashed")]
    Crash,
    #[error("Skill Pack consumer is late for the exact mounted generation")]
    LateConsumer,
    #[error("Skill Pack host release failed")]
    HostReleaseFailed,
    #[error("Skill Pack verification failed")]
    VerificationFailed,
}

impl From<PluginError> for SkillPackError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<super::PluginErrorCode> for SkillPackErrorCode {
    fn from(error: super::PluginErrorCode) -> Self {
        let _ = error;
        Self::Plugin
    }
}

impl From<super::PluginError> for SkillPackErrorCode {
    fn from(error: super::PluginError) -> Self {
        error.code().into()
    }
}

impl SkillPackError {
    pub const fn code(self) -> SkillPackErrorCode {
        match self {
            Self::InvalidText => SkillPackErrorCode::InvalidText,
            Self::InvalidPath => SkillPackErrorCode::InvalidPath,
            Self::InvalidDigest => SkillPackErrorCode::InvalidDigest,
            Self::InvalidSchema => SkillPackErrorCode::InvalidSchema,
            Self::InvalidIdentifier => SkillPackErrorCode::InvalidIdentifier,
            Self::InvalidPackage => SkillPackErrorCode::InvalidPackage,
            Self::UnknownFile => SkillPackErrorCode::UnknownFile,
            Self::MissingFile => SkillPackErrorCode::MissingFile,
            Self::SymlinkEscape => SkillPackErrorCode::SymlinkEscape,
            Self::PathDrift => SkillPackErrorCode::PathDrift,
            Self::SignatureUnavailable => SkillPackErrorCode::SignatureUnavailable,
            Self::Disconnected => SkillPackErrorCode::Disconnected,
            Self::DigestMismatch => SkillPackErrorCode::DigestMismatch,
            Self::HostApiMismatch => SkillPackErrorCode::HostApiMismatch,
            Self::ScopeMismatch => SkillPackErrorCode::ScopeMismatch,
            Self::GenerationMismatch => SkillPackErrorCode::GenerationMismatch,
            Self::PolicyDenied => SkillPackErrorCode::PolicyDenied,
            Self::MissingCapability => SkillPackErrorCode::MissingCapability,
            Self::CapabilityMismatch => SkillPackErrorCode::CapabilityMismatch,
            Self::Plugin(_) => SkillPackErrorCode::Plugin,
            Self::MountMissing => SkillPackErrorCode::MountMissing,
            Self::PluginRevoked => SkillPackErrorCode::PluginRevoked,
            Self::PluginUnmounted => SkillPackErrorCode::PluginUnmounted,
            Self::SessionClosed => SkillPackErrorCode::SessionClosed,
            Self::AuditCommitFailed => SkillPackErrorCode::AuditCommitFailed,
            Self::ContextReceiptInvalid => SkillPackErrorCode::ContextReceiptInvalid,
            Self::UpgradeMigrationRequired => SkillPackErrorCode::UpgradeMigrationRequired,
            Self::UpgradeFailed => SkillPackErrorCode::UpgradeFailed,
            Self::Crash => SkillPackErrorCode::Crash,
            Self::LateConsumer => SkillPackErrorCode::LateConsumer,
            Self::HostReleaseFailed => SkillPackErrorCode::HostReleaseFailed,
            Self::VerificationFailed => SkillPackErrorCode::VerificationFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SkillPackHostError {
    #[error("verified Skill Pack signature is unavailable")]
    SignatureUnavailable,
    #[error("verified Skill Pack host is disconnected")]
    Disconnected,
    #[error("Skill Pack host verification failed")]
    VerificationFailed,
    #[error("Skill Pack host returned an unknown file")]
    UnknownFile,
    #[error("Skill Pack host returned a symlink escape")]
    SymlinkEscape,
    #[error("Skill Pack host returned path drift")]
    PathDrift,
    #[error("Skill Pack host returned a digest mismatch")]
    DigestMismatch,
    #[error("Skill Pack host has no verified upgrade migration")]
    MigrationUnavailable,
    #[error("Skill Pack host release failed")]
    ReleaseFailed,
    #[error("Skill Pack host crashed")]
    Crashed,
}

impl From<SkillPackHostError> for SkillPackError {
    fn from(error: SkillPackHostError) -> Self {
        match error {
            SkillPackHostError::SignatureUnavailable => Self::SignatureUnavailable,
            SkillPackHostError::Disconnected => Self::Disconnected,
            SkillPackHostError::VerificationFailed => Self::VerificationFailed,
            SkillPackHostError::UnknownFile => Self::UnknownFile,
            SkillPackHostError::SymlinkEscape => Self::SymlinkEscape,
            SkillPackHostError::PathDrift => Self::PathDrift,
            SkillPackHostError::DigestMismatch => Self::DigestMismatch,
            SkillPackHostError::MigrationUnavailable => Self::UpgradeMigrationRequired,
            SkillPackHostError::ReleaseFailed => Self::HostReleaseFailed,
            SkillPackHostError::Crashed => Self::Crash,
        }
    }
}

macro_rules! define_skill_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, SkillPackError> {
                let value = value.into();
                if super::valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(SkillPackError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
                    .finish()
            }
        }
    };
}

define_skill_identifier!(SkillPackId);
define_skill_identifier!(SkillId);
define_skill_identifier!(SkillItemId);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SkillPackPath(String);

impl SkillPackPath {
    pub fn new(value: impl Into<String>) -> Result<Self, SkillPackError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SKILL_PATH_BYTES
            || value.trim() != value
            || value.starts_with('/')
            || value.contains('\\')
            || value.contains(':')
            || value.chars().any(char::is_control)
            || value
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(SkillPackError::InvalidPath);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SkillPackPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackPath")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillText(String);

impl SkillText {
    pub fn new(value: impl Into<String>) -> Result<Self, SkillPackError> {
        let value = value.into();
        validate_text(&value, MAX_SKILL_TEXT_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for SkillText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillText")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackFileKind {
    Regular,
    Symlink,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackFile {
    path: SkillPackPath,
    kind: SkillPackFileKind,
    bytes: Vec<u8>,
    symlink_target: Option<SkillPackPath>,
}

impl SkillPackFile {
    pub fn regular(path: SkillPackPath, bytes: Vec<u8>) -> Result<Self, SkillPackError> {
        if bytes.len() > MAX_SKILL_TEXT_BYTES * 2 {
            return Err(SkillPackError::InvalidPackage);
        }
        Ok(Self {
            path,
            kind: SkillPackFileKind::Regular,
            bytes,
            symlink_target: None,
        })
    }

    pub fn symlink(path: SkillPackPath, target: SkillPackPath) -> Result<Self, SkillPackError> {
        Ok(Self {
            path,
            kind: SkillPackFileKind::Symlink,
            bytes: Vec::new(),
            symlink_target: Some(target),
        })
    }

    pub fn path(&self) -> &SkillPackPath {
        &self.path
    }

    pub const fn kind(&self) -> SkillPackFileKind {
        self.kind
    }

    fn content_digest(&self) -> Digest {
        match (&self.kind, &self.symlink_target) {
            (SkillPackFileKind::Regular, None) => Digest::from_bytes(&self.bytes),
            (SkillPackFileKind::Symlink, Some(target)) => {
                digest_serialized(&(SKILL_PACK_SOURCE_SCHEMA, self.kind, target.as_str()))
            }
            _ => Digest::from_text("invalid-skill-file"),
        }
    }

    fn binding_digest(&self) -> Digest {
        digest_serialized(&(self.path.as_str(), self.kind, self.content_digest()))
    }

    fn text(&self) -> Result<SkillText, SkillPackError> {
        if self.kind != SkillPackFileKind::Regular || self.symlink_target.is_some() {
            return Err(SkillPackError::SymlinkEscape);
        }
        let text = std::str::from_utf8(&self.bytes).map_err(|_| SkillPackError::InvalidPackage)?;
        SkillText::new(text)
    }
}

impl fmt::Debug for SkillPackFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackFile")
            .field("path_digest", &Digest::from_text(self.path.as_str()))
            .field("kind", &self.kind)
            .field("content_digest", &self.content_digest())
            .field(
                "symlink_target_digest",
                &self
                    .symlink_target
                    .as_ref()
                    .map(|target| Digest::from_text(target.as_str())),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackSource {
    locator_digest: Digest,
    source_digest: Digest,
}

impl SkillPackSource {
    pub fn new(locator_digest: Digest, source_digest: Digest) -> Result<Self, SkillPackError> {
        validate_digest(&locator_digest)?;
        validate_digest(&source_digest)?;
        Ok(Self {
            locator_digest,
            source_digest,
        })
    }

    pub fn locator_digest(&self) -> &Digest {
        &self.locator_digest
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }
}

impl fmt::Debug for SkillPackSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackSource")
            .field("locator_digest", &self.locator_digest)
            .field("source_digest", &self.source_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillEffectClass {
    ReadOnly,
    EffectProposal,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillServiceRequirement {
    service_id: ServiceId,
    version: PluginVersion,
    contract_digest: Digest,
}

impl SkillServiceRequirement {
    pub fn new(
        service_id: ServiceId,
        version: PluginVersion,
        contract_digest: Digest,
    ) -> Result<Self, SkillPackError> {
        validate_digest(&contract_digest)?;
        let requirement = Self {
            service_id,
            version,
            contract_digest,
        };
        requirement.validate()?;
        Ok(requirement)
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(&(SKILL_PACK_MANIFEST_SCHEMA, self))
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        self.service_id.validate().map_err(SkillPackError::from)?;
        validate_digest(&self.contract_digest).map_err(|_| SkillPackError::InvalidDigest)
    }
}

impl fmt::Debug for SkillServiceRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillServiceRequirement")
            .field(
                "service_id_digest",
                &Digest::from_text(self.service_id.as_str()),
            )
            .field("version", &self.version)
            .field("contract_digest", &self.contract_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillToolRequirement {
    service_id: ServiceId,
    tool_id: ConsumerId,
    version: PluginVersion,
    descriptor_digest: Digest,
    effect_class: SkillEffectClass,
}

impl SkillToolRequirement {
    pub fn new(
        service_id: ServiceId,
        tool_id: ConsumerId,
        version: PluginVersion,
        descriptor_digest: Digest,
        effect_class: SkillEffectClass,
    ) -> Result<Self, SkillPackError> {
        validate_digest(&descriptor_digest)?;
        let requirement = Self {
            service_id,
            tool_id,
            version,
            descriptor_digest,
            effect_class,
        };
        requirement.validate()?;
        Ok(requirement)
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    pub fn tool_id(&self) -> &ConsumerId {
        &self.tool_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn descriptor_digest(&self) -> &Digest {
        &self.descriptor_digest
    }

    pub const fn effect_class(&self) -> SkillEffectClass {
        self.effect_class
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(&(SKILL_PACK_MANIFEST_SCHEMA, self))
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        self.service_id.validate().map_err(SkillPackError::from)?;
        self.tool_id.validate().map_err(SkillPackError::from)?;
        validate_digest(&self.descriptor_digest).map_err(|_| SkillPackError::InvalidDigest)
    }
}

impl fmt::Debug for SkillToolRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillToolRequirement")
            .field(
                "service_id_digest",
                &Digest::from_text(self.service_id.as_str()),
            )
            .field("tool_id_digest", &Digest::from_text(self.tool_id.as_str()))
            .field("version", &self.version)
            .field("descriptor_digest", &self.descriptor_digest)
            .field("effect_class", &self.effect_class)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackManifest {
    schema: String,
    package_id: SkillPackId,
    plugin_id: PluginId,
    skill_id: SkillId,
    version: PluginVersion,
    host_api: PluginVersion,
    files: BTreeMap<SkillPackPath, Digest>,
    instructions: BTreeMap<SkillItemId, SkillPackPath>,
    recipes: BTreeMap<SkillItemId, SkillPackPath>,
    required_services: Vec<SkillServiceRequirement>,
    required_tools: Vec<SkillToolRequirement>,
    manifest_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SkillPackManifestBody<'a> {
    schema: &'a str,
    package_id: &'a SkillPackId,
    plugin_id: &'a PluginId,
    skill_id: &'a SkillId,
    version: PluginVersion,
    host_api: PluginVersion,
    files: &'a BTreeMap<SkillPackPath, Digest>,
    instructions: &'a BTreeMap<SkillItemId, SkillPackPath>,
    recipes: &'a BTreeMap<SkillItemId, SkillPackPath>,
    required_services: &'a [SkillServiceRequirement],
    required_tools: &'a [SkillToolRequirement],
}

impl SkillPackManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: SkillPackId,
        plugin_id: PluginId,
        skill_id: SkillId,
        version: PluginVersion,
        host_api: PluginVersion,
        files: BTreeMap<SkillPackPath, Digest>,
        instructions: BTreeMap<SkillItemId, SkillPackPath>,
        recipes: BTreeMap<SkillItemId, SkillPackPath>,
        required_services: Vec<SkillServiceRequirement>,
        required_tools: Vec<SkillToolRequirement>,
    ) -> Result<Self, SkillPackError> {
        let mut manifest = Self {
            schema: SKILL_PACK_MANIFEST_SCHEMA.into(),
            package_id,
            plugin_id,
            skill_id,
            version,
            host_api,
            files,
            instructions,
            recipes,
            required_services,
            required_tools,
            manifest_digest: Digest::from_text("pending-skill-manifest"),
        };
        manifest.validate_without_digest()?;
        manifest.manifest_digest = manifest.computed_digest();
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn package_id(&self) -> &SkillPackId {
        &self.package_id
    }

    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    pub fn skill_id(&self) -> &SkillId {
        &self.skill_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn host_api(&self) -> PluginVersion {
        self.host_api
    }

    pub fn files(&self) -> &BTreeMap<SkillPackPath, Digest> {
        &self.files
    }

    pub fn instructions(&self) -> &BTreeMap<SkillItemId, SkillPackPath> {
        &self.instructions
    }

    pub fn recipes(&self) -> &BTreeMap<SkillItemId, SkillPackPath> {
        &self.recipes
    }

    pub fn required_services(&self) -> &[SkillServiceRequirement] {
        &self.required_services
    }

    pub fn required_tools(&self) -> &[SkillToolRequirement] {
        &self.required_tools
    }

    pub fn digest(&self) -> &Digest {
        &self.manifest_digest
    }

    fn validate_without_digest(&self) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_MANIFEST_SCHEMA
            || self.files.is_empty()
            || self.files.len() > MAX_SKILL_FILES
            || self.instructions.is_empty() && self.recipes.is_empty()
        {
            return Err(SkillPackError::InvalidSchema);
        }
        if !super::valid_identifier(self.package_id.as_str())
            || !super::valid_identifier(self.skill_id.as_str())
        {
            return Err(SkillPackError::InvalidIdentifier);
        }
        self.plugin_id.validate().map_err(SkillPackError::from)?;
        for (path, digest) in &self.files {
            if SkillPackPath::new(path.as_str().to_owned())? != *path {
                return Err(SkillPackError::PathDrift);
            }
            validate_digest(digest)?;
        }
        let mut item_ids = BTreeSet::new();
        for (item_id, path) in self.instructions.iter().chain(self.recipes.iter()) {
            if !super::valid_identifier(item_id.as_str()) {
                return Err(SkillPackError::InvalidIdentifier);
            }
            if !item_ids.insert(item_id.clone()) {
                return Err(SkillPackError::InvalidSchema);
            }
            if !self.files.contains_key(path) {
                return Err(SkillPackError::MissingFile);
            }
        }
        if self
            .instructions
            .values()
            .any(|path| self.recipes.values().any(|recipe_path| recipe_path == path))
        {
            return Err(SkillPackError::InvalidSchema);
        }
        for requirement in &self.required_services {
            requirement.validate()?;
        }
        for requirement in &self.required_tools {
            requirement.validate()?;
        }
        if self
            .required_services
            .windows(2)
            .any(|window| window[0] >= window[1])
            || self
                .required_tools
                .windows(2)
                .any(|window| window[0] >= window[1])
        {
            return Err(SkillPackError::InvalidSchema);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&SkillPackManifestBody {
            schema: &self.schema,
            package_id: &self.package_id,
            plugin_id: &self.plugin_id,
            skill_id: &self.skill_id,
            version: self.version,
            host_api: self.host_api,
            files: &self.files,
            instructions: &self.instructions,
            recipes: &self.recipes,
            required_services: &self.required_services,
            required_tools: &self.required_tools,
        })
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        self.validate_without_digest()?;
        if self.manifest_digest != self.computed_digest() {
            return Err(SkillPackError::DigestMismatch);
        }
        validate_digest(&self.manifest_digest)
    }
}

impl fmt::Debug for SkillPackManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackManifest")
            .field("manifest_digest", &self.manifest_digest)
            .field(
                "package_id_digest",
                &Digest::from_text(self.package_id.as_str()),
            )
            .field(
                "plugin_id_digest",
                &Digest::from_text(self.plugin_id.as_str()),
            )
            .field(
                "skill_id_digest",
                &Digest::from_text(self.skill_id.as_str()),
            )
            .field("version", &self.version)
            .field("host_api", &self.host_api)
            .field("file_count", &self.files.len())
            .field("instruction_count", &self.instructions.len())
            .field("recipe_count", &self.recipes.len())
            .field("required_service_count", &self.required_services.len())
            .field("required_tool_count", &self.required_tools.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackVerificationStatus {
    Verified,
    SignatureUnavailable,
    Disconnected,
}

impl fmt::Debug for SkillPackVerificationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Verified => "Verified",
            Self::SignatureUnavailable => "SignatureUnavailable",
            Self::Disconnected => "Disconnected",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackVerificationAttestation {
    pub status: SkillPackVerificationStatus,
    pub verifier_digest: Digest,
    pub signature_digest: Digest,
    pub source_digest: Digest,
    pub manifest_digest: Digest,
    pub content_digest: Digest,
    pub host_api: PluginVersion,
    pub verified_at: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackVerificationReceipt {
    schema: String,
    receipt_digest: Digest,
    status: SkillPackVerificationStatus,
    verifier_digest: Digest,
    signature_digest: Digest,
    source_digest: Digest,
    manifest_digest: Digest,
    content_digest: Digest,
    host_api: PluginVersion,
    verified_at: u64,
}

impl SkillPackVerificationReceipt {
    pub fn from_attestation(
        attestation: SkillPackVerificationAttestation,
    ) -> Result<Self, SkillPackError> {
        for digest in [
            &attestation.verifier_digest,
            &attestation.signature_digest,
            &attestation.source_digest,
            &attestation.manifest_digest,
            &attestation.content_digest,
        ] {
            validate_digest(digest)?;
        }
        if attestation.verified_at == 0 {
            return Err(SkillPackError::VerificationFailed);
        }
        let mut receipt = Self {
            schema: SKILL_PACK_VERIFICATION_SCHEMA.into(),
            receipt_digest: Digest::from_text("pending-skill-verification"),
            status: attestation.status,
            verifier_digest: attestation.verifier_digest,
            signature_digest: attestation.signature_digest,
            source_digest: attestation.source_digest,
            manifest_digest: attestation.manifest_digest,
            content_digest: attestation.content_digest,
            host_api: attestation.host_api,
            verified_at: attestation.verified_at,
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn is_verified(&self) -> bool {
        self.status == SkillPackVerificationStatus::Verified
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub const fn status(&self) -> &SkillPackVerificationStatus {
        &self.status
    }

    pub fn verifier_digest(&self) -> &Digest {
        &self.verifier_digest
    }

    pub fn signature_digest(&self) -> &Digest {
        &self.signature_digest
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub const fn host_api(&self) -> PluginVersion {
        self.host_api
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            SKILL_PACK_VERIFICATION_SCHEMA,
            self.status,
            &self.verifier_digest,
            &self.signature_digest,
            &self.source_digest,
            &self.manifest_digest,
            &self.content_digest,
            self.host_api,
            self.verified_at,
        ))
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_VERIFICATION_SCHEMA
            || self.receipt_digest != self.computed_digest()
        {
            return Err(SkillPackError::VerificationFailed);
        }
        for digest in [
            &self.receipt_digest,
            &self.verifier_digest,
            &self.signature_digest,
            &self.source_digest,
            &self.manifest_digest,
            &self.content_digest,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SkillPackVerificationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackVerificationReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("status", &self.status)
            .field("verifier_digest", &self.verifier_digest)
            .field("signature_digest", &self.signature_digest)
            .field("source_digest", &self.source_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("content_digest", &self.content_digest)
            .field("host_api", &self.host_api)
            .field("verified_at", &self.verified_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackLoadRequest {
    scope: PluginScope,
    policy_digest: Digest,
    source: SkillPackSource,
    expected_package_digest: Option<Digest>,
    expected_manifest_digest: Option<Digest>,
    expected_content_digest: Option<Digest>,
}

impl SkillPackLoadRequest {
    pub fn new(
        scope: PluginScope,
        policy_digest: Digest,
        source: SkillPackSource,
        expected_package_digest: Option<Digest>,
        expected_manifest_digest: Option<Digest>,
        expected_content_digest: Option<Digest>,
    ) -> Result<Self, SkillPackError> {
        validate_digest(&policy_digest)?;
        for digest in expected_package_digest
            .iter()
            .chain(expected_manifest_digest.iter())
            .chain(expected_content_digest.iter())
        {
            validate_digest(digest)?;
        }
        let request = Self {
            scope,
            policy_digest,
            source,
            expected_package_digest,
            expected_manifest_digest,
            expected_content_digest,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn scope(&self) -> &PluginScope {
        &self.scope
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn source(&self) -> &SkillPackSource {
        &self.source
    }

    pub fn expected_package_digest(&self) -> Option<&Digest> {
        self.expected_package_digest.as_ref()
    }

    pub fn expected_manifest_digest(&self) -> Option<&Digest> {
        self.expected_manifest_digest.as_ref()
    }

    pub fn expected_content_digest(&self) -> Option<&Digest> {
        self.expected_content_digest.as_ref()
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        self.scope.validate().map_err(SkillPackError::from)?;
        validate_digest(&self.policy_digest)?;
        Ok(())
    }
}

impl fmt::Debug for SkillPackLoadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackLoadRequest")
            .field("scope_digest", &self.scope.digest())
            .field("policy_digest", &self.policy_digest)
            .field("source", &self.source)
            .field("expected_package_digest", &self.expected_package_digest)
            .field("expected_manifest_digest", &self.expected_manifest_digest)
            .field("expected_content_digest", &self.expected_content_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackVerifiedPackage {
    manifest: SkillPackManifest,
    source: SkillPackSource,
    verification: SkillPackVerificationReceipt,
    files: BTreeMap<SkillPackPath, SkillPackFile>,
    package_digest: Digest,
    content_digest: Digest,
}

impl SkillPackVerifiedPackage {
    pub fn new(
        manifest: SkillPackManifest,
        source: SkillPackSource,
        files: &[SkillPackFile],
        verification: SkillPackVerificationReceipt,
    ) -> Result<Self, SkillPackError> {
        manifest.validate()?;
        if !verification.is_verified() {
            return Err(match verification.status() {
                SkillPackVerificationStatus::SignatureUnavailable => {
                    SkillPackError::SignatureUnavailable
                }
                SkillPackVerificationStatus::Disconnected => SkillPackError::Disconnected,
                SkillPackVerificationStatus::Verified => SkillPackError::VerificationFailed,
            });
        }
        verification.validate()?;
        if verification.manifest_digest() != manifest.digest()
            || verification.source_digest() != source.source_digest()
            || verification.host_api() != manifest.host_api()
        {
            return Err(SkillPackError::DigestMismatch);
        }
        let file_map = Self::validate_files(&manifest, files)?;
        let content_digest = Self::compute_content_digest(files);
        if verification.content_digest() != &content_digest {
            return Err(SkillPackError::DigestMismatch);
        }
        let package_digest = digest_serialized(&(
            SKILL_PACK_RECEIPT_SCHEMA,
            manifest.digest(),
            &source,
            &content_digest,
            verification.digest(),
        ));
        let package = Self {
            manifest,
            source,
            verification,
            files: file_map,
            package_digest,
            content_digest,
        };
        package.validate_with_files(&package.files)?;
        Ok(package)
    }

    pub fn manifest(&self) -> &SkillPackManifest {
        &self.manifest
    }

    pub fn source(&self) -> &SkillPackSource {
        &self.source
    }

    pub fn verification_receipt(&self) -> &SkillPackVerificationReceipt {
        &self.verification
    }

    pub fn package_digest(&self) -> &Digest {
        &self.package_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub fn content_digest_for_files(files: &[SkillPackFile]) -> Digest {
        Self::compute_content_digest(files)
    }

    fn compute_content_digest(files: &[SkillPackFile]) -> Digest {
        let mut bindings: Vec<_> = files.iter().map(SkillPackFile::binding_digest).collect();
        bindings.sort();
        digest_serialized(&(SKILL_PACK_SOURCE_SCHEMA, bindings))
    }

    fn validate_files(
        manifest: &SkillPackManifest,
        files: &[SkillPackFile],
    ) -> Result<BTreeMap<SkillPackPath, SkillPackFile>, SkillPackError> {
        if files.len() != manifest.files.len() || files.len() > MAX_SKILL_FILES {
            return if files.len() < manifest.files.len() {
                Err(SkillPackError::MissingFile)
            } else {
                Err(SkillPackError::UnknownFile)
            };
        }
        let mut file_map = BTreeMap::new();
        for file in files {
            if file.kind == SkillPackFileKind::Symlink {
                return Err(SkillPackError::SymlinkEscape);
            }
            if file_map.insert(file.path.clone(), file.clone()).is_some() {
                return Err(SkillPackError::UnknownFile);
            }
            let expected = manifest
                .files
                .get(file.path())
                .ok_or(SkillPackError::UnknownFile)?;
            if expected != &file.content_digest() {
                return Err(SkillPackError::DigestMismatch);
            }
        }
        if file_map.keys().ne(manifest.files.keys()) {
            return Err(SkillPackError::PathDrift);
        }
        Ok(file_map)
    }

    fn validate_with_files(
        &self,
        files: &BTreeMap<SkillPackPath, SkillPackFile>,
    ) -> Result<(), SkillPackError> {
        if self.package_digest
            != digest_serialized(&(
                SKILL_PACK_RECEIPT_SCHEMA,
                self.manifest.digest(),
                &self.source,
                &self.content_digest,
                self.verification.digest(),
            ))
        {
            return Err(SkillPackError::DigestMismatch);
        }
        for path in self
            .manifest
            .instructions
            .values()
            .chain(self.manifest.recipes.values())
        {
            let file = files.get(path).ok_or(SkillPackError::MissingFile)?;
            file.text()?;
        }
        Ok(())
    }

    fn instruction(
        &self,
        id: &SkillItemId,
        files: &BTreeMap<SkillPackPath, SkillPackFile>,
    ) -> Result<SkillInstruction, SkillPackError> {
        let path = self
            .manifest
            .instructions
            .get(id)
            .ok_or(SkillPackError::PolicyDenied)?;
        let file = files.get(path).ok_or(SkillPackError::MissingFile)?;
        Ok(SkillInstruction {
            id: id.clone(),
            content: file.text()?,
        })
    }

    fn recipe(
        &self,
        id: &SkillItemId,
        files: &BTreeMap<SkillPackPath, SkillPackFile>,
    ) -> Result<SkillRecipe, SkillPackError> {
        let path = self
            .manifest
            .recipes
            .get(id)
            .ok_or(SkillPackError::PolicyDenied)?;
        let file = files.get(path).ok_or(SkillPackError::MissingFile)?;
        Ok(SkillRecipe {
            id: id.clone(),
            content: file.text()?,
        })
    }

    fn files(&self) -> &BTreeMap<SkillPackPath, SkillPackFile> {
        &self.files
    }
}

impl fmt::Debug for SkillPackVerifiedPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackVerifiedPackage")
            .field("package_digest", &self.package_digest)
            .field("manifest_digest", self.manifest.digest())
            .field("source_digest", self.source.source_digest())
            .field("content_digest", &self.content_digest)
            .field("verification_receipt_digest", self.verification.digest())
            .field("version", &self.manifest.version())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackPolicySpec {
    pub allowed_package_ids: BTreeSet<SkillPackId>,
    pub allowed_skill_ids: BTreeSet<SkillId>,
    pub allowed_source_digests: BTreeSet<Digest>,
    pub allowed_instruction_ids: BTreeSet<SkillItemId>,
    pub allowed_recipe_ids: BTreeSet<SkillItemId>,
    pub allowed_capability_digests: BTreeSet<Digest>,
    pub host_api: PluginVersion,
}

impl fmt::Debug for SkillPackPolicySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackPolicySpec")
            .field(
                "allowed_package_set_digest",
                &digest_serialized(&self.allowed_package_ids),
            )
            .field(
                "allowed_skill_set_digest",
                &digest_serialized(&self.allowed_skill_ids),
            )
            .field(
                "allowed_source_set_digest",
                &digest_serialized(&self.allowed_source_digests),
            )
            .field(
                "allowed_instruction_set_digest",
                &digest_serialized(&self.allowed_instruction_ids),
            )
            .field(
                "allowed_recipe_set_digest",
                &digest_serialized(&self.allowed_recipe_ids),
            )
            .field(
                "allowed_capability_set_digest",
                &digest_serialized(&self.allowed_capability_digests),
            )
            .field("host_api", &self.host_api)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackPolicy {
    schema: String,
    policy_digest: Digest,
    spec: SkillPackPolicySpec,
}

impl SkillPackPolicy {
    pub fn new(spec: SkillPackPolicySpec) -> Result<Self, SkillPackError> {
        for digest in spec
            .allowed_source_digests
            .iter()
            .chain(spec.allowed_capability_digests.iter())
        {
            validate_digest(digest)?;
        }
        let policy_digest = digest_serialized(&(SKILL_PACK_POLICY_SCHEMA, &spec));
        let policy = Self {
            schema: SKILL_PACK_POLICY_SCHEMA.into(),
            policy_digest,
            spec,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn spec(&self) -> &SkillPackPolicySpec {
        &self.spec
    }

    fn allows_package(&self, manifest: &SkillPackManifest, source: &SkillPackSource) -> bool {
        self.spec
            .allowed_package_ids
            .contains(manifest.package_id())
            && self.spec.allowed_skill_ids.contains(manifest.skill_id())
            && self
                .spec
                .allowed_source_digests
                .contains(source.source_digest())
            && manifest.host_api() == self.spec.host_api
    }

    fn allows_instruction(&self, id: &SkillItemId) -> bool {
        self.spec.allowed_instruction_ids.contains(id)
    }

    fn allows_recipe(&self, id: &SkillItemId) -> bool {
        self.spec.allowed_recipe_ids.contains(id)
    }

    fn allows_capability(&self, digest: &Digest) -> bool {
        self.spec.allowed_capability_digests.contains(digest)
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_POLICY_SCHEMA
            || self.policy_digest != digest_serialized(&(SKILL_PACK_POLICY_SCHEMA, &self.spec))
        {
            return Err(SkillPackError::DigestMismatch);
        }
        for identifier in &self.spec.allowed_package_ids {
            if !super::valid_identifier(identifier.as_str()) {
                return Err(SkillPackError::InvalidIdentifier);
            }
        }
        for identifier in &self.spec.allowed_skill_ids {
            if !super::valid_identifier(identifier.as_str()) {
                return Err(SkillPackError::InvalidIdentifier);
            }
        }
        for identifier in self
            .spec
            .allowed_instruction_ids
            .iter()
            .chain(self.spec.allowed_recipe_ids.iter())
        {
            if !super::valid_identifier(identifier.as_str()) {
                return Err(SkillPackError::InvalidIdentifier);
            }
        }
        for digest in self
            .spec
            .allowed_source_digests
            .iter()
            .chain(self.spec.allowed_capability_digests.iter())
        {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SkillPackPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackPolicy")
            .field("policy_digest", &self.policy_digest)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillInstruction {
    id: SkillItemId,
    content: SkillText,
}

impl SkillInstruction {
    pub fn id(&self) -> &SkillItemId {
        &self.id
    }

    pub fn content(&self) -> &SkillText {
        &self.content
    }

    pub fn content_digest(&self) -> Digest {
        self.content.digest()
    }
}

impl fmt::Debug for SkillInstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillInstruction")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field("content_digest", &self.content.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillRecipe {
    id: SkillItemId,
    content: SkillText,
}

impl SkillRecipe {
    pub fn id(&self) -> &SkillItemId {
        &self.id
    }

    pub fn content(&self) -> &SkillText {
        &self.content
    }

    pub fn content_digest(&self) -> Digest {
        self.content.digest()
    }
}

impl fmt::Debug for SkillRecipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillRecipe")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field("content_digest", &self.content.digest())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackCapabilityResolution {
    scope_digest: Digest,
    policy_digest: Digest,
    services: Vec<SkillServiceRequirement>,
    tools: Vec<SkillToolRequirement>,
    resolution_digest: Digest,
}

impl SkillPackCapabilityResolution {
    pub fn from_requirements(
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        services: Vec<SkillServiceRequirement>,
        tools: Vec<SkillToolRequirement>,
    ) -> Result<Self, SkillPackError> {
        scope.validate().map_err(SkillPackError::from)?;
        policy.validate()?;
        let mut resolution = Self {
            scope_digest: scope.digest(),
            policy_digest: policy.digest().clone(),
            services,
            tools,
            resolution_digest: Digest::from_text("pending-skill-capability-resolution"),
        };
        resolution.validate_exact(scope, policy, &resolution.services, &resolution.tools)?;
        resolution.resolution_digest = resolution.computed_digest();
        resolution.validate()?;
        Ok(resolution)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn services(&self) -> &[SkillServiceRequirement] {
        &self.services
    }

    pub fn tools(&self) -> &[SkillToolRequirement] {
        &self.tools
    }

    pub fn digest(&self) -> &Digest {
        &self.resolution_digest
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            SKILL_PACK_CONTEXT_SCHEMA,
            &self.scope_digest,
            &self.policy_digest,
            &self.services,
            &self.tools,
        ))
    }

    fn validate(&self) -> Result<(), SkillPackError> {
        if self.resolution_digest != self.computed_digest() {
            return Err(SkillPackError::CapabilityMismatch);
        }
        validate_digest(&self.scope_digest)?;
        validate_digest(&self.policy_digest)?;
        if self
            .services
            .windows(2)
            .any(|window| window[0] >= window[1])
            || self.tools.windows(2).any(|window| window[0] >= window[1])
        {
            return Err(SkillPackError::CapabilityMismatch);
        }
        Ok(())
    }

    fn validate_exact(
        &self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        required_services: &[SkillServiceRequirement],
        required_tools: &[SkillToolRequirement],
    ) -> Result<(), SkillPackError> {
        if self.scope_digest != scope.digest() || self.policy_digest != *policy.digest() {
            return Err(SkillPackError::ScopeMismatch);
        }
        if self.services.as_slice() != required_services || self.tools.as_slice() != required_tools
        {
            return Err(SkillPackError::CapabilityMismatch);
        }
        for requirement in &self.services {
            if !policy.allows_capability(&requirement.digest()) {
                return Err(SkillPackError::PolicyDenied);
            }
        }
        for requirement in &self.tools {
            if !policy.allows_capability(&requirement.digest()) {
                return Err(SkillPackError::PolicyDenied);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for SkillPackCapabilityResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackCapabilityResolution")
            .field("resolution_digest", &self.resolution_digest)
            .field("scope_digest", &self.scope_digest)
            .field("policy_digest", &self.policy_digest)
            .field("service_count", &self.services.len())
            .field("tool_count", &self.tools.len())
            .finish_non_exhaustive()
    }
}

pub trait SkillPackCapabilityResolver {
    fn resolve(
        &mut self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        required_services: &[SkillServiceRequirement],
        required_tools: &[SkillToolRequirement],
    ) -> Result<SkillPackCapabilityResolution, SkillPackError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackPlugin {
    definition: PluginDefinition,
    package_digest: Digest,
    manifest_digest: Digest,
    content_digest: Digest,
    verification_receipt_digest: Digest,
    service_id: ServiceId,
    provider_id: ProviderId,
    consumer_id: ConsumerId,
}

impl SkillPackPlugin {
    pub fn from_verified(
        scope: PluginScope,
        package: &SkillPackVerifiedPackage,
        policy: &SkillPackPolicy,
    ) -> Result<Self, SkillPackError> {
        if package.manifest.host_api() != policy.spec.host_api
            || !policy.allows_package(&package.manifest, &package.source)
        {
            return Err(SkillPackError::PolicyDenied);
        }
        let service_id = ServiceId::new(SKILL_PACK_SERVICE_ID).map_err(SkillPackError::from)?;
        let version = package.manifest.version();
        let provider_id = ProviderId::new(format!(
            "skill.pack.provider.{}.v{}.v{}.v{}",
            package.manifest.package_id().as_str(),
            version.major(),
            version.minor(),
            version.patch()
        ))
        .map_err(SkillPackError::from)?;
        let consumer_id = ConsumerId::new(format!(
            "skill.pack.consumer.{}.v{}.v{}.v{}",
            package.manifest.skill_id().as_str(),
            version.major(),
            version.minor(),
            version.patch()
        ))
        .map_err(SkillPackError::from)?;
        let service = SkillPackService::definition()?;
        let provider = ProviderDefinition::new(
            provider_id.clone(),
            service_id.clone(),
            version,
            package.package_digest().clone(),
        )
        .map_err(SkillPackError::from)?;
        let descriptor_digest = digest_serialized(&(
            SKILL_PACK_CONTEXT_SCHEMA,
            package.manifest.digest(),
            package.content_digest(),
            package.verification_receipt().digest(),
            policy.digest(),
            package.manifest.required_services(),
            package.manifest.required_tools(),
        ));
        let consumer = ConsumerDefinition::tool(
            consumer_id.clone(),
            service_id.clone(),
            PluginVersion::new(1, 0, 0),
            descriptor_digest,
        )?;
        let definition = PluginDefinition::new(
            package.manifest.plugin_id().clone(),
            version,
            scope,
            super::PluginContributions {
                services: vec![service],
                providers: vec![provider],
                consumers: vec![consumer],
                ..super::PluginContributions::default()
            },
        )
        .map_err(SkillPackError::from)?;
        Ok(Self {
            definition,
            package_digest: package.package_digest().clone(),
            manifest_digest: package.manifest.digest().clone(),
            content_digest: package.content_digest().clone(),
            verification_receipt_digest: package.verification_receipt().digest().clone(),
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

    pub fn package_digest(&self) -> &Digest {
        &self.package_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub fn verification_receipt_digest(&self) -> &Digest {
        &self.verification_receipt_digest
    }

    pub fn define(
        &self,
        runtime: &mut PluginRuntime,
    ) -> Result<PluginDefinitionHandle, SkillPackError> {
        runtime
            .define(self.definition.clone())
            .map_err(SkillPackError::from)
    }

    pub fn mount(&self, runtime: &mut PluginRuntime) -> Result<SkillPackMount, SkillPackError> {
        let handle = self.define(runtime)?;
        let receipt = runtime.mount(&handle).map_err(SkillPackError::from)?;
        let mount = SkillPackMount {
            plugin: self.clone(),
            handle,
            receipt,
        };
        mount.validate_runtime(runtime)?;
        Ok(mount)
    }
}

impl fmt::Debug for SkillPackPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackPlugin")
            .field("plugin_digest", self.plugin_digest())
            .field("scope_digest", &self.scope().digest())
            .field("package_digest", &self.package_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("content_digest", &self.content_digest)
            .field(
                "verification_receipt_digest",
                &self.verification_receipt_digest,
            )
            .field(
                "service_id_digest",
                &Digest::from_text(self.service_id.as_str()),
            )
            .field(
                "provider_id_digest",
                &Digest::from_text(self.provider_id.as_str()),
            )
            .field(
                "consumer_id_digest",
                &Digest::from_text(self.consumer_id.as_str()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackMount {
    plugin: SkillPackPlugin,
    handle: PluginDefinitionHandle,
    receipt: RegistrationReceipt,
}

impl SkillPackMount {
    pub fn plugin(&self) -> &SkillPackPlugin {
        &self.plugin
    }

    pub fn handle(&self) -> &PluginDefinitionHandle {
        &self.handle
    }

    pub fn receipt(&self) -> &RegistrationReceipt {
        &self.receipt
    }

    pub fn validate_runtime(&self, runtime: &PluginRuntime) -> Result<(), SkillPackError> {
        let lifecycle = runtime
            .lifecycle(&self.handle)
            .map_err(SkillPackError::from)?;
        match lifecycle.lifecycle {
            PluginLifecycle::Mounted => {}
            PluginLifecycle::Revoked => return Err(SkillPackError::PluginRevoked),
            PluginLifecycle::Stopped => return Err(SkillPackError::PluginUnmounted),
            _ => return Err(SkillPackError::MountMissing),
        }
        if lifecycle.plugin_digest != *self.plugin.plugin_digest()
            || lifecycle.scope_digest != self.plugin.scope().digest()
            || lifecycle.receipt_digest.as_ref() != Some(self.receipt.digest())
        {
            return Err(SkillPackError::MountMissing);
        }
        let inspection = runtime.inspect(self.plugin.scope());
        if inspection.scope_digest != self.plugin.scope().digest()
            || inspection.generation != self.plugin.scope().generation()
            || !inspection.plugins.iter().any(|plugin| {
                plugin.plugin_digest == *self.plugin.plugin_digest()
                    && plugin.receipt_digest == *self.receipt.digest()
                    && plugin.version == self.plugin.definition().version()
            })
        {
            return Err(SkillPackError::MountMissing);
        }
        self.validate_contributions(&inspection)
    }

    pub fn unmount(&self, runtime: &mut PluginRuntime) -> Result<UnmountReceipt, SkillPackError> {
        self.validate_runtime(runtime)?;
        runtime.unmount(&self.receipt).map_err(SkillPackError::from)
    }

    pub fn revoke(&self, runtime: &mut PluginRuntime) -> Result<RevocationReceipt, SkillPackError> {
        self.validate_runtime(runtime)?;
        runtime.revoke(&self.handle).map_err(SkillPackError::from)
    }

    fn validate_contributions(
        &self,
        inspection: &super::RuntimeInspection,
    ) -> Result<(), SkillPackError> {
        let contributions = self.plugin.definition().contributions();
        let service = contributions
            .services
            .first()
            .ok_or(SkillPackError::MountMissing)?;
        let provider = contributions
            .providers
            .first()
            .ok_or(SkillPackError::MountMissing)?;
        let consumer = contributions
            .consumers
            .first()
            .ok_or(SkillPackError::MountMissing)?;
        let service_ok = inspection.services.iter().any(|candidate| {
            candidate.service_id_digest == Digest::from_text(service.id().as_str())
                && candidate.owner_plugin_digest == *self.plugin.plugin_digest()
                && candidate.version == service.version()
                && candidate.access == ServiceAccess::ReadOnly
                && candidate.contract_digest == *service.contract_digest()
        });
        let provider_ok = inspection.providers.iter().any(|candidate| {
            candidate.provider_id_digest == Digest::from_text(provider.id().as_str())
                && candidate.service_id_digest == Digest::from_text(provider.service_id().as_str())
                && candidate.owner_plugin_digest == *self.plugin.plugin_digest()
                && candidate.version == provider.version()
                && candidate.implementation_digest == *provider.implementation_digest()
        });
        let consumer_ok = inspection.consumers.iter().any(|candidate| {
            candidate.consumer_id_digest == Digest::from_text(consumer.id().as_str())
                && candidate.service_id_digest == Digest::from_text(consumer.service_id().as_str())
                && candidate.owner_plugin_digest == *self.plugin.plugin_digest()
                && candidate.kind == ConsumerKind::Tool
                && candidate.required_version == consumer.required_version()
                && candidate.descriptor_digest == *consumer.descriptor_digest()
        });
        if service_ok && provider_ok && consumer_ok {
            Ok(())
        } else {
            Err(SkillPackError::MountMissing)
        }
    }
}

impl fmt::Debug for SkillPackMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackMount")
            .field("plugin_digest", self.plugin.plugin_digest())
            .field("package_digest", self.plugin.package_digest())
            .field("scope_digest", &self.plugin.scope().digest())
            .field("receipt_digest", self.receipt.digest())
            .field("generation", &self.plugin.scope().generation())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackStatus {
    Mounted,
    Upgrading,
    Revoked,
    Unmounted,
    Failed,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackMissionContext {
    scope: PluginScope,
    policy_digest: Digest,
}

impl SkillPackMissionContext {
    pub fn new(scope: PluginScope, policy_digest: Digest) -> Result<Self, SkillPackError> {
        scope.validate().map_err(SkillPackError::from)?;
        validate_digest(&policy_digest)?;
        Ok(Self {
            scope,
            policy_digest,
        })
    }

    pub fn scope(&self) -> &PluginScope {
        &self.scope
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(&(SKILL_PACK_CONTEXT_SCHEMA, &self.scope, &self.policy_digest))
    }
}

impl fmt::Debug for SkillPackMissionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackMissionContext")
            .field("scope_digest", &self.scope.digest())
            .field("policy_digest", &self.policy_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackBindingMetadata {
    package_digest: Digest,
    plugin_digest: Digest,
    package_id_digest: Digest,
    skill_id_digest: Digest,
    version: PluginVersion,
    source_digest: Digest,
    manifest_digest: Digest,
    content_digest: Digest,
    verification_receipt_digest: Digest,
    host_api: PluginVersion,
    project_digest: Digest,
    mission_digest: Digest,
    scope_digest: Digest,
    generation: u64,
    policy_digest: Digest,
}

impl SkillPackBindingMetadata {
    fn from_package(
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        package: &SkillPackVerifiedPackage,
        plugin: &SkillPackPlugin,
    ) -> Self {
        Self {
            package_digest: package.package_digest().clone(),
            plugin_digest: plugin.plugin_digest().clone(),
            package_id_digest: Digest::from_text(package.manifest.package_id().as_str()),
            skill_id_digest: Digest::from_text(package.manifest.skill_id().as_str()),
            version: package.manifest.version(),
            source_digest: package.source.source_digest().clone(),
            manifest_digest: package.manifest.digest().clone(),
            content_digest: package.content_digest().clone(),
            verification_receipt_digest: package.verification.digest().clone(),
            host_api: package.manifest.host_api(),
            project_digest: Digest::from_text(scope.project_id().as_str()),
            mission_digest: Digest::from_text(scope.mission_id().as_str()),
            scope_digest: scope.digest(),
            generation: scope.generation(),
            policy_digest: policy.digest().clone(),
        }
    }

    pub fn package_id_digest(&self) -> &Digest {
        &self.package_id_digest
    }

    pub fn skill_id_digest(&self) -> &Digest {
        &self.skill_id_digest
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub const fn host_api(&self) -> PluginVersion {
        self.host_api
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }
}

impl fmt::Debug for SkillPackBindingMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackBindingMetadata")
            .field("package_digest", &self.package_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("package_id_digest", &self.package_id_digest)
            .field("skill_id_digest", &self.skill_id_digest)
            .field("version", &self.version)
            .field("source_digest", &self.source_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("content_digest", &self.content_digest)
            .field(
                "verification_receipt_digest",
                &self.verification_receipt_digest,
            )
            .field("host_api", &self.host_api)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("policy_digest", &self.policy_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackAuditEventKind {
    Verified,
    Mounted,
    CapabilitiesResolved,
    InstructionVisible,
    RecipeVisible,
    ContextComposed,
    UpgradePrepared,
    Revoked,
    Unmounted,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SkillPackAuditLogError {
    #[error("Skill Pack audit log is unavailable")]
    Unavailable,
    #[error("Skill Pack audit log rejected an event")]
    Rejected,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackAuditEntry {
    pub schema: String,
    pub event_digest: Digest,
    pub kind: SkillPackAuditEventKind,
    pub package_digest: Digest,
    pub plugin_digest: Digest,
    pub package_id_digest: Digest,
    pub skill_id_digest: Digest,
    pub version: PluginVersion,
    pub source_digest: Digest,
    pub manifest_digest: Digest,
    pub content_digest: Digest,
    pub verification_receipt_digest: Digest,
    pub host_api: PluginVersion,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub scope_digest: Digest,
    pub generation: u64,
    pub policy_digest: Digest,
    pub resolved_capability_digest: Option<Digest>,
    pub item_id_digest: Option<Digest>,
    pub item_content_digest: Option<Digest>,
    pub model_visible: bool,
    pub observed_at: u64,
}

impl SkillPackAuditEntry {
    fn new(
        metadata: &SkillPackBindingMetadata,
        kind: SkillPackAuditEventKind,
        resolved_capability_digest: Option<Digest>,
        item_id_digest: Option<Digest>,
        item_content_digest: Option<Digest>,
        model_visible: bool,
        observed_at: u64,
    ) -> Result<Self, SkillPackError> {
        let mut entry = Self {
            schema: SKILL_PACK_AUDIT_SCHEMA.into(),
            event_digest: Digest::from_text("pending-skill-audit"),
            kind,
            package_digest: metadata.package_digest.clone(),
            plugin_digest: metadata.plugin_digest.clone(),
            package_id_digest: metadata.package_id_digest.clone(),
            skill_id_digest: metadata.skill_id_digest.clone(),
            version: metadata.version,
            source_digest: metadata.source_digest.clone(),
            manifest_digest: metadata.manifest_digest.clone(),
            content_digest: metadata.content_digest.clone(),
            verification_receipt_digest: metadata.verification_receipt_digest.clone(),
            host_api: metadata.host_api,
            project_digest: metadata.project_digest.clone(),
            mission_digest: metadata.mission_digest.clone(),
            scope_digest: metadata.scope_digest.clone(),
            generation: metadata.generation,
            policy_digest: metadata.policy_digest.clone(),
            resolved_capability_digest,
            item_id_digest,
            item_content_digest,
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
                &self.package_digest,
                &self.plugin_digest,
                &self.package_id_digest,
                &self.skill_id_digest,
                self.version,
                &self.source_digest,
                &self.manifest_digest,
                &self.content_digest,
                &self.verification_receipt_digest,
                self.host_api,
            ),
            (
                &self.project_digest,
                &self.mission_digest,
                &self.scope_digest,
                self.generation,
                &self.policy_digest,
                &self.resolved_capability_digest,
                &self.item_id_digest,
                &self.item_content_digest,
                self.model_visible,
                self.observed_at,
            ),
        ))
    }

    fn validate_without_event_digest(&self) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_AUDIT_SCHEMA || self.generation == 0 {
            return Err(SkillPackError::InvalidSchema);
        }
        for digest in [
            &self.package_digest,
            &self.plugin_digest,
            &self.package_id_digest,
            &self.skill_id_digest,
            &self.source_digest,
            &self.manifest_digest,
            &self.content_digest,
            &self.verification_receipt_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.scope_digest,
            &self.policy_digest,
        ]
        .into_iter()
        .chain(self.resolved_capability_digest.iter())
        .chain(self.item_id_digest.iter())
        .chain(self.item_content_digest.iter())
        {
            validate_digest(digest)?;
        }
        if self.model_visible && self.item_content_digest.is_none() {
            return Err(SkillPackError::InvalidSchema);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SkillPackError> {
        self.validate_without_event_digest()?;
        if self.event_digest != self.canonical_digest() {
            return Err(SkillPackError::DigestMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for SkillPackAuditEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackAuditEntry")
            .field("event_digest", &self.event_digest)
            .field("kind", &self.kind)
            .field("package_digest", &self.package_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("package_id_digest", &self.package_id_digest)
            .field("skill_id_digest", &self.skill_id_digest)
            .field("version", &self.version)
            .field("source_digest", &self.source_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("content_digest", &self.content_digest)
            .field(
                "verification_receipt_digest",
                &self.verification_receipt_digest,
            )
            .field("host_api", &self.host_api)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("policy_digest", &self.policy_digest)
            .field(
                "resolved_capability_digest",
                &self.resolved_capability_digest,
            )
            .field("item_id_digest", &self.item_id_digest)
            .field("item_content_digest", &self.item_content_digest)
            .field("model_visible", &self.model_visible)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

pub trait SkillPackAuditLog {
    fn append(&mut self, entry: SkillPackAuditEntry) -> Result<(), SkillPackAuditLogError>;
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySkillPackAuditLog {
    entries: Vec<SkillPackAuditEntry>,
}

impl MemorySkillPackAuditLog {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[SkillPackAuditEntry] {
        &self.entries
    }
}

impl fmt::Debug for MemorySkillPackAuditLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemorySkillPackAuditLog")
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

impl SkillPackAuditLog for MemorySkillPackAuditLog {
    fn append(&mut self, entry: SkillPackAuditEntry) -> Result<(), SkillPackAuditLogError> {
        entry
            .validate()
            .map_err(|_| SkillPackAuditLogError::Rejected)?;
        if self
            .entries
            .iter()
            .any(|existing| existing.event_digest == entry.event_digest)
        {
            return Err(SkillPackAuditLogError::Rejected);
        }
        self.entries.push(entry);
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackContextReceipt {
    schema: String,
    context_digest: Digest,
    binding: SkillPackBindingMetadata,
    resolved_capability_digest: Digest,
    instruction_set_digest: Digest,
    recipe_set_digest: Digest,
    audit_event_digest: Digest,
}

impl SkillPackContextReceipt {
    fn new(
        binding: SkillPackBindingMetadata,
        resolution: &SkillPackCapabilityResolution,
        instructions: &[SkillInstruction],
        recipes: &[SkillRecipe],
        audit_event_digest: Digest,
    ) -> Result<Self, SkillPackError> {
        let instruction_set_digest = digest_serialized(
            &instructions
                .iter()
                .map(|instruction| {
                    (
                        Digest::from_text(instruction.id().as_str()),
                        instruction.content_digest(),
                    )
                })
                .collect::<Vec<_>>(),
        );
        let recipe_set_digest = digest_serialized(
            &recipes
                .iter()
                .map(|recipe| {
                    (
                        Digest::from_text(recipe.id().as_str()),
                        recipe.content_digest(),
                    )
                })
                .collect::<Vec<_>>(),
        );
        let mut receipt = Self {
            schema: SKILL_PACK_RECEIPT_SCHEMA.into(),
            context_digest: Digest::from_text("pending-skill-context"),
            binding,
            resolved_capability_digest: resolution.digest().clone(),
            instruction_set_digest,
            recipe_set_digest,
            audit_event_digest,
        };
        receipt.context_digest = receipt.computed_digest();
        receipt.validate(resolution)?;
        Ok(receipt)
    }

    pub fn digest(&self) -> &Digest {
        &self.context_digest
    }

    pub fn package_digest(&self) -> &Digest {
        &self.binding.package_digest
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.binding.plugin_digest
    }

    pub fn version(&self) -> PluginVersion {
        self.binding.version
    }

    pub fn source_digest(&self) -> &Digest {
        &self.binding.source_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.binding.manifest_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.binding.content_digest
    }

    pub fn verification_receipt_digest(&self) -> &Digest {
        &self.binding.verification_receipt_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.binding.policy_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.binding.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.binding.generation
    }

    pub fn audit_event_digest(&self) -> &Digest {
        &self.audit_event_digest
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            SKILL_PACK_RECEIPT_SCHEMA,
            &self.binding,
            &self.resolved_capability_digest,
            &self.instruction_set_digest,
            &self.recipe_set_digest,
            &self.audit_event_digest,
        ))
    }

    fn validate(&self, resolution: &SkillPackCapabilityResolution) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_RECEIPT_SCHEMA
            || self.context_digest != self.computed_digest()
            || self.resolved_capability_digest != *resolution.digest()
            || self.binding.scope_digest != *resolution.scope_digest()
            || self.binding.policy_digest != *resolution.policy_digest()
        {
            return Err(SkillPackError::ContextReceiptInvalid);
        }
        for digest in [
            &self.context_digest,
            &self.resolved_capability_digest,
            &self.instruction_set_digest,
            &self.recipe_set_digest,
            &self.audit_event_digest,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }

    fn validate_against(&self, metadata: &SkillPackBindingMetadata) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_RECEIPT_SCHEMA
            || self.binding != *metadata
            || self.context_digest != self.computed_digest()
        {
            return Err(SkillPackError::LateConsumer);
        }
        for digest in [
            &self.context_digest,
            &self.binding.package_digest,
            &self.binding.plugin_digest,
            &self.binding.package_id_digest,
            &self.binding.skill_id_digest,
            &self.binding.source_digest,
            &self.binding.manifest_digest,
            &self.binding.content_digest,
            &self.binding.verification_receipt_digest,
            &self.binding.project_digest,
            &self.binding.mission_digest,
            &self.binding.scope_digest,
            &self.binding.policy_digest,
            &self.resolved_capability_digest,
            &self.instruction_set_digest,
            &self.recipe_set_digest,
            &self.audit_event_digest,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SkillPackContextReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackContextReceipt")
            .field("context_digest", &self.context_digest)
            .field("package_digest", &self.binding.package_digest)
            .field("plugin_digest", &self.binding.plugin_digest)
            .field("version", &self.binding.version)
            .field("source_digest", &self.binding.source_digest)
            .field("manifest_digest", &self.binding.manifest_digest)
            .field("content_digest", &self.binding.content_digest)
            .field(
                "verification_receipt_digest",
                &self.binding.verification_receipt_digest,
            )
            .field("host_api", &self.binding.host_api)
            .field("project_digest", &self.binding.project_digest)
            .field("mission_digest", &self.binding.mission_digest)
            .field("scope_digest", &self.binding.scope_digest)
            .field("generation", &self.binding.generation)
            .field("policy_digest", &self.binding.policy_digest)
            .field(
                "resolved_capability_digest",
                &self.resolved_capability_digest,
            )
            .field("instruction_set_digest", &self.instruction_set_digest)
            .field("recipe_set_digest", &self.recipe_set_digest)
            .field("audit_event_digest", &self.audit_event_digest)
            .finish_non_exhaustive()
    }
}

/// The only model-facing value produced by a Skill Pack consumer.
///
/// The contents are intentionally available through explicit accessors for
/// composition, while `Debug` and the durable receipt contain digests only.
#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackModelContext {
    instructions: Vec<SkillInstruction>,
    recipes: Vec<SkillRecipe>,
    resolution: SkillPackCapabilityResolution,
    receipt: SkillPackContextReceipt,
}

impl SkillPackModelContext {
    pub fn instructions(&self) -> &[SkillInstruction] {
        &self.instructions
    }

    pub fn recipes(&self) -> &[SkillRecipe] {
        &self.recipes
    }

    pub fn resolution(&self) -> &SkillPackCapabilityResolution {
        &self.resolution
    }

    pub fn receipt(&self) -> &SkillPackContextReceipt {
        &self.receipt
    }
}

impl fmt::Debug for SkillPackModelContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackModelContext")
            .field("instruction_count", &self.instructions.len())
            .field("recipe_count", &self.recipes.len())
            .field("resolution_digest", self.resolution.digest())
            .field("receipt_digest", self.receipt.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillPackMigrationReceipt {
    schema: String,
    receipt_digest: Digest,
    scope_digest: Digest,
    policy_digest: Digest,
    old_package_digest: Digest,
    new_package_digest: Digest,
    old_version: PluginVersion,
    new_version: PluginVersion,
    migration_digest: Digest,
}

impl SkillPackMigrationReceipt {
    pub fn new(
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        old_package: &SkillPackVerifiedPackage,
        new_package: &SkillPackVerifiedPackage,
        migration_digest: Digest,
    ) -> Result<Self, SkillPackError> {
        validate_digest(&migration_digest)?;
        if old_package.manifest.plugin_id() != new_package.manifest.plugin_id()
            || old_package.manifest.package_id() != new_package.manifest.package_id()
            || old_package.manifest.skill_id() != new_package.manifest.skill_id()
            || new_package.manifest.version() <= old_package.manifest.version()
        {
            return Err(SkillPackError::UpgradeFailed);
        }
        let mut receipt = Self {
            schema: SKILL_PACK_RECEIPT_SCHEMA.into(),
            receipt_digest: Digest::from_text("pending-skill-migration"),
            scope_digest: scope.digest(),
            policy_digest: policy.digest().clone(),
            old_package_digest: old_package.package_digest().clone(),
            new_package_digest: new_package.package_digest().clone(),
            old_version: old_package.manifest.version(),
            new_version: new_package.manifest.version(),
            migration_digest,
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate(scope, policy)?;
        Ok(receipt)
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn old_package_digest(&self) -> &Digest {
        &self.old_package_digest
    }

    pub fn new_package_digest(&self) -> &Digest {
        &self.new_package_digest
    }

    pub const fn old_version(&self) -> PluginVersion {
        self.old_version
    }

    pub const fn new_version(&self) -> PluginVersion {
        self.new_version
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            SKILL_PACK_RECEIPT_SCHEMA,
            &self.scope_digest,
            &self.policy_digest,
            &self.old_package_digest,
            &self.new_package_digest,
            self.old_version,
            self.new_version,
            &self.migration_digest,
        ))
    }

    fn validate(
        &self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
    ) -> Result<(), SkillPackError> {
        if self.schema != SKILL_PACK_RECEIPT_SCHEMA
            || self.receipt_digest != self.computed_digest()
            || self.scope_digest != scope.digest()
            || self.policy_digest != *policy.digest()
            || self.new_version <= self.old_version
        {
            return Err(SkillPackError::UpgradeFailed);
        }
        for digest in [
            &self.receipt_digest,
            &self.scope_digest,
            &self.policy_digest,
            &self.old_package_digest,
            &self.new_package_digest,
            &self.migration_digest,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SkillPackMigrationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackMigrationReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("scope_digest", &self.scope_digest)
            .field("policy_digest", &self.policy_digest)
            .field("old_package_digest", &self.old_package_digest)
            .field("new_package_digest", &self.new_package_digest)
            .field("old_version", &self.old_version)
            .field("new_version", &self.new_version)
            .field("migration_digest", &self.migration_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackUpgradePlan {
    package: SkillPackVerifiedPackage,
    migration: SkillPackMigrationReceipt,
}

impl SkillPackUpgradePlan {
    pub fn new(package: SkillPackVerifiedPackage, migration: SkillPackMigrationReceipt) -> Self {
        Self { package, migration }
    }

    fn package(&self) -> &SkillPackVerifiedPackage {
        &self.package
    }

    fn migration(&self) -> &SkillPackMigrationReceipt {
        &self.migration
    }
}

impl fmt::Debug for SkillPackUpgradePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackUpgradePlan")
            .field("package_digest", self.package.package_digest())
            .field("migration", &self.migration)
            .finish_non_exhaustive()
    }
}

pub trait SkillPackHostAdapter {
    fn verify_and_load(
        &mut self,
        request: &SkillPackLoadRequest,
    ) -> Result<SkillPackVerifiedPackage, SkillPackHostError>;

    fn prepare_upgrade(
        &mut self,
        _current: &SkillPackVerifiedPackage,
        _request: &SkillPackLoadRequest,
    ) -> Result<SkillPackUpgradePlan, SkillPackHostError> {
        Err(SkillPackHostError::MigrationUnavailable)
    }

    fn release(&mut self, package_digest: &Digest) -> Result<(), SkillPackHostError>;
}

struct SkillPackAuditRequest {
    kind: SkillPackAuditEventKind,
    resolved_capability_digest: Option<Digest>,
    item_id_digest: Option<Digest>,
    item_content_digest: Option<Digest>,
    model_visible: bool,
    observed_at: u64,
}

pub struct SkillPackProvider<H> {
    host: H,
    package: Option<SkillPackVerifiedPackage>,
    plugin: Option<SkillPackPlugin>,
    mount: Option<SkillPackMount>,
    policy: SkillPackPolicy,
    metadata: SkillPackBindingMetadata,
    status: SkillPackStatus,
}

impl<H> SkillPackProvider<H>
where
    H: SkillPackHostAdapter,
{
    pub fn load_and_mount(
        mut host: H,
        request: &SkillPackLoadRequest,
        policy: SkillPackPolicy,
        runtime: &mut PluginRuntime,
    ) -> Result<Self, SkillPackError> {
        request.validate()?;
        policy.validate()?;
        if request.policy_digest() != policy.digest() || request.scope().generation() == 0 {
            return Err(SkillPackError::ScopeMismatch);
        }
        let package = host
            .verify_and_load(request)
            .map_err(SkillPackError::from)?;
        if let Err(error) = Self::validate_requested_package(&package, request, &policy) {
            let _ = host.release(package.package_digest());
            return Err(error);
        }
        let plugin =
            match SkillPackPlugin::from_verified(request.scope().clone(), &package, &policy) {
                Ok(plugin) => plugin,
                Err(error) => {
                    let _ = host.release(package.package_digest());
                    return Err(error);
                }
            };
        let mount = match plugin.mount(runtime) {
            Ok(mount) => mount,
            Err(error) => {
                let _ = host.release(package.package_digest());
                return Err(error);
            }
        };
        let metadata =
            SkillPackBindingMetadata::from_package(request.scope(), &policy, &package, &plugin);
        Ok(Self {
            host,
            package: Some(package),
            plugin: Some(plugin),
            mount: Some(mount),
            policy,
            metadata,
            status: SkillPackStatus::Mounted,
        })
    }

    pub fn status(&self) -> SkillPackStatus {
        self.status
    }

    pub fn policy(&self) -> &SkillPackPolicy {
        &self.policy
    }

    pub fn metadata(&self) -> &SkillPackBindingMetadata {
        &self.metadata
    }

    pub fn package_digest(&self) -> &Digest {
        &self.metadata.package_digest
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.metadata.plugin_digest
    }

    pub fn verification_receipt_digest(&self) -> &Digest {
        &self.metadata.verification_receipt_digest
    }

    pub fn mount(&self) -> Option<&SkillPackMount> {
        self.mount.as_ref()
    }

    pub fn plugin(&self) -> Option<&SkillPackPlugin> {
        self.plugin.as_ref()
    }

    pub fn verification_receipt(&self) -> Option<&SkillPackVerificationReceipt> {
        self.package
            .as_ref()
            .map(SkillPackVerifiedPackage::verification_receipt)
    }

    pub fn validate_context(
        &mut self,
        context: &SkillPackMissionContext,
        model: &SkillPackModelContext,
        runtime: &PluginRuntime,
    ) -> Result<(), SkillPackError> {
        self.validate_context_receipt(context, model.receipt(), runtime)
    }

    pub(crate) fn validate_context_receipt(
        &mut self,
        context: &SkillPackMissionContext,
        receipt: &SkillPackContextReceipt,
        runtime: &PluginRuntime,
    ) -> Result<(), SkillPackError> {
        self.ensure_live(context, runtime)?;
        receipt.validate_against(&self.metadata)?;
        if *receipt.scope_digest() != context.scope().digest()
            || receipt.policy_digest() != context.policy_digest()
        {
            return Err(SkillPackError::LateConsumer);
        }
        Ok(())
    }

    pub fn compose<R, L>(
        &mut self,
        context: &SkillPackMissionContext,
        resolver: &mut R,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<SkillPackModelContext, SkillPackError>
    where
        R: SkillPackCapabilityResolver,
        L: SkillPackAuditLog,
    {
        self.ensure_live(context, runtime)?;
        let package = self
            .package
            .as_ref()
            .ok_or(SkillPackError::SessionClosed)?
            .clone();
        let resolution = match resolver.resolve(
            context.scope(),
            &self.policy,
            package.manifest.required_services(),
            package.manifest.required_tools(),
        ) {
            Ok(resolution) => resolution,
            Err(error) => return self.fail_closed(runtime, error),
        };
        if let Err(error) = self.validate_resolution(&package, &resolution, context) {
            return self.fail_closed(runtime, error);
        }
        self.append_audit(
            log,
            SkillPackAuditRequest {
                kind: SkillPackAuditEventKind::CapabilitiesResolved,
                resolved_capability_digest: Some(resolution.digest().clone()),
                item_id_digest: None,
                item_content_digest: None,
                model_visible: false,
                observed_at,
            },
            runtime,
        )?;
        let (instructions, recipes) =
            match self.compose_visible_items(&package, &resolution, log, observed_at, runtime) {
                Ok(items) => items,
                Err(error) => return self.fail_closed(runtime, error),
            };
        let event_digest = self.append_audit(
            log,
            SkillPackAuditRequest {
                kind: SkillPackAuditEventKind::ContextComposed,
                resolved_capability_digest: Some(resolution.digest().clone()),
                item_id_digest: None,
                item_content_digest: None,
                model_visible: false,
                observed_at,
            },
            runtime,
        )?;
        let receipt = match SkillPackContextReceipt::new(
            self.metadata.clone(),
            &resolution,
            &instructions,
            &recipes,
            event_digest,
        ) {
            Ok(receipt) => receipt,
            Err(error) => return self.fail_closed(runtime, error),
        };
        Ok(SkillPackModelContext {
            instructions,
            recipes,
            resolution,
            receipt,
        })
    }

    fn compose_visible_items<L>(
        &mut self,
        package: &SkillPackVerifiedPackage,
        resolution: &SkillPackCapabilityResolution,
        log: &mut L,
        observed_at: u64,
        runtime: &mut PluginRuntime,
    ) -> Result<(Vec<SkillInstruction>, Vec<SkillRecipe>), SkillPackError>
    where
        L: SkillPackAuditLog,
    {
        let files = Self::files_for_package(package);
        let mut instructions = Vec::new();
        for item_id in package.manifest.instructions().keys() {
            if self.policy.allows_instruction(item_id) {
                let instruction = package.instruction(item_id, &files)?;
                self.append_audit(
                    log,
                    SkillPackAuditRequest {
                        kind: SkillPackAuditEventKind::InstructionVisible,
                        resolved_capability_digest: Some(resolution.digest().clone()),
                        item_id_digest: Some(Digest::from_text(item_id.as_str())),
                        item_content_digest: Some(instruction.content_digest()),
                        model_visible: true,
                        observed_at,
                    },
                    runtime,
                )?;
                instructions.push(instruction);
            }
        }
        let mut recipes = Vec::new();
        for item_id in package.manifest.recipes().keys() {
            if self.policy.allows_recipe(item_id) {
                let recipe = package.recipe(item_id, &files)?;
                self.append_audit(
                    log,
                    SkillPackAuditRequest {
                        kind: SkillPackAuditEventKind::RecipeVisible,
                        resolved_capability_digest: Some(resolution.digest().clone()),
                        item_id_digest: Some(Digest::from_text(item_id.as_str())),
                        item_content_digest: Some(recipe.content_digest()),
                        model_visible: true,
                        observed_at,
                    },
                    runtime,
                )?;
                recipes.push(recipe);
            }
        }
        Ok((instructions, recipes))
    }

    pub fn upgrade<L>(
        &mut self,
        context: &SkillPackMissionContext,
        request: &SkillPackLoadRequest,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<(), SkillPackError>
    where
        L: SkillPackAuditLog,
    {
        self.ensure_live(context, runtime)?;
        if request.scope() != context.scope() || request.policy_digest() != context.policy_digest()
        {
            return Err(SkillPackError::ScopeMismatch);
        }
        let current = self
            .package
            .as_ref()
            .ok_or(SkillPackError::SessionClosed)?
            .clone();
        self.status = SkillPackStatus::Upgrading;
        let plan = match self.host.prepare_upgrade(&current, request) {
            Ok(plan) => plan,
            Err(error) => {
                self.status = SkillPackStatus::Mounted;
                return Err(error.into());
            }
        };
        if let Err(error) = Self::validate_requested_package(plan.package(), request, &self.policy)
        {
            return self.fail_closed(runtime, error);
        }
        if let Err(error) = plan.migration().validate(context.scope(), &self.policy) {
            return self.fail_closed(runtime, error);
        }
        if plan.migration().old_package_digest() != current.package_digest()
            || plan.migration().new_package_digest() != plan.package().package_digest()
        {
            return self.fail_closed(runtime, SkillPackError::UpgradeFailed);
        }
        self.append_audit(
            log,
            SkillPackAuditRequest {
                kind: SkillPackAuditEventKind::UpgradePrepared,
                resolved_capability_digest: None,
                item_id_digest: None,
                item_content_digest: None,
                model_visible: false,
                observed_at,
            },
            runtime,
        )?;
        let Some(old_mount) = self.mount.take() else {
            return self.fail_closed(runtime, SkillPackError::MountMissing);
        };
        old_mount
            .unmount(runtime)
            .inspect_err(|_| self.status = SkillPackStatus::Failed)?;
        let old_digest = current.package_digest().clone();
        if self.host.release(&old_digest).is_err() {
            self.status = SkillPackStatus::Failed;
            self.package = None;
            self.plugin = None;
            return Err(SkillPackError::HostReleaseFailed);
        }
        let package = plan.package().clone();
        let plugin =
            match SkillPackPlugin::from_verified(context.scope().clone(), &package, &self.policy) {
                Ok(plugin) => plugin,
                Err(error) => {
                    self.status = SkillPackStatus::Failed;
                    self.package = None;
                    self.plugin = None;
                    return Err(error);
                }
            };
        let mount = match plugin.mount(runtime) {
            Ok(mount) => mount,
            Err(error) => {
                self.status = SkillPackStatus::Failed;
                self.package = None;
                self.plugin = None;
                return Err(error);
            }
        };
        self.metadata = SkillPackBindingMetadata::from_package(
            context.scope(),
            &self.policy,
            &package,
            &plugin,
        );
        self.package = Some(package);
        self.plugin = Some(plugin);
        self.mount = Some(mount);
        self.status = SkillPackStatus::Mounted;
        self.append_audit(
            log,
            SkillPackAuditRequest {
                kind: SkillPackAuditEventKind::Mounted,
                resolved_capability_digest: None,
                item_id_digest: None,
                item_content_digest: None,
                model_visible: false,
                observed_at,
            },
            runtime,
        )?;
        Ok(())
    }

    pub fn unmount<L>(
        &mut self,
        context: &SkillPackMissionContext,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<UnmountReceipt, SkillPackError>
    where
        L: SkillPackAuditLog,
    {
        self.ensure_live(context, runtime)?;
        let mount = self.mount.take().ok_or(SkillPackError::MountMissing)?;
        let receipt = mount.unmount(runtime)?;
        let digest = self.metadata.package_digest.clone();
        if self.host.release(&digest).is_err() {
            self.status = SkillPackStatus::Failed;
            self.package = None;
            self.plugin = None;
            return Err(SkillPackError::HostReleaseFailed);
        }
        self.package = None;
        self.plugin = None;
        self.status = SkillPackStatus::Unmounted;
        self.append_audit(
            log,
            SkillPackAuditRequest {
                kind: SkillPackAuditEventKind::Unmounted,
                resolved_capability_digest: None,
                item_id_digest: None,
                item_content_digest: None,
                model_visible: false,
                observed_at,
            },
            runtime,
        )?;
        Ok(receipt)
    }

    pub fn revoke<L>(
        &mut self,
        context: &SkillPackMissionContext,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<RevocationReceipt, SkillPackError>
    where
        L: SkillPackAuditLog,
    {
        self.ensure_live(context, runtime)?;
        let mount = self.mount.take().ok_or(SkillPackError::MountMissing)?;
        let receipt = mount.revoke(runtime)?;
        let digest = self.metadata.package_digest.clone();
        if self.host.release(&digest).is_err() {
            self.status = SkillPackStatus::Failed;
            self.package = None;
            self.plugin = None;
            return Err(SkillPackError::HostReleaseFailed);
        }
        self.package = None;
        self.plugin = None;
        self.status = SkillPackStatus::Revoked;
        self.append_audit(
            log,
            SkillPackAuditRequest {
                kind: SkillPackAuditEventKind::Revoked,
                resolved_capability_digest: None,
                item_id_digest: None,
                item_content_digest: None,
                model_visible: false,
                observed_at,
            },
            runtime,
        )?;
        Ok(receipt)
    }

    pub fn crash(&mut self, runtime: &mut PluginRuntime) -> Result<(), SkillPackError> {
        self.status = SkillPackStatus::Failed;
        if let Some(mount) = self.mount.take() {
            let _ = mount.unmount(runtime);
        }
        if let Some(package) = self.package.take() {
            self.host
                .release(package.package_digest())
                .map_err(|_| SkillPackError::HostReleaseFailed)?;
        }
        self.plugin = None;
        Ok(())
    }

    fn ensure_live(
        &mut self,
        context: &SkillPackMissionContext,
        runtime: &PluginRuntime,
    ) -> Result<(), SkillPackError> {
        if context.scope().digest() != self.metadata.scope_digest
            || context.policy_digest() != &self.metadata.policy_digest
        {
            return Err(SkillPackError::ScopeMismatch);
        }
        if self.status != SkillPackStatus::Mounted {
            return Err(match self.status {
                SkillPackStatus::Revoked => SkillPackError::PluginRevoked,
                SkillPackStatus::Unmounted => SkillPackError::PluginUnmounted,
                _ => SkillPackError::SessionClosed,
            });
        }
        let mount = self.mount.as_ref().ok_or(SkillPackError::MountMissing)?;
        if let Err(error) = mount.validate_runtime(runtime) {
            self.status = match error {
                SkillPackError::PluginRevoked => SkillPackStatus::Revoked,
                SkillPackError::PluginUnmounted => SkillPackStatus::Unmounted,
                _ => SkillPackStatus::Failed,
            };
            return Err(error);
        }
        Ok(())
    }

    fn validate_requested_package(
        package: &SkillPackVerifiedPackage,
        request: &SkillPackLoadRequest,
        policy: &SkillPackPolicy,
    ) -> Result<(), SkillPackError> {
        if package.source() != request.source() {
            return Err(SkillPackError::PathDrift);
        }
        if request
            .expected_package_digest
            .as_ref()
            .is_some_and(|digest| digest != package.package_digest())
            || request
                .expected_manifest_digest
                .as_ref()
                .is_some_and(|digest| digest != package.manifest.digest())
            || request
                .expected_content_digest
                .as_ref()
                .is_some_and(|digest| digest != package.content_digest())
        {
            return Err(SkillPackError::DigestMismatch);
        }
        if !policy.allows_package(&package.manifest, &package.source) {
            return Err(SkillPackError::PolicyDenied);
        }
        Ok(())
    }

    fn files_for_package(
        package: &SkillPackVerifiedPackage,
    ) -> BTreeMap<SkillPackPath, SkillPackFile> {
        package.files().clone()
    }

    fn validate_resolution(
        &self,
        package: &SkillPackVerifiedPackage,
        resolution: &SkillPackCapabilityResolution,
        context: &SkillPackMissionContext,
    ) -> Result<(), SkillPackError> {
        resolution.validate()?;
        if *resolution.scope_digest() != context.scope().digest()
            || resolution.policy_digest() != self.policy.digest()
            || resolution.services() != package.manifest.required_services()
            || resolution.tools() != package.manifest.required_tools()
        {
            return Err(SkillPackError::CapabilityMismatch);
        }
        for requirement in resolution.services() {
            if !self.policy.allows_capability(&requirement.digest()) {
                return Err(SkillPackError::PolicyDenied);
            }
        }
        for requirement in resolution.tools() {
            if !self.policy.allows_capability(&requirement.digest()) {
                return Err(SkillPackError::PolicyDenied);
            }
        }
        Ok(())
    }

    fn append_audit<L>(
        &mut self,
        log: &mut L,
        audit: SkillPackAuditRequest,
        runtime: &mut PluginRuntime,
    ) -> Result<Digest, SkillPackError>
    where
        L: SkillPackAuditLog,
    {
        let entry = SkillPackAuditEntry::new(
            &self.metadata,
            audit.kind,
            audit.resolved_capability_digest,
            audit.item_id_digest,
            audit.item_content_digest,
            audit.model_visible,
            audit.observed_at,
        )?;
        let digest = entry.event_digest.clone();
        if log.append(entry).is_err() {
            self.status = SkillPackStatus::Failed;
            let _ = self.cleanup_runtime(runtime);
            return Err(SkillPackError::AuditCommitFailed);
        }
        Ok(digest)
    }

    fn cleanup_runtime(&mut self, runtime: &mut PluginRuntime) -> Result<(), SkillPackError> {
        if let Some(mount) = self.mount.take() {
            mount.unmount(runtime)?;
        }
        if let Some(package) = self.package.take() {
            self.host
                .release(package.package_digest())
                .map_err(|_| SkillPackError::HostReleaseFailed)?;
        }
        self.plugin = None;
        Ok(())
    }

    fn fail_closed<U>(
        &mut self,
        runtime: &mut PluginRuntime,
        error: SkillPackError,
    ) -> Result<U, SkillPackError> {
        self.status = SkillPackStatus::Failed;
        let _ = self.cleanup_runtime(runtime);
        Err(error)
    }
}

impl<H: fmt::Debug> fmt::Debug for SkillPackProvider<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillPackProvider")
            .field("host_type", &std::any::type_name::<H>())
            .field("metadata", &self.metadata)
            .field("status", &self.status)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}
