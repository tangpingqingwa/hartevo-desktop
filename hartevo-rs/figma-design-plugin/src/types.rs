use std::collections::BTreeSet;
use std::fmt;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_LENGTH: usize = 128;
pub const MAX_NODE_IDS: usize = 64;
pub const MAX_VERSION_PAGES: usize = 8;
pub const MAX_VERSION_PAGE_SIZE: usize = 100;
pub const MAX_EXPORT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const REDACTED_VALUE: &str = "[REDACTED]";

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FigmaTypeError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid export request")]
    InvalidExportRequest,
    #[error("serialization failed for typed digest material")]
    Serialization,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FigmaTypeError::InvalidDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(bytes);
        Self(format!("{:x}", digest.finalize()))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self, FigmaTypeError> {
        let bytes = serde_json::to_vec(value).map_err(|_| FigmaTypeError::Serialization)?;
        Ok(Self::from_bytes(&bytes))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

identifier_type!(TenantId, "tenant id");
identifier_type!(ProjectId, "Hartevo project id");
identifier_type!(MissionId, "Mission id");
identifier_type!(TeamId, "Figma team id");
identifier_type!(FigmaProjectId, "Figma project id");
identifier_type!(FileKey, "Figma file key");
identifier_type!(NodeId, "Figma node id");
identifier_type!(VersionId, "Figma version id");
identifier_type!(RegistrationId, "registration id");
identifier_type!(ResultId, "design result id");
identifier_type!(ProposalId, "adoption proposal id");
identifier_type!(ReceiptId, "receipt id");
identifier_type!(SecretReferenceId, "secret reference id");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FigmaTimestamp(String);

impl FigmaTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || value.trim() != value
            || value.chars().any(char::is_control)
            || !value.contains('T')
        {
            return Err(FigmaTypeError::InvalidTimestamp);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for FigmaTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FigmaTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RedactedText(String);

impl RedactedText {
    pub fn new(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
        let value = value.into();
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(FigmaTypeError::InvalidIdentifier("redacted text"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_text(&self.0)
    }

    #[must_use]
    pub fn is_redacted(&self) -> bool {
        self.0 == REDACTED_VALUE
    }
}

impl fmt::Debug for RedactedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for RedactedText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED_VALUE)
    }
}

impl<'de> Deserialize<'de> for RedactedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: SecretReferenceId,
    scope_digest: Sha256Digest,
    credential_revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &FigmaScope,
        credential_revision: u64,
    ) -> Result<Self, FigmaTypeError> {
        if credential_revision == 0 {
            return Err(FigmaTypeError::InvalidIdentifier("credential revision"));
        }
        Ok(Self {
            reference_id: SecretReferenceId::new(reference_id)?,
            scope_digest: scope.digest(),
            credential_revision,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_id(&self) -> &SecretReferenceId {
        &self.reference_id
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Sha256Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FigmaAuthMethod {
    OAuth,
    PersonalAccessToken,
    PlanAccessToken,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FigmaProviderMode {
    Fixture,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl FigmaProviderMode {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FigmaEvidenceClass {
    Fixture,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl FigmaEvidenceClass {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn for_mode(mode: FigmaProviderMode) -> Self {
        match mode {
            FigmaProviderMode::Fixture => Self::Fixture,
            FigmaProviderMode::Loopback => Self::Loopback,
            FigmaProviderMode::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FigmaNodeKind {
    Document,
    Canvas,
    Frame,
    Group,
    Component,
    ComponentSet,
    Instance,
    Text,
    Vector,
    Rectangle,
    Ellipse,
    Section,
    Page,
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FigmaScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    team_id: TeamId,
    figma_project_id: FigmaProjectId,
    file_key: FileKey,
    node_ids: BTreeSet<NodeId>,
    version_id: VersionId,
}

impl<'de> Deserialize<'de> for FigmaScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireScope {
            tenant_id: TenantId,
            project_id: ProjectId,
            mission_id: MissionId,
            team_id: TeamId,
            figma_project_id: FigmaProjectId,
            file_key: FileKey,
            node_ids: BTreeSet<NodeId>,
            version_id: VersionId,
        }
        let wire = WireScope::deserialize(deserializer)?;
        Self::new(
            wire.tenant_id,
            wire.project_id,
            wire.mission_id,
            wire.team_id,
            wire.figma_project_id,
            wire.file_key,
            wire.node_ids,
            wire.version_id,
        )
        .map_err(D::Error::custom)
    }
}

impl FigmaScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        team_id: TeamId,
        figma_project_id: FigmaProjectId,
        file_key: FileKey,
        node_ids: impl IntoIterator<Item = NodeId>,
        version_id: VersionId,
    ) -> Result<Self, FigmaTypeError> {
        let node_ids = node_ids.into_iter().collect::<BTreeSet<_>>();
        if node_ids.is_empty() || node_ids.len() > MAX_NODE_IDS {
            return Err(FigmaTypeError::InvalidScope);
        }
        Ok(Self {
            tenant_id,
            project_id,
            mission_id,
            team_id,
            figma_project_id,
            file_key,
            node_ids,
            version_id,
        })
    }

    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub fn figma_project_id(&self) -> &FigmaProjectId {
        &self.figma_project_id
    }

    #[must_use]
    pub fn file_key(&self) -> &FileKey {
        &self.file_key
    }

    #[must_use]
    pub fn node_ids(&self) -> &BTreeSet<NodeId> {
        &self.node_ids
    }

    #[must_use]
    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(self).expect("FigmaScope is serializable")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderVersion(String);

impl ProviderVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
        let value = value.into();
        validate_identifier(&value, "provider version")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ProviderVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AdapterId(String);

impl AdapterId {
    pub fn new(value: impl Into<String>) -> Result<Self, FigmaTypeError> {
        let value = value.into();
        validate_compound_identifier(&value, "adapter id")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AdapterId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaRegistrationBinding {
    provider_id: String,
    adapter_id: AdapterId,
    adapter_version: u32,
    provider_version: ProviderVersion,
    implementation_digest: Sha256Digest,
    contract_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaRegistrationBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireBinding {
            provider_id: String,
            adapter_id: AdapterId,
            adapter_version: u32,
            provider_version: ProviderVersion,
            implementation_digest: Sha256Digest,
            contract_digest: Sha256Digest,
        }
        let wire = WireBinding::deserialize(deserializer)?;
        Self::new(
            wire.provider_id,
            wire.adapter_id,
            wire.adapter_version,
            wire.provider_version,
            wire.implementation_digest,
            wire.contract_digest,
        )
        .map_err(D::Error::custom)
    }
}

impl FigmaRegistrationBinding {
    pub fn new(
        provider_id: impl Into<String>,
        adapter_id: AdapterId,
        adapter_version: u32,
        provider_version: ProviderVersion,
        implementation_digest: Sha256Digest,
        contract_digest: Sha256Digest,
    ) -> Result<Self, FigmaTypeError> {
        let provider_id = provider_id.into();
        validate_identifier(&provider_id, "provider id")?;
        if adapter_version == 0 {
            return Err(FigmaTypeError::InvalidIdentifier("adapter version"));
        }
        Ok(Self {
            provider_id,
            adapter_id,
            adapter_version,
            provider_version,
            implementation_digest,
            contract_digest,
        })
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    #[must_use]
    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    #[must_use]
    pub fn provider_version(&self) -> &ProviderVersion {
        &self.provider_version
    }

    #[must_use]
    pub fn implementation_digest(&self) -> &Sha256Digest {
        &self.implementation_digest
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Sha256Digest {
        &self.contract_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaDesignRegistration {
    registration_id: RegistrationId,
    binding: FigmaRegistrationBinding,
    scope: FigmaScope,
    status: RegistrationStatus,
    revision: u64,
    revocation_epoch: u64,
    record_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaDesignRegistration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireRegistration {
            registration_id: RegistrationId,
            binding: FigmaRegistrationBinding,
            scope: FigmaScope,
            status: RegistrationStatus,
            revision: u64,
            revocation_epoch: u64,
            record_digest: Sha256Digest,
        }
        let wire = WireRegistration::deserialize(deserializer)?;
        let registration = Self {
            registration_id: wire.registration_id,
            binding: wire.binding,
            scope: wire.scope,
            status: wire.status,
            revision: wire.revision,
            revocation_epoch: wire.revocation_epoch,
            record_digest: wire.record_digest,
        };
        registration.validate().map_err(D::Error::custom)?;
        Ok(registration)
    }
}

#[derive(Serialize)]
struct RegistrationDigestMaterial<'a> {
    registration_id: &'a RegistrationId,
    binding: &'a FigmaRegistrationBinding,
    scope: &'a FigmaScope,
    status: &'a RegistrationStatus,
    revision: u64,
    revocation_epoch: u64,
}

impl FigmaDesignRegistration {
    pub fn register(
        registration_id: RegistrationId,
        binding: FigmaRegistrationBinding,
        scope: FigmaScope,
    ) -> Result<Self, FigmaTypeError> {
        let mut registration = Self {
            registration_id,
            binding,
            scope,
            status: RegistrationStatus::Active,
            revision: 1,
            revocation_epoch: 1,
            record_digest: Sha256Digest::from_text("uninitialized-registration"),
        };
        registration.record_digest = registration.compute_record_digest();
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), FigmaTypeError> {
        if self.revision == 0 || self.revocation_epoch == 0 {
            return Err(FigmaTypeError::InvalidIdentifier("registration revision"));
        }
        if self.compute_record_digest() != self.record_digest {
            return Err(FigmaTypeError::InvalidDigest);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), FigmaTypeError> {
        if self.status == RegistrationStatus::Revoked {
            return Ok(());
        }
        self.status = RegistrationStatus::Revoked;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(FigmaTypeError::InvalidIdentifier("registration revision"))?;
        self.revocation_epoch = self
            .revocation_epoch
            .checked_add(1)
            .ok_or(FigmaTypeError::InvalidIdentifier("revocation epoch"))?;
        self.record_digest = self.compute_record_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), FigmaTypeError> {
        if self.status == RegistrationStatus::Active {
            return Ok(());
        }
        self.status = RegistrationStatus::Active;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(FigmaTypeError::InvalidIdentifier("registration revision"))?;
        self.revocation_epoch = self
            .revocation_epoch
            .checked_add(1)
            .ok_or(FigmaTypeError::InvalidIdentifier("revocation epoch"))?;
        self.record_digest = self.compute_record_digest();
        Ok(())
    }

    fn compute_record_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&RegistrationDigestMaterial {
            registration_id: &self.registration_id,
            binding: &self.binding,
            scope: &self.scope,
            status: &self.status,
            revision: self.revision,
            revocation_epoch: self.revocation_epoch,
        })
        .expect("registration digest material is serializable")
    }

    #[must_use]
    pub fn registration_id(&self) -> &RegistrationId {
        &self.registration_id
    }

    #[must_use]
    pub fn binding(&self) -> &FigmaRegistrationBinding {
        &self.binding
    }

    #[must_use]
    pub fn scope(&self) -> &FigmaScope {
        &self.scope
    }

    #[must_use]
    pub const fn status(&self) -> &RegistrationStatus {
        &self.status
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    #[must_use]
    pub fn record_digest(&self) -> &Sha256Digest {
        &self.record_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Jpg,
    Png,
    Svg,
    Pdf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ExportScale(u16);

impl ExportScale {
    /// Creates a scale in hundredths, so 100 represents 1.00x.
    pub fn new(hundredths: u16) -> Result<Self, FigmaTypeError> {
        if !(1..=400).contains(&hundredths) {
            return Err(FigmaTypeError::InvalidExportRequest);
        }
        Ok(Self(hundredths))
    }

    #[must_use]
    pub const fn hundredths(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportRequest {
    file_key: FileKey,
    version_id: VersionId,
    node_id: NodeId,
    format: ExportFormat,
    scale: ExportScale,
    max_bytes: u64,
}

impl<'de> Deserialize<'de> for ExportRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireRequest {
            file_key: FileKey,
            version_id: VersionId,
            node_id: NodeId,
            format: ExportFormat,
            scale: ExportScale,
            max_bytes: u64,
        }
        let wire = WireRequest::deserialize(deserializer)?;
        Self::new(
            wire.file_key,
            wire.version_id,
            wire.node_id,
            wire.format,
            wire.scale,
            wire.max_bytes,
        )
        .map_err(D::Error::custom)
    }
}

impl ExportRequest {
    pub fn new(
        file_key: FileKey,
        version_id: VersionId,
        node_id: NodeId,
        format: ExportFormat,
        scale: ExportScale,
        max_bytes: u64,
    ) -> Result<Self, FigmaTypeError> {
        if max_bytes == 0 || max_bytes > MAX_EXPORT_BYTES {
            return Err(FigmaTypeError::InvalidExportRequest);
        }
        Ok(Self {
            file_key,
            version_id,
            node_id,
            format,
            scale,
            max_bytes,
        })
    }

    #[must_use]
    pub fn file_key(&self) -> &FileKey {
        &self.file_key
    }

    #[must_use]
    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    #[must_use]
    pub fn format(&self) -> &ExportFormat {
        &self.format
    }

    #[must_use]
    pub const fn scale(&self) -> ExportScale {
        self.scale
    }

    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(self).expect("ExportRequest is serializable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaFileMetadata {
    file_key: FileKey,
    version_id: VersionId,
    version_timestamp: FigmaTimestamp,
    last_modified: FigmaTimestamp,
    name: RedactedText,
    metadata_digest: Sha256Digest,
    scope_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaFileMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireMetadata {
            file_key: FileKey,
            version_id: VersionId,
            version_timestamp: FigmaTimestamp,
            last_modified: FigmaTimestamp,
            name: RedactedText,
            metadata_digest: Sha256Digest,
            scope_digest: Sha256Digest,
        }
        let wire = WireMetadata::deserialize(deserializer)?;
        Ok(Self {
            file_key: wire.file_key,
            version_id: wire.version_id,
            version_timestamp: wire.version_timestamp,
            last_modified: wire.last_modified,
            name: wire.name,
            metadata_digest: wire.metadata_digest,
            scope_digest: wire.scope_digest,
        })
    }
}

#[derive(Serialize)]
struct FileMetadataDigestMaterial<'a> {
    file_key: &'a FileKey,
    version_id: &'a VersionId,
    version_timestamp: &'a FigmaTimestamp,
    last_modified: &'a FigmaTimestamp,
    name_digest: Sha256Digest,
}

impl FigmaFileMetadata {
    pub fn new(
        file_key: FileKey,
        version_id: VersionId,
        version_timestamp: FigmaTimestamp,
        last_modified: FigmaTimestamp,
        name: RedactedText,
        scope: &FigmaScope,
    ) -> Self {
        let metadata_digest = Sha256Digest::from_serializable(&FileMetadataDigestMaterial {
            file_key: &file_key,
            version_id: &version_id,
            version_timestamp: &version_timestamp,
            last_modified: &last_modified,
            name_digest: name.digest(),
        })
        .expect("file metadata digest material is serializable");
        Self {
            file_key,
            version_id,
            version_timestamp,
            last_modified,
            name,
            metadata_digest,
            scope_digest: scope.digest(),
        }
    }

    fn compute_metadata_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&FileMetadataDigestMaterial {
            file_key: &self.file_key,
            version_id: &self.version_id,
            version_timestamp: &self.version_timestamp,
            last_modified: &self.last_modified,
            name_digest: self.name.digest(),
        })
        .expect("file metadata digest material is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), FigmaTypeError> {
        if self.compute_metadata_digest() != self.metadata_digest {
            return Err(FigmaTypeError::InvalidDigest);
        }
        Ok(())
    }

    #[must_use]
    pub fn file_key(&self) -> &FileKey {
        &self.file_key
    }

    #[must_use]
    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn version_timestamp(&self) -> &FigmaTimestamp {
        &self.version_timestamp
    }

    #[must_use]
    pub fn last_modified(&self) -> &FigmaTimestamp {
        &self.last_modified
    }

    #[must_use]
    pub fn name(&self) -> &RedactedText {
        &self.name
    }

    #[must_use]
    pub fn metadata_digest(&self) -> &Sha256Digest {
        &self.metadata_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Sha256Digest {
        &self.scope_digest
    }

    pub fn validate_for_scope(&self, scope: &FigmaScope) -> Result<(), FigmaTypeError> {
        self.validate_integrity()?;
        if self.file_key != *scope.file_key()
            || self.version_id != *scope.version_id()
            || self.scope_digest != scope.digest()
        {
            return Err(FigmaTypeError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaVersion {
    version_id: VersionId,
    created_at: FigmaTimestamp,
    label: RedactedText,
    user: RedactedText,
    version_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireVersion {
            version_id: VersionId,
            created_at: FigmaTimestamp,
            label: RedactedText,
            user: RedactedText,
            version_digest: Sha256Digest,
        }
        let wire = WireVersion::deserialize(deserializer)?;
        Ok(Self {
            version_id: wire.version_id,
            created_at: wire.created_at,
            label: wire.label,
            user: wire.user,
            version_digest: wire.version_digest,
        })
    }
}

impl FigmaVersion {
    pub fn new(
        version_id: VersionId,
        created_at: FigmaTimestamp,
        label: RedactedText,
        user: RedactedText,
    ) -> Self {
        let version_digest = Sha256Digest::from_serializable(&(
            &version_id,
            &created_at,
            label.digest(),
            user.digest(),
        ))
        .expect("version digest material is serializable");
        Self {
            version_id,
            created_at,
            label,
            user,
            version_digest,
        }
    }

    fn compute_version_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&(
            &self.version_id,
            &self.created_at,
            self.label.digest(),
            self.user.digest(),
        ))
        .expect("version digest material is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), FigmaTypeError> {
        if self.compute_version_digest() != self.version_digest {
            return Err(FigmaTypeError::InvalidDigest);
        }
        Ok(())
    }

    #[must_use]
    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn created_at(&self) -> &FigmaTimestamp {
        &self.created_at
    }

    #[must_use]
    pub fn label(&self) -> &RedactedText {
        &self.label
    }

    #[must_use]
    pub fn user(&self) -> &RedactedText {
        &self.user
    }

    #[must_use]
    pub fn version_digest(&self) -> &Sha256Digest {
        &self.version_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaNodeMetadata {
    node_id: NodeId,
    version_id: VersionId,
    kind: FigmaNodeKind,
    name: RedactedText,
    metadata_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for FigmaNodeMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireNode {
            node_id: NodeId,
            version_id: VersionId,
            kind: FigmaNodeKind,
            name: RedactedText,
            metadata_digest: Sha256Digest,
        }
        let wire = WireNode::deserialize(deserializer)?;
        Ok(Self {
            node_id: wire.node_id,
            version_id: wire.version_id,
            kind: wire.kind,
            name: wire.name,
            metadata_digest: wire.metadata_digest,
        })
    }
}

impl FigmaNodeMetadata {
    pub fn new(
        node_id: NodeId,
        version_id: VersionId,
        kind: FigmaNodeKind,
        name: RedactedText,
    ) -> Self {
        let metadata_digest =
            Sha256Digest::from_serializable(&(&node_id, &version_id, &kind, name.digest()))
                .expect("node metadata digest material is serializable");
        Self {
            node_id,
            version_id,
            kind,
            name,
            metadata_digest,
        }
    }

    fn compute_metadata_digest(&self) -> Sha256Digest {
        Sha256Digest::from_serializable(&(
            &self.node_id,
            &self.version_id,
            &self.kind,
            self.name.digest(),
        ))
        .expect("node metadata digest material is serializable")
    }

    pub fn validate_integrity(&self) -> Result<(), FigmaTypeError> {
        if self.compute_metadata_digest() != self.metadata_digest {
            return Err(FigmaTypeError::InvalidDigest);
        }
        Ok(())
    }

    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    #[must_use]
    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn kind(&self) -> &FigmaNodeKind {
        &self.kind
    }

    #[must_use]
    pub fn name(&self) -> &RedactedText {
        &self.name
    }

    #[must_use]
    pub fn metadata_digest(&self) -> &Sha256Digest {
        &self.metadata_digest
    }

    pub fn validate_for_scope(&self, scope: &FigmaScope) -> Result<(), FigmaTypeError> {
        self.validate_integrity()?;
        if self.version_id != *scope.version_id() || !scope.node_ids().contains(&self.node_id) {
            return Err(FigmaTypeError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FigmaExportMetadata {
    file_key: FileKey,
    version_id: VersionId,
    node_id: NodeId,
    format: ExportFormat,
    scale: ExportScale,
    max_bytes: u64,
    byte_length: u64,
    content_digest: Sha256Digest,
    complete: bool,
    truncated: bool,
}

impl<'de> Deserialize<'de> for FigmaExportMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireMetadata {
            file_key: FileKey,
            version_id: VersionId,
            node_id: NodeId,
            format: ExportFormat,
            scale: ExportScale,
            max_bytes: u64,
            byte_length: u64,
            content_digest: Sha256Digest,
            complete: bool,
            truncated: bool,
        }
        let wire = WireMetadata::deserialize(deserializer)?;
        Ok(Self {
            file_key: wire.file_key,
            version_id: wire.version_id,
            node_id: wire.node_id,
            format: wire.format,
            scale: wire.scale,
            max_bytes: wire.max_bytes,
            byte_length: wire.byte_length,
            content_digest: wire.content_digest,
            complete: wire.complete,
            truncated: wire.truncated,
        })
    }
}

impl FigmaExportMetadata {
    pub fn from_bytes(request: &ExportRequest, bytes: &[u8]) -> Result<Self, FigmaTypeError> {
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| FigmaTypeError::InvalidExportRequest)?;
        if byte_length > request.max_bytes {
            return Err(FigmaTypeError::InvalidExportRequest);
        }
        Ok(Self {
            file_key: request.file_key.clone(),
            version_id: request.version_id.clone(),
            node_id: request.node_id.clone(),
            format: request.format.clone(),
            scale: request.scale,
            max_bytes: request.max_bytes,
            byte_length,
            content_digest: Sha256Digest::from_bytes(bytes),
            complete: true,
            truncated: false,
        })
    }

    #[must_use]
    pub fn file_key(&self) -> &FileKey {
        &self.file_key
    }

    #[must_use]
    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    #[must_use]
    pub fn format(&self) -> &ExportFormat {
        &self.format
    }

    #[must_use]
    pub const fn scale(&self) -> ExportScale {
        self.scale
    }

    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn validate_for_request(&self, request: &ExportRequest) -> Result<(), FigmaTypeError> {
        if self.file_key != *request.file_key()
            || self.version_id != *request.version_id()
            || self.node_id != *request.node_id()
            || self.format != *request.format()
            || self.scale != request.scale()
            || self.max_bytes != request.max_bytes()
            || self.byte_length > self.max_bytes
            || !self.complete
            || self.truncated
        {
            return Err(FigmaTypeError::InvalidExportRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FigmaExportPayload {
    metadata: FigmaExportMetadata,
    bytes: Vec<u8>,
}

impl fmt::Debug for FigmaExportPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FigmaExportPayload")
            .field("metadata", &self.metadata)
            .field("byte_length", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl FigmaExportPayload {
    pub fn from_bytes(request: &ExportRequest, bytes: Vec<u8>) -> Result<Self, FigmaTypeError> {
        let metadata = FigmaExportMetadata::from_bytes(request, &bytes)?;
        Ok(Self { metadata, bytes })
    }

    /// This constructor is intentionally useful for tamper tests. Callers
    /// must run verify_exact before any payload can become a receipt.
    #[must_use]
    pub fn from_parts(metadata: FigmaExportMetadata, bytes: Vec<u8>) -> Self {
        Self { metadata, bytes }
    }

    #[must_use]
    pub fn metadata(&self) -> &FigmaExportMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn byte_length(&self) -> usize {
        self.bytes.len()
    }

    pub fn verify_exact(&self, request: &ExportRequest) -> Result<(), FigmaTypeError> {
        self.metadata.validate_for_request(request)?;
        let actual_length =
            u64::try_from(self.bytes.len()).map_err(|_| FigmaTypeError::InvalidExportRequest)?;
        if actual_length != self.metadata.byte_length
            || Sha256Digest::from_bytes(&self.bytes) != self.metadata.content_digest
        {
            return Err(FigmaTypeError::InvalidExportRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDesignSource {
    mission_id: MissionId,
    result_revision: u64,
    result_revision_digest: Sha256Digest,
}

impl<'de> Deserialize<'de> for MissionDesignSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireSource {
            mission_id: MissionId,
            result_revision: u64,
            result_revision_digest: Sha256Digest,
        }
        let wire = WireSource::deserialize(deserializer)?;
        Self::new(
            wire.mission_id,
            wire.result_revision,
            wire.result_revision_digest,
        )
        .map_err(D::Error::custom)
    }
}

impl MissionDesignSource {
    pub fn new(
        mission_id: MissionId,
        result_revision: u64,
        result_revision_digest: Sha256Digest,
    ) -> Result<Self, FigmaTypeError> {
        if result_revision == 0 {
            return Err(FigmaTypeError::InvalidIdentifier("result revision"));
        }
        Ok(Self {
            mission_id,
            result_revision,
            result_revision_digest,
        })
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub const fn result_revision(&self) -> u64 {
        self.result_revision
    }

    #[must_use]
    pub fn result_revision_digest(&self) -> &Sha256Digest {
        &self.result_revision_digest
    }
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), FigmaTypeError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LENGTH
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(FigmaTypeError::InvalidIdentifier(label));
    }
    Ok(())
}

fn validate_compound_identifier(value: &str, label: &'static str) -> Result<(), FigmaTypeError> {
    validate_identifier(value, label)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)))
    {
        return Err(FigmaTypeError::InvalidIdentifier(label));
    }
    Ok(())
}
