use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{HcpPackerArtifactResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_ARTIFACTS, MAX_BUILDS, MAX_IDENTIFIER_BYTES, MAX_LABEL_BYTES,
    MAX_LABEL_KEYS, MAX_RESPONSE_BYTES, MAX_VALUE_BYTES, NEXT_TOKEN_TTL_SECONDS,
};

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_len_prefixed(&mut bytes, domain);
        for (name, value) in fields {
            append_len_prefixed(&mut bytes, name);
            append_len_prefixed(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(HcpPackerArtifactResultError::InvalidDigest { field: "digest" })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(HcpPackerArtifactResultError::InvalidDigest { field: "digest" })
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_len_prefixed(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn valid_label_key(value: &str) -> bool {
    valid_text(value, MAX_LABEL_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(HcpPackerArtifactResultError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(HcpPackerArtifactResultError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(HcpPackerArtifactResultError::InvalidText { field });
    }
    if !valid_identifier(value, MAX_IDENTIFIER_BYTES) {
        return Err(HcpPackerArtifactResultError::InvalidCharacters { field });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("hcp-packer-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .finish()
            }
        }
    };
}

identifier_type!(OrganizationId, "organization-id");
identifier_type!(ProjectId, "project-id");
identifier_type!(BucketName, "bucket-name");
identifier_type!(VersionFingerprint, "version-fingerprint");
identifier_type!(ChannelName, "channel-name");
identifier_type!(CloudProvider, "cloud-provider");
identifier_type!(CloudRegion, "cloud-region");
identifier_type!(LabelKey, "label-key");

pub type HcpOrganizationId = OrganizationId;
pub type HcpProjectId = ProjectId;
pub type HcpBucketName = BucketName;
pub type HcpVersionFingerprint = VersionFingerprint;
pub type HcpChannelName = ChannelName;
pub type HcpCloud = CloudProvider;
pub type HcpRegion = CloudRegion;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(HcpPackerArtifactResultError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts("hcp-packer-revision/v1", &[("value", self.0.to_string())])
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Revision").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionBinding {
    id: String,
    revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "mission-id")?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-mission-binding/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "mission-id")
    }
}

impl fmt::Debug for MissionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBinding")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectBinding {
    id: String,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "mission-project-id")?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-project-binding/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "mission-project-id")
    }
}

impl fmt::Debug for ProjectBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectBinding")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductBinding {
    id: String,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "work-product-id")?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-work-product-binding/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "work-product-id")
    }
}

impl fmt::Debug for WorkProductBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductBinding")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HcpPackerArtifactScope {
    organization_id: OrganizationId,
    project_id: ProjectId,
    bucket_name: BucketName,
    version_fingerprint: VersionFingerprint,
    channel_name: ChannelName,
    cloud: CloudProvider,
    region: CloudRegion,
    version_revision: Revision,
    channel_revision: Revision,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    allowlisted_label_keys: BTreeSet<LabelKey>,
}

impl HcpPackerArtifactScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I>(
        organization_id: OrganizationId,
        project_id: ProjectId,
        bucket_name: BucketName,
        version_fingerprint: VersionFingerprint,
        channel_name: ChannelName,
        cloud: CloudProvider,
        region: CloudRegion,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        allowlisted_label_keys: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = LabelKey>,
    {
        Self::with_revisions(
            organization_id,
            project_id,
            bucket_name,
            version_fingerprint,
            channel_name,
            cloud,
            region,
            Revision::new(1)?,
            Revision::new(1)?,
            mission,
            project,
            work_product,
            allowlisted_label_keys,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_revisions<I>(
        organization_id: OrganizationId,
        project_id: ProjectId,
        bucket_name: BucketName,
        version_fingerprint: VersionFingerprint,
        channel_name: ChannelName,
        cloud: CloudProvider,
        region: CloudRegion,
        version_revision: Revision,
        channel_revision: Revision,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        allowlisted_label_keys: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = LabelKey>,
    {
        let allowlisted_label_keys = allowlisted_label_keys.into_iter().collect::<BTreeSet<_>>();
        let scope = Self {
            organization_id,
            project_id,
            bucket_name,
            version_fingerprint,
            channel_name,
            cloud,
            region,
            version_revision,
            channel_revision,
            mission,
            project,
            work_product,
            allowlisted_label_keys,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn bucket_name(&self) -> &BucketName {
        &self.bucket_name
    }

    pub fn version_fingerprint(&self) -> &VersionFingerprint {
        &self.version_fingerprint
    }

    pub fn channel_name(&self) -> &ChannelName {
        &self.channel_name
    }

    pub fn cloud(&self) -> &CloudProvider {
        &self.cloud
    }

    pub fn region(&self) -> &CloudRegion {
        &self.region
    }

    pub const fn version_revision(&self) -> Revision {
        self.version_revision
    }

    pub const fn channel_revision(&self) -> Revision {
        self.channel_revision
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn allowlisted_label_keys(&self) -> &BTreeSet<LabelKey> {
        &self.allowlisted_label_keys
    }

    pub fn allowlist_digest(&self) -> Digest {
        let values = self
            .allowlisted_label_keys
            .iter()
            .map(|key| key.as_str().to_owned())
            .collect::<Vec<_>>()
            .join("\u{1f}");
        Digest::from_parts("hcp-packer-label-allowlist/v1", &[("keys", values)])
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-artifact-scope/v1",
            &[
                (
                    "organization",
                    self.organization_id.digest().as_str().to_owned(),
                ),
                ("project", self.project_id.digest().as_str().to_owned()),
                ("bucket", self.bucket_name.digest().as_str().to_owned()),
                (
                    "version",
                    self.version_fingerprint.digest().as_str().to_owned(),
                ),
                ("channel", self.channel_name.digest().as_str().to_owned()),
                ("cloud", self.cloud.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "version_revision",
                    self.version_revision.value().to_string(),
                ),
                (
                    "channel_revision",
                    self.channel_revision.value().to_string(),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project_binding", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "label_allowlist",
                    self.allowlist_digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.organization_id.validate()?;
        self.project_id.validate()?;
        self.bucket_name.validate()?;
        self.version_fingerprint.validate()?;
        self.channel_name.validate()?;
        self.cloud.validate()?;
        self.region.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.allowlisted_label_keys.len() > MAX_LABEL_KEYS
            || self
                .allowlisted_label_keys
                .iter()
                .any(|key| key.validate().is_err() || !valid_label_key(key.as_str()))
        {
            return Err(HcpPackerArtifactResultError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for HcpPackerArtifactScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HcpPackerArtifactScope")
            .field("scope_digest", &self.digest())
            .field("version_revision", &self.version_revision)
            .field("channel_revision", &self.channel_revision)
            .field("label_allowlist", &self.allowlist_digest())
            .finish()
    }
}

pub type HcpPackerScope = HcpPackerArtifactScope;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub revision: Revision,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl PermissionFence {
    pub fn readonly<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = Revision::new(revision)?;
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let fence = Self {
            revision,
            permissions,
            digest: Digest::zero(),
        };
        let mut fence = fence;
        fence.digest = fence.compute_digest();
        fence.validate()?;
        Ok(fence)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self::readonly(revision, LAYER1_PERMISSIONS.iter().copied())
            .expect("the Layer-1 permission allowlist is valid")
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.permissions.len() != LAYER1_PERMISSIONS.len()
            || !LAYER1_PERMISSIONS
                .iter()
                .all(|permission| self.permissions.contains(*permission))
            || self.digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::InvalidPermissionFence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-permission-fence/v1",
            &[
                ("revision", self.revision.value().to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        )
    }
}

pub type PermissionSnapshot = PermissionFence;

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl AsRef<str>,
        scope: &HcpPackerArtifactScope,
        revision: u64,
    ) -> Result<Self> {
        let opaque_handle = opaque_handle.as_ref();
        if opaque_handle.is_empty() {
            return Err(HcpPackerArtifactResultError::Empty {
                field: "opaque secret handle",
            });
        }
        if opaque_handle.len() > MAX_VALUE_BYTES || opaque_handle.chars().any(char::is_control) {
            return Err(HcpPackerArtifactResultError::TooLong {
                field: "opaque secret handle",
            });
        }
        let revision = Revision::new(revision)?;
        Ok(Self {
            reference_digest: Digest::from_parts(
                "hcp-packer-secret-reference/v1",
                &[
                    ("opaque_handle", opaque_handle.to_owned()),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("revision", revision.value().to_string()),
                ],
            ),
            scope_digest: scope.digest(),
            revision,
            revoked: false,
        })
    }

    pub fn hcp(
        opaque_handle: impl AsRef<str>,
        scope: &HcpPackerArtifactScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, revision)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(HcpPackerArtifactResultError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub(crate) fn validate(&self, scope: &HcpPackerArtifactScope) -> Result<()> {
        self.reference_digest.validate()?;
        self.scope_digest.validate()?;
        if self.revoked || self.scope_digest != scope.digest() || self.revision.value() == 0 {
            return Err(HcpPackerArtifactResultError::SecretRevoked);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque", &true)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
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

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BucketState {
    Active,
    Inactive,
    Unknown,
}

impl BucketState {
    pub fn from_api(value: &str) -> Self {
        match value {
            "ACTIVE" | "BUCKET_ACTIVE" => Self::Active,
            "INACTIVE" | "BUCKET_INACTIVE" | "DEACTIVATED" => Self::Inactive,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChannelState {
    Active,
    Placeholder,
    Restricted,
    Unknown,
}

impl ChannelState {
    pub fn from_api(value: &str) -> Self {
        match value {
            "ACTIVE" | "CHANNEL_ACTIVE" => Self::Active,
            "PLACEHOLDER" | "CHANNEL_PLACEHOLDER" => Self::Placeholder,
            "RESTRICTED" | "CHANNEL_RESTRICTED" => Self::Restricted,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VersionState {
    Unset,
    Running,
    Cancelled,
    Failed,
    Revoked,
    RevocationScheduled,
    Active,
    Incomplete,
    Unknown,
}

impl VersionState {
    pub fn from_api(value: &str) -> Self {
        match value {
            "VERSION_UNSET" | "UNSET" => Self::Unset,
            "VERSION_RUNNING" | "RUNNING" => Self::Running,
            "VERSION_CANCELLED" | "CANCELLED" => Self::Cancelled,
            "VERSION_FAILED" | "FAILED" => Self::Failed,
            "VERSION_REVOKED" | "REVOKED" => Self::Revoked,
            "VERSION_REVOCATION_SCHEDULED" | "REVOCATION_SCHEDULED" => Self::RevocationScheduled,
            "VERSION_ACTIVE" | "ACTIVE" => Self::Active,
            "VERSION_INCOMPLETE" | "INCOMPLETE" => Self::Incomplete,
            _ => Self::Unknown,
        }
    }

    pub const fn evidence_state(self) -> HcpPackerEvidenceState {
        match self {
            Self::Active => HcpPackerEvidenceState::Ready,
            Self::Running => HcpPackerEvidenceState::Running,
            Self::Cancelled => HcpPackerEvidenceState::Cancelled,
            Self::Failed => HcpPackerEvidenceState::Failed,
            Self::Revoked | Self::RevocationScheduled => HcpPackerEvidenceState::Revoked,
            Self::Incomplete | Self::Unset | Self::Unknown => HcpPackerEvidenceState::Incomplete,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BuildState {
    Unset,
    Running,
    Success,
    Failed,
    Unknown,
}

impl BuildState {
    pub fn from_api(value: &str) -> Self {
        match value {
            "BUILD_UNSET" | "UNSET" => Self::Unset,
            "BUILD_RUNNING" | "RUNNING" => Self::Running,
            "BUILD_SUCCESS" | "SUCCESS" | "COMPLETED" => Self::Success,
            "BUILD_FAILED" | "FAILED" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactState {
    Ready,
    Revoked,
    Unknown,
}

impl ArtifactState {
    pub fn from_api(value: &str) -> Self {
        match value {
            "ARTIFACT_ACTIVE" | "ACTIVE" | "READY" => Self::Ready,
            "ARTIFACT_REVOKED" | "REVOKED" => Self::Revoked,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketProjection {
    pub bucket_digest: Digest,
    pub organization_digest: Digest,
    pub project_digest: Digest,
    pub bucket_name_digest: Digest,
    pub state: BucketState,
    pub version_count: u64,
    pub allowlisted_labels: BTreeMap<String, String>,
}

impl fmt::Debug for BucketProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BucketProjection")
            .field("bucket_digest", &self.bucket_digest)
            .field("organization_digest", &self.organization_digest)
            .field("project_digest", &self.project_digest)
            .field("bucket_name_digest", &self.bucket_name_digest)
            .field("state", &self.state)
            .field("version_count", &self.version_count)
            .field(
                "allowlisted_label_keys",
                &self.allowlisted_labels.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelProjection {
    pub channel_digest: Digest,
    pub assigned_version_digest: Option<Digest>,
    pub channel_revision: Revision,
    pub state: ChannelState,
}

impl fmt::Debug for ChannelProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelProjection")
            .field("channel_digest", &self.channel_digest)
            .field("assigned_version_digest", &self.assigned_version_digest)
            .field("channel_revision", &self.channel_revision)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionProjection {
    pub version_digest: Digest,
    pub fingerprint_digest: Digest,
    pub state: VersionState,
    pub version_revision: Revision,
    pub build_count: u64,
    pub allowlisted_labels: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for VersionProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionProjection")
            .field("version_digest", &self.version_digest)
            .field("fingerprint_digest", &self.fingerprint_digest)
            .field("state", &self.state)
            .field("version_revision", &self.version_revision)
            .field("build_count", &self.build_count)
            .field(
                "allowlisted_label_keys",
                &self.allowlisted_labels.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildProjection {
    pub build_digest: Digest,
    pub version_digest: Digest,
    pub component_type_digest: Digest,
    pub state: BuildState,
    pub source_location_digest: Option<Digest>,
    pub cloud_digest: Digest,
    pub region_digest: Digest,
    pub allowlisted_labels: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for BuildProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildProjection")
            .field("build_digest", &self.build_digest)
            .field("version_digest", &self.version_digest)
            .field("component_type_digest", &self.component_type_digest)
            .field("state", &self.state)
            .field("source_location_digest", &self.source_location_digest)
            .field("cloud_digest", &self.cloud_digest)
            .field("region_digest", &self.region_digest)
            .field(
                "allowlisted_label_keys",
                &self.allowlisted_labels.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactProjection {
    pub artifact_digest: Digest,
    pub build_digest: Digest,
    pub cloud_digest: Digest,
    pub region_digest: Digest,
    pub artifact_location_digest: Option<Digest>,
    pub state: ArtifactState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for ArtifactProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactProjection")
            .field("artifact_digest", &self.artifact_digest)
            .field("build_digest", &self.build_digest)
            .field("cloud_digest", &self.cloud_digest)
            .field("region_digest", &self.region_digest)
            .field("artifact_location_digest", &self.artifact_location_digest)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BucketMetadataInput {
    pub id: String,
    pub organization_id: String,
    pub project_id: String,
    pub name: String,
    pub state: String,
    pub version_count: u64,
    pub labels: BTreeMap<String, String>,
}

impl BucketMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        name: impl Into<String>,
        state: impl Into<String>,
        version_count: u64,
        labels: BTreeMap<String, String>,
    ) -> Self {
        Self {
            id: id.into(),
            organization_id: organization_id.into(),
            project_id: project_id.into(),
            name: name.into(),
            state: state.into(),
            version_count,
            labels,
        }
    }
}

impl fmt::Debug for BucketMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BucketMetadataInput")
            .field("id_digest", &Digest::from_text(&self.id))
            .field(
                "organization_digest",
                &Digest::from_text(&self.organization_id),
            )
            .field("project_digest", &Digest::from_text(&self.project_id))
            .field("name_digest", &Digest::from_text(&self.name))
            .field("state", &self.state)
            .field("version_count", &self.version_count)
            .field("label_count", &self.labels.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ChannelMetadataInput {
    pub name: String,
    pub assigned_version_fingerprint: Option<String>,
    pub revision: u64,
    pub state: String,
}

impl ChannelMetadataInput {
    pub fn new(
        name: impl Into<String>,
        assigned_version_fingerprint: Option<String>,
        revision: u64,
        state: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            assigned_version_fingerprint,
            revision,
            state: state.into(),
        }
    }
}

impl fmt::Debug for ChannelMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelMetadataInput")
            .field("name_digest", &Digest::from_text(&self.name))
            .field(
                "assigned_version_digest",
                &self
                    .assigned_version_fingerprint
                    .as_deref()
                    .map(Digest::from_text),
            )
            .field("revision", &self.revision)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VersionMetadataInput {
    pub id: String,
    pub fingerprint: String,
    pub revision: u64,
    pub state: String,
    pub build_count: u64,
    pub labels: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VersionMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        fingerprint: impl Into<String>,
        revision: u64,
        state: impl Into<String>,
        build_count: u64,
        labels: BTreeMap<String, String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: id.into(),
            fingerprint: fingerprint.into(),
            revision,
            state: state.into(),
            build_count,
            labels,
            created_at,
            updated_at,
        }
    }
}

impl fmt::Debug for VersionMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionMetadataInput")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("fingerprint_digest", &Digest::from_text(&self.fingerprint))
            .field("revision", &self.revision)
            .field("state", &self.state)
            .field("build_count", &self.build_count)
            .field("label_count", &self.labels.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BuildMetadataInput {
    pub id: String,
    pub version_fingerprint: String,
    pub component_type: String,
    pub state: String,
    pub source_external_identifier: Option<String>,
    pub cloud: String,
    pub region: String,
    pub labels: BTreeMap<String, String>,
    pub build_log: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BuildMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        version_fingerprint: impl Into<String>,
        component_type: impl Into<String>,
        state: impl Into<String>,
        source_external_identifier: Option<String>,
        cloud: impl Into<String>,
        region: impl Into<String>,
        labels: BTreeMap<String, String>,
        build_log: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: id.into(),
            version_fingerprint: version_fingerprint.into(),
            component_type: component_type.into(),
            state: state.into(),
            source_external_identifier,
            cloud: cloud.into(),
            region: region.into(),
            labels,
            build_log,
            created_at,
            updated_at,
        }
    }
}

impl fmt::Debug for BuildMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildMetadataInput")
            .field("id_digest", &Digest::from_text(&self.id))
            .field(
                "version_digest",
                &Digest::from_text(&self.version_fingerprint),
            )
            .field(
                "component_type_digest",
                &Digest::from_text(&self.component_type),
            )
            .field("state", &self.state)
            .field(
                "source_location_digest",
                &self
                    .source_external_identifier
                    .as_deref()
                    .map(Digest::from_text),
            )
            .field("cloud_digest", &Digest::from_text(&self.cloud))
            .field("region_digest", &Digest::from_text(&self.region))
            .field("label_count", &self.labels.len())
            .field("build_log_present", &self.build_log.is_some())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactMetadataInput {
    pub id: String,
    pub build_id: String,
    pub version_fingerprint: String,
    pub cloud: String,
    pub region: String,
    pub external_identifier: Option<String>,
    pub state: String,
    pub labels: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ArtifactMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        build_id: impl Into<String>,
        version_fingerprint: impl Into<String>,
        cloud: impl Into<String>,
        region: impl Into<String>,
        external_identifier: Option<String>,
        state: impl Into<String>,
        labels: BTreeMap<String, String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: id.into(),
            build_id: build_id.into(),
            version_fingerprint: version_fingerprint.into(),
            cloud: cloud.into(),
            region: region.into(),
            external_identifier,
            state: state.into(),
            labels,
            created_at,
            updated_at,
        }
    }
}

impl fmt::Debug for ArtifactMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactMetadataInput")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("build_id_digest", &Digest::from_text(&self.build_id))
            .field(
                "version_digest",
                &Digest::from_text(&self.version_fingerprint),
            )
            .field("cloud_digest", &Digest::from_text(&self.cloud))
            .field("region_digest", &Digest::from_text(&self.region))
            .field(
                "artifact_location_digest",
                &self.external_identifier.as_deref().map(Digest::from_text),
            )
            .field("state", &self.state)
            .field("label_count", &self.labels.len())
            .finish()
    }
}

fn filter_labels(
    labels: &BTreeMap<String, String>,
    allowlist: &BTreeSet<LabelKey>,
) -> Result<BTreeMap<String, String>> {
    if labels.len() > MAX_LABEL_KEYS.saturating_mul(8) {
        return Err(HcpPackerArtifactResultError::Invalid {
            field: "provider labels",
        });
    }
    let mut filtered = BTreeMap::new();
    for (key, value) in labels {
        if allowlist.iter().any(|allowed| allowed.as_str() == key) {
            if !valid_text(value, MAX_VALUE_BYTES, true) || value.len() > MAX_LABEL_BYTES {
                return Err(HcpPackerArtifactResultError::Invalid {
                    field: "allowlisted label value",
                });
            }
            filtered.insert(key.clone(), value.clone());
        }
    }
    Ok(filtered)
}

impl BucketProjection {
    pub(crate) fn from_input(
        input: &BucketMetadataInput,
        scope: &HcpPackerArtifactScope,
    ) -> Result<Self> {
        if input.organization_id != scope.organization_id.as_str()
            || input.project_id != scope.project_id.as_str()
            || input.name != scope.bucket_name.as_str()
        {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        validate_identifier(&input.id, "bucket-id")?;
        Ok(Self {
            bucket_digest: Digest::from_text(&input.id),
            organization_digest: scope.organization_id.digest(),
            project_digest: scope.project_id.digest(),
            bucket_name_digest: scope.bucket_name.digest(),
            state: BucketState::from_api(&input.state),
            version_count: input.version_count,
            allowlisted_labels: filter_labels(&input.labels, scope.allowlisted_label_keys())?,
        })
    }
}

impl ChannelProjection {
    pub(crate) fn from_input(
        input: &ChannelMetadataInput,
        scope: &HcpPackerArtifactScope,
    ) -> Result<Self> {
        if input.name != scope.channel_name.as_str()
            || input.revision != scope.channel_revision.value()
        {
            return Err(HcpPackerArtifactResultError::StaleState);
        }
        let assigned_version_digest =
            input
                .assigned_version_fingerprint
                .as_deref()
                .map(|fingerprint| {
                    if fingerprint == scope.version_fingerprint.as_str() {
                        scope.version_fingerprint.digest()
                    } else {
                        Digest::from_text(fingerprint)
                    }
                });
        Ok(Self {
            channel_digest: scope.channel_name.digest(),
            assigned_version_digest,
            channel_revision: scope.channel_revision,
            state: ChannelState::from_api(&input.state),
        })
    }
}

impl VersionProjection {
    pub(crate) fn from_input(
        input: &VersionMetadataInput,
        scope: &HcpPackerArtifactScope,
    ) -> Result<Self> {
        if input.fingerprint != scope.version_fingerprint.as_str()
            || input.revision != scope.version_revision.value()
        {
            return Err(HcpPackerArtifactResultError::StaleState);
        }
        validate_identifier(&input.id, "version-id")?;
        Ok(Self {
            version_digest: Digest::from_text(&input.id),
            fingerprint_digest: scope.version_fingerprint.digest(),
            state: VersionState::from_api(&input.state),
            version_revision: scope.version_revision,
            build_count: input.build_count,
            allowlisted_labels: filter_labels(&input.labels, scope.allowlisted_label_keys())?,
            created_at: input.created_at,
            updated_at: input.updated_at,
        })
    }
}

impl BuildProjection {
    pub(crate) fn from_input(
        input: &BuildMetadataInput,
        scope: &HcpPackerArtifactScope,
    ) -> Result<Self> {
        if input.version_fingerprint != scope.version_fingerprint.as_str()
            || input.cloud != scope.cloud.as_str()
            || input.region != scope.region.as_str()
        {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        validate_identifier(&input.id, "build-id")?;
        validate_identifier(&input.component_type, "component-type")?;
        Ok(Self {
            build_digest: Digest::from_text(&input.id),
            version_digest: scope.version_fingerprint.digest(),
            component_type_digest: Digest::from_text(&input.component_type),
            state: BuildState::from_api(&input.state),
            source_location_digest: input
                .source_external_identifier
                .as_deref()
                .map(Digest::from_text),
            cloud_digest: scope.cloud.digest(),
            region_digest: scope.region.digest(),
            allowlisted_labels: filter_labels(&input.labels, scope.allowlisted_label_keys())?,
            created_at: input.created_at,
            updated_at: input.updated_at,
        })
    }
}

impl ArtifactProjection {
    pub(crate) fn from_input(
        input: &ArtifactMetadataInput,
        scope: &HcpPackerArtifactScope,
    ) -> Result<Self> {
        if input.version_fingerprint != scope.version_fingerprint.as_str()
            || input.cloud != scope.cloud.as_str()
            || input.region != scope.region.as_str()
        {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        validate_identifier(&input.id, "artifact-id")?;
        validate_identifier(&input.build_id, "build-id")?;
        Ok(Self {
            artifact_digest: Digest::from_text(&input.id),
            build_digest: Digest::from_text(&input.build_id),
            cloud_digest: scope.cloud.digest(),
            region_digest: scope.region.digest(),
            artifact_location_digest: input.external_identifier.as_deref().map(Digest::from_text),
            state: ArtifactState::from_api(&input.state),
            created_at: input.created_at,
            updated_at: input.updated_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HcpPackerEvidenceState {
    Ready,
    Running,
    Incomplete,
    Cancelled,
    Failed,
    Revoked,
    Partial,
    Stale,
    Truncated,
    PaginationReplay,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    RegistrationRevoked,
}

impl HcpPackerEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub evidence_digest: Digest,
    pub observation_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.evidence_binding_digest.validate()?;
        self.evidence_digest.validate()?;
        self.observation_digest.validate()?;
        if self.evidence_digest != self.observation_digest {
            return Err(HcpPackerArtifactResultError::EvidenceDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HcpPackerArtifactEvidence {
    pub scope_digest: Digest,
    pub bucket: BucketProjection,
    pub channel: ChannelProjection,
    pub version: VersionProjection,
    pub builds: Vec<BuildProjection>,
    pub artifacts: Vec<ArtifactProjection>,
    pub build_pages: u16,
    pub artifact_pages: u16,
    pub complete: bool,
    pub truncated: bool,
    pub redacted: bool,
    pub provenance: TransportProvenance,
    pub digests: EvidenceDigests,
}

impl HcpPackerArtifactEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope: &HcpPackerArtifactScope,
        bucket: BucketProjection,
        channel: ChannelProjection,
        version: VersionProjection,
        builds: Vec<BuildProjection>,
        artifacts: Vec<ArtifactProjection>,
        build_pages: u16,
        artifact_pages: u16,
        provenance: TransportProvenance,
        evidence_binding_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        let observation_digest = Digest::from_parts(
            "hcp-packer-observation/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("bucket", digest_json(&bucket)),
                ("channel", digest_json(&channel)),
                ("version", digest_json(&version)),
                ("builds", digest_json(&builds)),
                ("artifacts", digest_json(&artifacts)),
                ("build_pages", build_pages.to_string()),
                ("artifact_pages", artifact_pages.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        let digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
            contract_digest: Digest::parse(crate::CONTRACT_DIGEST.to_owned())
                .expect("contract digest is pinned as SHA-256"),
            provider_digest,
            api_digest: Digest::from_text(crate::PROVIDER_API_REVISION),
            permission_digest,
            scope_digest: scope.digest(),
            evidence_binding_digest,
            evidence_digest: observation_digest.clone(),
            observation_digest,
        };
        Self {
            scope_digest: scope.digest(),
            bucket,
            channel,
            version,
            builds,
            artifacts,
            build_pages,
            artifact_pages,
            complete: true,
            truncated: false,
            redacted: true,
            provenance,
            digests,
        }
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn validate_integrity(&self, scope: &HcpPackerArtifactScope) -> Result<()> {
        let observation_digest = Digest::from_parts(
            "hcp-packer-observation/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("bucket", digest_json(&self.bucket)),
                ("channel", digest_json(&self.channel)),
                ("version", digest_json(&self.version)),
                ("builds", digest_json(&self.builds)),
                ("artifacts", digest_json(&self.artifacts)),
                ("build_pages", self.build_pages.to_string()),
                ("artifact_pages", self.artifact_pages.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        );
        if self.scope_digest != scope.digest()
            || !self.complete
            || self.truncated
            || !self.redacted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.builds.len() > MAX_BUILDS
            || self.artifacts.len() > MAX_ARTIFACTS
            || self.digests.observation_digest != observation_digest
            || self.digests.evidence_digest != observation_digest
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        self.digests.validate()?;
        for build in &self.builds {
            build.build_digest.validate()?;
        }
        for artifact in &self.artifacts {
            artifact.artifact_digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub redacted: bool,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    pub(crate) fn from_error(error: &HcpPackerArtifactResultError) -> Self {
        let category = match error {
            HcpPackerArtifactResultError::AccessLoss
            | HcpPackerArtifactResultError::Transport(
                crate::error::HcpPackerTransportError::Unauthorized
                | crate::error::HcpPackerTransportError::Forbidden
                | crate::error::HcpPackerTransportError::AccessLoss,
            ) => "access_loss",
            HcpPackerArtifactResultError::ProviderUnknown
            | HcpPackerArtifactResultError::Transport(
                crate::error::HcpPackerTransportError::BlockedEnvironment
                | crate::error::HcpPackerTransportError::ProviderUnknown
                | crate::error::HcpPackerTransportError::MalformedResponse,
            ) => "provider_unknown",
            HcpPackerArtifactResultError::PaginationReplay
            | HcpPackerArtifactResultError::ReplayConflict
            | HcpPackerArtifactResultError::Transport(
                crate::error::HcpPackerTransportError::Replay,
            ) => "pagination_replay",
            HcpPackerArtifactResultError::PaginationExceeded => "pagination_exhausted",
            HcpPackerArtifactResultError::Truncated
            | HcpPackerArtifactResultError::ResponseTooLarge
            | HcpPackerArtifactResultError::Transport(
                crate::error::HcpPackerTransportError::ResponseTruncated,
            ) => "truncated",
            HcpPackerArtifactResultError::StaleState => "stale",
            HcpPackerArtifactResultError::TamperedEvidence => "tampered",
            HcpPackerArtifactResultError::RegistrationInactive
            | HcpPackerArtifactResultError::RegistrationReversed
            | HcpPackerArtifactResultError::SecretRevoked => "registration_revoked",
            _ => "provider_unknown",
        }
        .to_owned();
        Self {
            failure_digest: Digest::from_parts(
                "hcp-packer-failure/v1",
                &[("category", category.clone())],
            ),
            category,
            status_code: None,
            redacted: true,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !self.redacted
            || self.category.is_empty()
            || self.category.contains(['\r', '\n'])
            || self.failure_digest
                != Digest::from_parts(
                    "hcp-packer-failure/v1",
                    &[("category", self.category.clone())],
                )
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    scope_digest: Digest,
    operation: String,
    subject_digest: Digest,
    page_number: u16,
    expires_at: DateTime<Utc>,
}

impl OpaqueCursor {
    pub fn new(
        opaque_token: impl AsRef<str>,
        scope: &HcpPackerArtifactScope,
        operation: impl Into<String>,
        subject_digest: Digest,
        page_number: u16,
    ) -> Result<Self> {
        Self::new_at(
            opaque_token,
            scope,
            operation,
            subject_digest,
            page_number,
            Utc::now(),
        )
    }

    pub fn new_at(
        opaque_token: impl AsRef<str>,
        scope: &HcpPackerArtifactScope,
        operation: impl Into<String>,
        subject_digest: Digest,
        page_number: u16,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let opaque_token = opaque_token.as_ref();
        if opaque_token.is_empty() || opaque_token.len() > MAX_VALUE_BYTES {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        if !(2..=crate::MAX_PAGES).contains(&page_number) {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        let operation = operation.into();
        validate_identifier(&operation, "pagination operation")?;
        subject_digest.validate()?;
        Ok(Self {
            token_digest: Digest::from_text(opaque_token),
            scope_digest: scope.digest(),
            operation,
            subject_digest,
            page_number,
            expires_at: now + Duration::seconds(NEXT_TOKEN_TTL_SECONDS),
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn subject_digest(&self) -> &Digest {
        &self.subject_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn validate_against(
        &self,
        scope: &HcpPackerArtifactScope,
        operation: &str,
        subject_digest: &Digest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.operation != operation
            || self.subject_digest != *subject_digest
            || self.page_number < 2
        {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        if now > self.expires_at {
            return Err(HcpPackerArtifactResultError::StaleState);
        }
        Ok(())
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("opaque", &true)
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("operation", &self.operation)
            .field("subject_digest", &self.subject_digest)
            .field("page_number", &self.page_number)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

fn digest_json<T: Serialize>(value: &T) -> String {
    serde_json::to_vec(value).map_or_else(
        |_| Digest::zero().as_str().to_owned(),
        |bytes| Digest::from_bytes(&bytes).as_str().to_owned(),
    )
}

pub(crate) fn validate_response_bytes(response_bytes: usize) -> Result<()> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(HcpPackerArtifactResultError::ResponseTooLarge)
    } else {
        Ok(())
    }
}
