//! Digest-first, bounded models for the AWS ECR image-scan Layer-1 slice.
//!
//! The model deliberately has no representation for credentials, image
//! layers, image bytes, tags, package paths, URLs, or provider response
//! bodies. Values that are useful for evidence but not safe to retain are
//! reduced to bounded SHA-256 digests at the provider boundary.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::Error as SerError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REPOSITORY_BYTES: usize = 256;
pub const MAX_IMAGE_DIGEST_BYTES: usize = 71;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_FINDINGS: usize = 256;
pub const MAX_SEVERITY_ENTRIES: usize = 8;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 100;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 8;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_FINDING_METADATA_BYTES: usize = 512;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(value: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(value.as_ref())))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    #[must_use]
    pub fn from_parts<I, S>(label: &str, parts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(label.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_ref());
        }
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded ECR value serializes");
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, ModelError> {
        let value = value.into();
        validate_digest(&value, field)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[must_use]
pub fn sha256_digest(value: impl AsRef<[u8]>) -> Digest {
    Digest::from_bytes(value)
}

#[must_use]
pub fn serialized_digest<T: Serialize>(value: &T) -> Digest {
    Digest::from_serialized(value)
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds its bound")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} is not allowed in Layer 1")]
    Unsupported { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@*".contains(&byte)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field, $max)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(RegistryId, "ECR registry", MAX_IDENTIFIER_BYTES);
bounded_identifier!(RepositoryName, "ECR repository", MAX_REPOSITORY_BYTES);
bounded_identifier!(AwsRegion, "AWS region", MAX_IDENTIFIER_BYTES);
bounded_identifier!(ProjectId, "Project id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(MissionId, "Mission id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WorkProductId, "Work Product id", MAX_IDENTIFIER_BYTES);

pub type Region = AwsRegion;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != MAX_IMAGE_DIGEST_BYTES
            || !value.starts_with("sha256:")
            || !value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::Invalid {
                field: "ECR image digest",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for ImageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageDigest")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        Digest::from_text(self.0.to_string())
    }
}

pub type ScanRevision = Revision;
pub type InspectorFindingRevision = Revision;
pub type FindingRevision = Revision;
pub type MissionRevision = Revision;
pub type ProjectRevision = Revision;
pub type WorkProductRevision = Revision;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Basic,
    Enhanced,
}

impl ScanType {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "basic" | "basic_scanning" => Ok(Self::Basic),
            "enhanced" | "enhanced_scanning" => Ok(Self::Enhanced),
            _ => Err(ModelError::Invalid {
                field: "ECR scan type",
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Enhanced => "enhanced",
        }
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    id: MissionId,
    revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &MissionId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    id: ProjectId,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    EcrDescribeImages,
    EcrDescribeImageScanFindings,
}

impl PermissionAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcrDescribeImages => "ecr:DescribeImages",
            Self::EcrDescribeImageScanFindings => "ecr:DescribeImageScanFindings",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionFence {
    actions: BTreeSet<PermissionAction>,
    revision: Revision,
    digest: Digest,
}

impl PermissionFence {
    pub fn new<I>(actions: I, revision: u64) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = PermissionAction>,
    {
        let actions: BTreeSet<_> = actions.into_iter().collect();
        let expected = BTreeSet::from([
            PermissionAction::EcrDescribeImages,
            PermissionAction::EcrDescribeImageScanFindings,
        ]);
        if actions != expected {
            return Err(ModelError::Unsupported {
                field: "ECR permission action",
            });
        }
        let revision = Revision::new(revision)?;
        let digest = serialized_digest(&PermissionDigestMaterial {
            actions: &actions,
            revision,
        });
        Ok(Self {
            actions,
            revision,
            digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                PermissionAction::EcrDescribeImages,
                PermissionAction::EcrDescribeImageScanFindings,
            ],
            revision,
        )
    }

    #[must_use]
    pub fn actions(&self) -> &BTreeSet<PermissionAction> {
        &self.actions
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn has(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.actions.iter().copied(), self.revision.get())?;
        if expected.digest != self.digest {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcrImageScanScopeSpec {
    pub registry: RegistryId,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub repository: RepositoryName,
    pub image_digest: ImageDigest,
    pub scan_type: ScanType,
    pub scan_revision: ScanRevision,
    pub inspector_finding_revision: InspectorFindingRevision,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionFence,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanScope {
    registry: RegistryId,
    account_id: AccountId,
    region: AwsRegion,
    repository: RepositoryName,
    image_digest: ImageDigest,
    scan_type: ScanType,
    scan_revision: ScanRevision,
    inspector_finding_revision: InspectorFindingRevision,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission: PermissionFence,
    scope_digest: Digest,
}

impl EcrImageScanScope {
    pub fn new(spec: EcrImageScanScopeSpec) -> Result<Self, ModelError> {
        spec.permission.validate()?;
        if !spec.permission.has(PermissionAction::EcrDescribeImages)
            || !spec
                .permission
                .has(PermissionAction::EcrDescribeImageScanFindings)
        {
            return Err(ModelError::Unsupported {
                field: "ECR permission action",
            });
        }
        let material = ScopeDigestMaterial {
            registry: &spec.registry,
            account_id: &spec.account_id,
            region: &spec.region,
            repository: &spec.repository,
            image_digest: &spec.image_digest,
            scan_type: spec.scan_type,
            scan_revision: spec.scan_revision,
            inspector_finding_revision: spec.inspector_finding_revision,
            project: &spec.project,
            mission: &spec.mission,
            work_product: &spec.work_product,
            permission_digest: spec.permission.digest(),
        };
        let scope_digest = serialized_digest(&material);
        Ok(Self {
            registry: spec.registry,
            account_id: spec.account_id,
            region: spec.region,
            repository: spec.repository,
            image_digest: spec.image_digest,
            scan_type: spec.scan_type,
            scan_revision: spec.scan_revision,
            inspector_finding_revision: spec.inspector_finding_revision,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            permission: spec.permission,
            scope_digest,
        })
    }

    #[must_use]
    pub fn registry(&self) -> &RegistryId {
        &self.registry
    }

    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    #[must_use]
    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    #[must_use]
    pub fn repository(&self) -> &RepositoryName {
        &self.repository
    }

    #[must_use]
    pub fn image_digest(&self) -> &ImageDigest {
        &self.image_digest
    }

    #[must_use]
    pub const fn scan_type(&self) -> ScanType {
        self.scan_type
    }

    #[must_use]
    pub const fn scan_revision(&self) -> ScanRevision {
        self.scan_revision
    }

    #[must_use]
    pub const fn inspector_finding_revision(&self) -> InspectorFindingRevision {
        self.inspector_finding_revision
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn registry_digest(&self) -> Digest {
        self.registry.digest()
    }

    #[must_use]
    pub fn repository_digest(&self) -> Digest {
        self.repository.digest()
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        serialized_digest(&(
            self.scan_revision,
            self.inspector_finding_revision,
            self.project.revision(),
            self.mission.revision(),
            self.work_product.revision(),
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(EcrImageScanScopeSpec {
            registry: self.registry.clone(),
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            repository: self.repository.clone(),
            image_digest: self.image_digest.clone(),
            scan_type: self.scan_type,
            scan_revision: self.scan_revision,
            inspector_finding_revision: self.inspector_finding_revision,
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            permission: self.permission.clone(),
        })?;
        if rebuilt.scope_digest != self.scope_digest {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        Ok(())
    }
}

pub type EcrScope = EcrImageScanScope;
pub type EcrImageScope = EcrImageScanScope;

#[derive(Serialize)]
struct PermissionDigestMaterial<'a> {
    actions: &'a BTreeSet<PermissionAction>,
    revision: Revision,
}

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    registry: &'a RegistryId,
    account_id: &'a AccountId,
    region: &'a AwsRegion,
    repository: &'a RepositoryName,
    image_digest: &'a ImageDigest,
    scan_type: ScanType,
    scan_revision: ScanRevision,
    inspector_finding_revision: InspectorFindingRevision,
    project: &'a ProjectBinding,
    mission: &'a MissionBinding,
    work_product: &'a WorkProductBinding,
    permission_digest: &'a Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<[u8]>,
        scope_digest: &Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference = reference_id.as_ref();
        if reference.is_empty() || reference.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::Invalid {
                field: "SigV4 SecretReference",
            });
        }
        if reference.iter().any(u8::is_ascii_control) {
            return Err(ModelError::Invalid {
                field: "SigV4 SecretReference",
            });
        }
        validate_digest(scope_digest.as_str(), "SecretReference scope digest")?;
        Ok(Self {
            reference_digest: Digest::from_bytes(reference),
            scope_digest: scope_digest.clone(),
            credential_revision: Revision::new(credential_revision)?,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl AsRef<[u8]>,
        scope: &EcrImageScanScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, scope.scope_digest(), credential_revision)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(&SecretDigestMaterial {
            reference_digest: &self.reference_digest,
            scope_digest: &self.scope_digest,
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        })
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            return Err(ModelError::NotRevoked);
        }
        self.revoked = false;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(SerError::custom(
            "opaque SigV4 SecretReference is intentionally non-serializing",
        ))
    }
}

#[derive(Serialize)]
struct SecretDigestMaterial<'a> {
    reference_digest: &'a Digest,
    scope_digest: &'a Digest,
    credential_revision: Revision,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EcrOperation {
    DescribeImages,
    DescribeImageScanFindings,
    ReadScan,
}

impl EcrOperation {
    #[must_use]
    pub const fn method(self) -> &'static str {
        "POST"
    }

    #[must_use]
    pub const fn target(self) -> &'static str {
        match self {
            Self::DescribeImages => "AmazonEC2ContainerRegistry_V20150921.DescribeImages",
            Self::DescribeImageScanFindings => {
                "AmazonEC2ContainerRegistry_V20150921.DescribeImageScanFindings"
            }
            Self::ReadScan => "hartevo.ecr.ReadScan",
        }
    }

    #[must_use]
    pub const fn permission(self) -> Option<PermissionAction> {
        match self {
            Self::DescribeImages => Some(PermissionAction::EcrDescribeImages),
            Self::DescribeImageScanFindings => Some(PermissionAction::EcrDescribeImageScanFindings),
            Self::ReadScan => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLifecycle {
    Pending,
    Complete,
    Failed,
    Inactive,
    Expired,
    Unknown,
}

impl ScanLifecycle {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "IN_PROGRESS" | "PENDING" | "QUEUED" => Self::Pending,
            "COMPLETE" | "COMPLETED" => Self::Complete,
            "FAILED" | "FAILURE" => Self::Failed,
            "UNSUPPORTED" | "INACTIVE" | "FINDINGS_UNAVAILABLE" => Self::Inactive,
            "SCAN_ELIGIBILITY_EXPIRED" | "EXPIRED" => Self::Expired,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProjection {
    Pending,
    Complete,
    Failed,
    Inactive,
    Expired,
    Partial,
    Stale,
    AccessLost,
    Tampered,
    ProviderUnknown,
}

impl ScanProjection {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Failed | Self::Inactive | Self::Expired
        )
    }
}

pub type EcrImageScanState = ScanProjection;
pub type EcrImageScanProjection = ScanProjection;
pub type ImageScanState = ScanProjection;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageLimit,
    CursorReplay,
    FindingsLimit,
    SeverityLimit,
    MissingImage,
    ScanStatusIncomplete,
    ProviderTruncation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    Partial,
    AccessLost,
    Stale,
    Tampered,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
    Undefined,
    Unknown,
}

impl Severity {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MEDIUM" => Self::Medium,
            "LOW" => Self::Low,
            "INFORMATIONAL" | "INFO" => Self::Informational,
            "UNDEFINED" | "NONE" => Self::Undefined,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixStatus {
    Available,
    NotAvailable,
    Unknown,
}

impl FixStatus {
    #[must_use]
    pub fn from_fixed_version(value: Option<&str>) -> Self {
        match value {
            Some(value)
                if value.is_empty()
                    || value == "-"
                    || value.eq_ignore_ascii_case("notavailable") =>
            {
                Self::NotAvailable
            }
            Some(_) => Self::Available,
            None => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SeverityCount {
    pub severity: Severity,
    pub count: u64,
}

impl SeverityCount {
    pub fn new(severity: Severity, count: u64) -> Self {
        Self { severity, count }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedFinding {
    pub severity: Severity,
    pub cve_digest: Digest,
    pub package_digest: Digest,
    pub installed_version_digest: Digest,
    pub fix_status: FixStatus,
    pub fixed_version_digest: Digest,
    pub metadata_digest: Digest,
}

impl RedactedFinding {
    pub fn from_raw(
        severity: Severity,
        cve: Option<&str>,
        package: Option<&str>,
        installed_version: Option<&str>,
        fixed_version: Option<&str>,
    ) -> Result<Self, ModelError> {
        for (value, field) in [
            (cve, "CVE identifier"),
            (package, "package identifier"),
            (installed_version, "installed package version"),
            (fixed_version, "fixed package version"),
        ] {
            if let Some(value) = value
                && (value.len() > MAX_FINDING_METADATA_BYTES || value.chars().any(char::is_control))
            {
                return Err(ModelError::Invalid { field });
            }
        }
        let cve_digest = optional_digest(cve);
        let package_digest = optional_digest(package);
        let installed_version_digest = optional_digest(installed_version);
        let fixed_version_digest = optional_digest(fixed_version);
        let fix_status = FixStatus::from_fixed_version(fixed_version);
        let metadata_digest = serialized_digest(&FindingDigestMaterial {
            severity,
            cve_digest: &cve_digest,
            package_digest: &package_digest,
            installed_version_digest: &installed_version_digest,
            fix_status,
            fixed_version_digest: &fixed_version_digest,
        });
        Ok(Self {
            severity,
            cve_digest,
            package_digest,
            installed_version_digest,
            fix_status,
            fixed_version_digest,
            metadata_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = serialized_digest(&FindingDigestMaterial {
            severity: self.severity,
            cve_digest: &self.cve_digest,
            package_digest: &self.package_digest,
            installed_version_digest: &self.installed_version_digest,
            fix_status: self.fix_status,
            fixed_version_digest: &self.fixed_version_digest,
        });
        if expected != self.metadata_digest {
            return Err(ModelError::ScopeMismatch {
                field: "finding metadata digest",
            });
        }
        Ok(())
    }
}

pub type FindingMetadata = RedactedFinding;
pub type RedactedFindingMetadata = RedactedFinding;

fn optional_digest(value: Option<&str>) -> Digest {
    value
        .filter(|value| !value.is_empty())
        .map_or_else(Digest::zero, Digest::from_text)
}

#[derive(Serialize)]
struct FindingDigestMaterial<'a> {
    severity: Severity,
    cve_digest: &'a Digest,
    package_digest: &'a Digest,
    installed_version_digest: &'a Digest,
    fix_status: FixStatus,
    fixed_version_digest: &'a Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageDescriptor {
    pub image_digest: ImageDigest,
}

impl EcrImageDescriptor {
    pub fn new(image_digest: ImageDigest) -> Self {
        Self { image_digest }
    }

    pub fn from_digest(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::new(ImageDigest::new(value)?))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_credentials_dropped: bool,
    pub raw_pagination_dropped: bool,
    pub raw_provider_body_dropped: bool,
    pub raw_layers_dropped: bool,
    pub raw_image_bytes_dropped: bool,
    pub raw_tags_dropped: bool,
    pub raw_finding_metadata_dropped: bool,
    pub raw_pii_dropped: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            raw_credentials_dropped: true,
            raw_pagination_dropped: true,
            raw_provider_body_dropped: true,
            raw_layers_dropped: true,
            raw_image_bytes_dropped: true,
            raw_tags_dropped: true,
            raw_finding_metadata_dropped: true,
            raw_pii_dropped: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorEvidence {
    pub kind: String,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(kind: impl Into<String>, status_code: Option<u16>, diagnostic: &str) -> Self {
        let kind = kind.into();
        let kind = kind
            .chars()
            .filter(|character| !character.is_control())
            .take(MAX_IDENTIFIER_BYTES)
            .collect::<String>();
        let diagnostic = diagnostic
            .chars()
            .filter(|character| !character.is_control())
            .take(MAX_DIAGNOSTIC_BYTES)
            .collect::<String>();
        Self {
            kind: if kind.is_empty() {
                "unknown".to_owned()
            } else {
                kind
            },
            status_code,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub describe_images_request_digest: Digest,
    pub findings_request_digest: Digest,
    pub image_digest: Digest,
    pub findings_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanEvidence {
    pub operation: EcrOperation,
    pub state: ScanProjection,
    pub lifecycle: Option<ScanLifecycle>,
    pub partial_reason: Option<PartialReason>,
    pub classification: EvidenceClassification,
    pub registry: RegistryId,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub repository: RepositoryName,
    pub image: EcrImageDescriptor,
    pub scan_type: ScanType,
    pub scan_revision: ScanRevision,
    pub inspector_finding_revision: InspectorFindingRevision,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub severity_counts: Vec<SeverityCount>,
    pub findings: Vec<RedactedFinding>,
    pub image_pages: u16,
    pub findings_pages: u16,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub redactions: RedactionSummary,
    pub request_digest: Digest,
    pub findings_request_digest: Digest,
    pub response_digest: Digest,
    pub digests: EvidenceDigests,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub adopted_outcome: bool,
    pub evidence_digest: Digest,
}

impl EcrImageScanEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(&EvidenceDigestMaterial {
            operation: self.operation,
            state: self.state,
            lifecycle: self.lifecycle,
            partial_reason: self.partial_reason,
            classification: self.classification,
            registry: &self.registry,
            account_id: &self.account_id,
            region: &self.region,
            repository: &self.repository,
            image: &self.image,
            scan_type: self.scan_type,
            scan_revision: self.scan_revision,
            inspector_finding_revision: self.inspector_finding_revision,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            severity_counts: &self.severity_counts,
            findings: &self.findings,
            image_pages: self.image_pages,
            findings_pages: self.findings_pages,
            provider_error: &self.provider_error,
            provenance: self.provenance,
            redactions: &self.redactions,
            request_digest: &self.request_digest,
            findings_request_digest: &self.findings_request_digest,
            response_digest: &self.response_digest,
            version_digest: &self.digests.version_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            registration_digest: &self.digests.registration_digest,
            describe_images_request_digest: &self.digests.describe_images_request_digest,
            nested_findings_request_digest: &self.digests.findings_request_digest,
            image_digest: &self.digests.image_digest,
            findings_digest: &self.digests.findings_digest,
            digest_response_digest: &self.digests.response_digest,
            native: self.native,
            connected: self.connected,
            durable_receipt: self.durable_receipt,
            independent_readback: self.independent_readback,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate(&self, scope: &EcrImageScanScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.registry != *scope.registry()
            || self.account_id != *scope.account_id()
            || self.region != *scope.region()
            || self.repository != *scope.repository()
            || self.image.image_digest != *scope.image_digest()
            || self.scan_type != scope.scan_type()
            || self.scan_revision != scope.scan_revision()
            || self.inspector_finding_revision != scope.inspector_finding_revision()
            || self.project != *scope.project()
            || self.mission != *scope.mission()
            || self.work_product != *scope.work_product()
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.native
            || self.connected
            || self.durable_receipt
            || self.independent_readback
            || self.adopted_outcome
            || self.redactions != RedactionSummary::default()
            || self.evidence_digest != self.digest()
            || self.digests.evidence_digest != self.evidence_digest
            || self.digests.version_digest != crate::version_digest()
            || self.digests.contract_digest != crate::contract_digest()
            || self.digests.permission_digest != *scope.permission().digest()
            || self.digests.scope_digest != *scope.scope_digest()
            || self.digests.describe_images_request_digest != self.request_digest
            || self.digests.findings_request_digest != self.findings_request_digest
            || self.digests.response_digest != self.response_digest
            || self.digests.image_digest != self.image.image_digest.digest()
            || self
                .findings
                .iter()
                .any(|finding| finding.validate().is_err())
        {
            return Err(ModelError::ScopeMismatch {
                field: "ECR evidence fence",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn is_access_loss(&self) -> bool {
        self.state == ScanProjection::AccessLost
    }

    #[must_use]
    pub fn is_tampered(&self) -> bool {
        self.state == ScanProjection::Tampered
    }
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    operation: EcrOperation,
    state: ScanProjection,
    lifecycle: Option<ScanLifecycle>,
    partial_reason: Option<PartialReason>,
    classification: EvidenceClassification,
    registry: &'a RegistryId,
    account_id: &'a AccountId,
    region: &'a AwsRegion,
    repository: &'a RepositoryName,
    image: &'a EcrImageDescriptor,
    scan_type: ScanType,
    scan_revision: ScanRevision,
    inspector_finding_revision: InspectorFindingRevision,
    project: &'a ProjectBinding,
    mission: &'a MissionBinding,
    work_product: &'a WorkProductBinding,
    severity_counts: &'a [SeverityCount],
    findings: &'a [RedactedFinding],
    image_pages: u16,
    findings_pages: u16,
    provider_error: &'a Option<ProviderErrorEvidence>,
    provenance: TransportProvenance,
    redactions: &'a RedactionSummary,
    request_digest: &'a Digest,
    nested_findings_request_digest: &'a Digest,
    response_digest: &'a Digest,
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    describe_images_request_digest: &'a Digest,
    findings_request_digest: &'a Digest,
    image_digest: &'a Digest,
    findings_digest: &'a Digest,
    digest_response_digest: &'a Digest,
    native: bool,
    connected: bool,
    durable_receipt: bool,
    independent_readback: bool,
    adopted_outcome: bool,
}
