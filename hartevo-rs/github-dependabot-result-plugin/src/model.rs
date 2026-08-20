//! Typed, bounded GitHub Dependabot scope and evidence models.
//!
//! The public model deliberately has no representation for a raw advisory
//! description, raw package name, raw manifest path, credential material, or
//! raw provider payload. Those values are either reduced to a digest or
//! discarded before they can cross the Layer-1 boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PATH_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_ALERTS: usize = 256;
pub const MAX_ALERTS_PER_PAGE: usize = 64;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_RETRIES: u8 = 2;
pub const MAX_PROVIDER_ERRORS: usize = 8;
pub const MAX_ADVISORY_IDENTIFIERS: usize = 8;

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
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
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
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@#~%".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(AdvisoryIdentifier, "advisory identifier");

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type AlertRevision = Revision;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).unwrap_or_default())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct RepositoryOwner(String);

impl RepositoryOwner {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "repository owner", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RepositoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryOwner")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for RepositoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct RepositoryName(String);

impl RepositoryName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "repository name", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RepositoryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryName")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for RepositoryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubRepository {
    pub owner: RepositoryOwner,
    pub name: RepositoryName,
}

impl GithubRepository {
    pub const fn new(owner: RepositoryOwner, name: RepositoryName) -> Self {
        Self { owner, name }
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-github-dependabot-repository/v1",
            &[
                self.owner.as_str().to_owned(),
                self.name.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct RefName(String);

impl RefName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "repository ref", MAX_IDENTIFIER_BYTES)?;
        if value.starts_with('/') || value.ends_with('/') || value.contains("..") {
            return Err(ModelError::Invalid {
                field: "repository ref",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefName")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !(7..=64).contains(&value.len()) || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
            return Err(ModelError::Invalid {
                field: "commit SHA",
            });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitSha")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestPath {
    digest: Digest,
}

impl ManifestPath {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, "manifest path", MAX_PATH_BYTES)?;
        if value.starts_with('/') || value.split('/').any(|segment| segment == "..") {
            return Err(ModelError::Invalid {
                field: "manifest path",
            });
        }
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-github-dependabot-manifest/v1",
                &[value.to_owned()],
            ),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for ManifestPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestPath")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for ManifestPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("ManifestPath", 1)?;
        value.serialize_field("digest", &self.digest)?;
        value.end()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageName {
    digest: Digest,
}

impl PackageName {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, "package name", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            digest: Digest::from_parts("hartevo-github-dependabot-package/v1", &[value.to_owned()]),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for PackageName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageName")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for PackageName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("PackageName", 1)?;
        value.serialize_field("digest", &self.digest)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GithubAuthKind {
    App,
    OAuth,
}

/// An App/OAuth reference is reduced to a digest. The original reference is
/// never retained and the custom serializer only emits an opaque marker.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    auth_kind: GithubAuthKind,
    scope_digest: Option<Digest>,
}

impl SecretReference {
    pub fn new(reference: impl AsRef<str>, auth_kind: GithubAuthKind) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        validate_text(reference, "GitHub secret reference", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-github-dependabot-secret/v1",
                &[format!("{auth_kind:?}"), reference.to_owned()],
            ),
            auth_kind,
            scope_digest: None,
        })
    }

    pub fn for_scope(
        reference: impl AsRef<str>,
        scope: &GithubDependabotScope,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        validate_text(reference, "GitHub secret reference", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-github-dependabot-scoped-secret/v1",
                &[
                    format!("{auth_kind:?}"),
                    reference.to_owned(),
                    scope.digest().to_string(),
                ],
            ),
            auth_kind,
            scope_digest: Some(scope.digest()),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn auth_kind(&self) -> GithubAuthKind {
        self.auth_kind
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference", &"<opaque>")
            .field("auth_kind", &self.auth_kind)
            .field("scope_digest", &self.scope_digest)
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor {
                field: "page cursor",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-github-dependabot-page-cursor/v1",
                &[value.to_owned()],
            ),
            binding_digest: None,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEcosystem {
    Actions,
    Bundler,
    Cargo,
    Composer,
    Dart,
    Docker,
    Go,
    Hex,
    Maven,
    Npm,
    Nuget,
    Pip,
    Pub,
    Swift,
    Terraform,
    Unknown,
}

impl PackageEcosystem {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        let ecosystem = match value.to_ascii_lowercase().as_str() {
            "actions" => Self::Actions,
            "bundler" => Self::Bundler,
            "cargo" => Self::Cargo,
            "composer" => Self::Composer,
            "dart" => Self::Dart,
            "docker" => Self::Docker,
            "go" => Self::Go,
            "hex" => Self::Hex,
            "maven" => Self::Maven,
            "npm" => Self::Npm,
            "nuget" => Self::Nuget,
            "pip" => Self::Pip,
            "pub" => Self::Pub,
            "swift" => Self::Swift,
            "terraform" => Self::Terraform,
            _ => {
                return Err(ModelError::Unsupported {
                    field: "Dependabot package ecosystem",
                });
            }
        };
        Ok(ecosystem)
    }

    pub const fn is_api_value(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Open,
    Fixed,
    Dismissed,
    AutoDismissed,
}

impl AlertState {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value {
            "open" => Ok(Self::Open),
            "fixed" => Ok(Self::Fixed),
            "dismissed" => Ok(Self::Dismissed),
            "auto_dismissed" => Ok(Self::AutoDismissed),
            _ => Err(ModelError::Invalid {
                field: "Dependabot alert state",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "moderate" => Ok(Self::Moderate),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(ModelError::Invalid {
                field: "Dependabot severity",
            }),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct AlertNumber(u64);

impl AlertNumber {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "alert number")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependabotAlertBinding {
    pub number: AlertNumber,
    pub revision: AlertRevision,
    pub package_ecosystem: PackageEcosystem,
    pub dependency_digest: Digest,
    pub package_digest: Digest,
    pub manifest_digest: Digest,
}

impl DependabotAlertBinding {
    pub fn new(
        number: AlertNumber,
        revision: AlertRevision,
        package_ecosystem: PackageEcosystem,
        package_name: impl AsRef<str>,
        manifest_path: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let package = PackageName::new(package_name)?;
        let manifest = ManifestPath::new(manifest_path)?;
        let dependency_digest = Digest::from_parts(
            "hartevo-github-dependabot-dependency/v1",
            &[
                format!("{package_ecosystem:?}"),
                package.digest().to_string(),
                manifest.digest().to_string(),
            ],
        );
        Ok(Self {
            number,
            revision,
            package_ecosystem,
            dependency_digest,
            package_digest: package.digest().clone(),
            manifest_digest: manifest.digest().clone(),
        })
    }

    pub fn from_digests(
        number: AlertNumber,
        revision: AlertRevision,
        package_ecosystem: PackageEcosystem,
        package_digest: Digest,
        manifest_digest: Digest,
    ) -> Result<Self, ModelError> {
        if package_digest == Digest::zero() || manifest_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "Dependabot package or manifest digest",
            });
        }
        let dependency_digest = Digest::from_parts(
            "hartevo-github-dependabot-dependency/v1",
            &[
                format!("{package_ecosystem:?}"),
                package_digest.to_string(),
                manifest_digest.to_string(),
            ],
        );
        Ok(Self {
            number,
            revision,
            package_ecosystem,
            dependency_digest,
            package_digest,
            manifest_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotScope {
    pub deployment: DeploymentBinding,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub repository: GithubRepository,
    pub ref_name: RefName,
    pub commit_sha: CommitSha,
    pub alerts: Vec<DependabotAlertBinding>,
    pub permission_digest: Digest,
}

impl GithubDependabotScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        repository: GithubRepository,
        ref_name: RefName,
        commit_sha: CommitSha,
        alerts: impl IntoIterator<Item = DependabotAlertBinding>,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut alerts = alerts.into_iter().collect::<Vec<_>>();
        if alerts.is_empty() {
            return Err(ModelError::Empty {
                field: "Dependabot alert allowlist",
            });
        }
        if alerts.len() > MAX_ALERTS {
            return Err(ModelError::TooMany {
                field: "Dependabot alert allowlist",
            });
        }
        alerts.sort_by_key(|alert| alert.number);
        for pair in alerts.windows(2) {
            if pair[0].number == pair[1].number {
                return Err(ModelError::Duplicate {
                    field: "Dependabot alert allowlist",
                });
            }
        }
        let scope = Self {
            deployment,
            project,
            mission,
            work_product,
            repository,
            ref_name,
            commit_sha,
            alerts,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.alerts.is_empty() {
            return Err(ModelError::Empty {
                field: "Dependabot alert allowlist",
            });
        }
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn alert_binding(&self, number: AlertNumber) -> Option<&DependabotAlertBinding> {
        self.alerts.iter().find(|alert| alert.number == number)
    }

    pub fn expected_alerts(&self, request: &GithubDependabotReadRequest) -> Vec<AlertNumber> {
        request.alert_number.map_or_else(
            || self.alerts.iter().map(|alert| alert.number).collect(),
            |number| vec![number],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    ListDependabotAlerts,
    GetDependabotAlert,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::ListDependabotAlerts,
                PermissionAction::GetDependabotAlert,
            ],
        )
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(Self {
            id,
            revision,
            allowed_actions,
        })
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertFilter {
    pub states: BTreeSet<AlertState>,
    pub severities: BTreeSet<Severity>,
    pub ecosystems: BTreeSet<PackageEcosystem>,
    pub package_digests: BTreeSet<Digest>,
}

impl AlertFilter {
    pub fn new(
        states: impl IntoIterator<Item = AlertState>,
        severities: impl IntoIterator<Item = Severity>,
        ecosystems: impl IntoIterator<Item = PackageEcosystem>,
    ) -> Result<Self, ModelError> {
        let states = states.into_iter().collect::<BTreeSet<_>>();
        let severities = severities.into_iter().collect::<BTreeSet<_>>();
        let ecosystems = ecosystems.into_iter().collect::<BTreeSet<_>>();
        if states.is_empty() || severities.is_empty() || ecosystems.is_empty() {
            return Err(ModelError::Empty {
                field: "Dependabot alert filter",
            });
        }
        if ecosystems.contains(&PackageEcosystem::Unknown) {
            return Err(ModelError::Unsupported {
                field: "unknown package ecosystem filter",
            });
        }
        Ok(Self {
            states,
            severities,
            ecosystems,
            package_digests: BTreeSet::new(),
        })
    }

    pub fn with_package_digests(
        mut self,
        package_digests: impl IntoIterator<Item = Digest>,
    ) -> Result<Self, ModelError> {
        let package_digests = package_digests.into_iter().collect::<BTreeSet<_>>();
        if package_digests.len() > MAX_ALERTS
            || package_digests
                .iter()
                .any(|digest| *digest == Digest::zero())
        {
            return Err(ModelError::Invalid {
                field: "Dependabot package digest filter",
            });
        }
        self.package_digests = package_digests;
        Ok(self)
    }

    pub fn all() -> Self {
        Self {
            states: [
                AlertState::Open,
                AlertState::Fixed,
                AlertState::Dismissed,
                AlertState::AutoDismissed,
            ]
            .into_iter()
            .collect(),
            severities: [
                Severity::Low,
                Severity::Moderate,
                Severity::High,
                Severity::Critical,
            ]
            .into_iter()
            .collect(),
            ecosystems: [
                PackageEcosystem::Actions,
                PackageEcosystem::Bundler,
                PackageEcosystem::Cargo,
                PackageEcosystem::Composer,
                PackageEcosystem::Dart,
                PackageEcosystem::Docker,
                PackageEcosystem::Go,
                PackageEcosystem::Hex,
                PackageEcosystem::Maven,
                PackageEcosystem::Npm,
                PackageEcosystem::Nuget,
                PackageEcosystem::Pip,
                PackageEcosystem::Pub,
                PackageEcosystem::Swift,
                PackageEcosystem::Terraform,
            ]
            .into_iter()
            .collect(),
            package_digests: BTreeSet::new(),
        }
    }

    pub fn allows(
        &self,
        state: AlertState,
        severity: Severity,
        ecosystem: PackageEcosystem,
    ) -> bool {
        self.states.contains(&state)
            && self.severities.contains(&severity)
            && self.ecosystems.contains(&ecosystem)
    }

    pub fn allows_package_digest(&self, digest: &Digest) -> bool {
        self.package_digests.is_empty() || self.package_digests.contains(digest)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum GithubDependabotReadOperation {
    ListAlerts,
    GetAlert,
}

impl GithubDependabotReadOperation {
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::ListAlerts => PermissionAction::ListDependabotAlerts,
            Self::GetAlert => PermissionAction::GetDependabotAlert,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotReadRequest {
    pub operation: GithubDependabotReadOperation,
    pub repository: GithubRepository,
    pub ref_name: RefName,
    pub commit_sha: CommitSha,
    pub alert_number: Option<AlertNumber>,
    pub filter: AlertFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_alerts: u16,
    pub max_response_bytes: usize,
    pub max_retries: u8,
    pub cursor: Option<OpaqueCursor>,
    pub etag_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadBinding<'a> {
    operation: GithubDependabotReadOperation,
    repository: &'a GithubRepository,
    ref_name: &'a RefName,
    commit_sha: &'a CommitSha,
    alert_number: Option<AlertNumber>,
    filter: &'a AlertFilter,
    page_size: u16,
    max_pages: u16,
    max_alerts: u16,
    max_response_bytes: usize,
    max_retries: u8,
    etag_digest: &'a Option<Digest>,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
}

impl GithubDependabotReadRequest {
    pub fn list(
        scope: &GithubDependabotScope,
        filter: AlertFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::new(
            GithubDependabotReadOperation::ListAlerts,
            scope,
            None,
            filter,
            page_size,
            max_pages,
            cursor,
        )
    }

    pub fn get(
        scope: &GithubDependabotScope,
        alert_number: AlertNumber,
    ) -> Result<Self, ModelError> {
        Self::new(
            GithubDependabotReadOperation::GetAlert,
            scope,
            Some(alert_number),
            AlertFilter::all(),
            1,
            1,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: GithubDependabotReadOperation,
        scope: &GithubDependabotScope,
        alert_number: Option<AlertNumber>,
        filter: AlertFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "page budget",
            });
        }
        if matches!(operation, GithubDependabotReadOperation::GetAlert) && alert_number.is_none() {
            return Err(ModelError::Invalid {
                field: "get alert number",
            });
        }
        if let Some(number) = alert_number
            && scope.alert_binding(number).is_none()
        {
            return Err(ModelError::ScopeMismatch {
                field: "alert allowlist",
            });
        }
        let request = Self {
            operation,
            repository: scope.repository.clone(),
            ref_name: scope.ref_name.clone(),
            commit_sha: scope.commit_sha.clone(),
            alert_number,
            filter,
            page_size,
            max_pages,
            max_alerts: MAX_ALERTS as u16,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retries: MAX_RETRIES,
            cursor: None,
            etag_digest: None,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
        };
        let mut request = request;
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    fn bind_cursor(
        &self,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Option<OpaqueCursor>, ModelError> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let binding = self.query_digest();
        if let Some(existing) = cursor.binding_digest()
            && existing != &binding
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        Ok(Some(cursor.bind(&binding)))
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self, ModelError> {
        let mut request = self.clone();
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    pub fn with_etag(&self, etag: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = etag.as_ref();
        validate_text(value, "ETag", MAX_CURSOR_BYTES)?;
        let mut request = self.clone();
        request.etag_digest = Some(Digest::from_parts(
            "hartevo-github-dependabot-etag/v1",
            &[value.to_owned()],
        ));
        if request.cursor.is_some() {
            request.cursor = None;
        }
        Ok(request)
    }

    pub fn with_bounds(
        &self,
        max_alerts: u16,
        max_response_bytes: usize,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        if self.cursor.is_some()
            || max_alerts == 0
            || usize::from(max_alerts) > MAX_ALERTS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        let mut request = self.clone();
        request.max_alerts = max_alerts;
        request.max_response_bytes = max_response_bytes;
        request.max_retries = max_retries;
        Ok(request)
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&ReadBinding {
            operation: self.operation,
            repository: &self.repository,
            ref_name: &self.ref_name,
            commit_sha: &self.commit_sha,
            alert_number: self.alert_number,
            filter: &self.filter,
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_alerts: self.max_alerts,
            max_response_bytes: self.max_response_bytes,
            max_retries: self.max_retries,
            etag_digest: &self.etag_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
        })
    }

    pub fn request_digest(&self) -> Digest {
        let cursor_digest = self
            .cursor
            .as_ref()
            .map_or_else(Digest::zero, |cursor| cursor.token_digest().clone());
        Digest::from_parts(
            "hartevo-github-dependabot-read-request/v1",
            &[self.query_digest().to_string(), cursor_digest.to_string()],
        )
    }

    pub fn validate_against(
        &self,
        scope: &GithubDependabotScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest() {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        if self.permission_digest != permission.digest()
            || self.permission_digest != scope.permission_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        if self.repository != scope.repository
            || self.ref_name != scope.ref_name
            || self.commit_sha != scope.commit_sha
        {
            return Err(ModelError::ScopeMismatch {
                field: "repository ref or commit",
            });
        }
        if let Some(number) = self.alert_number
            && scope.alert_binding(number).is_none()
        {
            return Err(ModelError::ScopeMismatch {
                field: "alert allowlist",
            });
        }
        if !permission.allows(self.operation.permission()) {
            return Err(ModelError::ScopeMismatch {
                field: "permission action",
            });
        }
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_alerts == 0
            || usize::from(self.max_alerts) > MAX_ALERTS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        if let Some(cursor) = &self.cursor
            && cursor.binding_digest() != Some(&self.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    AlertBudget,
    ResponseTooLarge,
    CursorReplay,
    CursorBindingMismatch,
    MissingAlert,
    StaleAlertRevision,
    AlertReplay,
    EvidenceOrdering,
    ProviderConflict,
    UnprocessableProviderResponse,
    NotModified,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UnprocessableEntity,
    RateLimited,
    ServerFailure,
    Timeout,
    NotModified,
    BlockedEnvironment,
    MalformedResponse,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("GitHub Dependabot provider returned HTTP 400")]
    InvalidRequest,
    #[error("GitHub Dependabot provider rejected the request")]
    Unauthorized,
    #[error("GitHub Dependabot provider denied the request")]
    Forbidden,
    #[error("GitHub Dependabot repository or alert was not found")]
    NotFound,
    #[error("GitHub Dependabot provider returned a conflict")]
    Conflict,
    #[error("GitHub Dependabot provider rejected the bounded request")]
    UnprocessableEntity,
    #[error("GitHub Dependabot provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("GitHub Dependabot provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("GitHub Dependabot provider timed out")]
    Timeout,
    #[error("GitHub Dependabot provider returned HTTP 304 Not Modified")]
    NotModified,
    #[error("GitHub Dependabot native transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("GitHub Dependabot provider response was malformed")]
    MalformedResponse,
    #[error("GitHub Dependabot provider returned an unknown error")]
    Unknown,
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::UnprocessableEntity => ProviderErrorKind::UnprocessableEntity,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::NotModified => ProviderErrorKind::NotModified,
            Self::BlockedEnvironment => ProviderErrorKind::BlockedEnvironment,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::UnprocessableEntity => Some(422),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::NotModified => Some(304),
            Self::Timeout | Self::BlockedEnvironment | Self::MalformedResponse | Self::Unknown => {
                None
            }
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub const fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind(),
            status_code: self.status_code(),
            retry_after_seconds: self.retry_after_seconds(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependabotEvidenceState {
    Open,
    Fixed,
    Dismissed,
    AutoDismissed,
    InsufficientData,
    Partial,
    AccessLoss,
    ProviderUnknown,
    NotModified,
}

impl DependabotEvidenceState {
    pub const fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::InsufficientData
                | Self::Partial
                | Self::AccessLoss
                | Self::ProviderUnknown
                | Self::NotModified
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependabotAlert {
    pub alert_number: AlertNumber,
    pub alert_revision: AlertRevision,
    pub state: AlertState,
    pub package_ecosystem: PackageEcosystem,
    pub dependency_digest: Digest,
    pub package_digest: Digest,
    pub manifest_digest: Digest,
    pub advisory_identifiers: Vec<AdvisoryIdentifier>,
    pub severity: Severity,
    pub cvss_score_basis_points: Option<u16>,
    pub epss_score_basis_points: Option<u16>,
    pub first_detected_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub alert_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AlertBody<'a> {
    alert_number: AlertNumber,
    alert_revision: AlertRevision,
    state: AlertState,
    package_ecosystem: PackageEcosystem,
    dependency_digest: &'a Digest,
    package_digest: &'a Digest,
    manifest_digest: &'a Digest,
    advisory_identifiers: &'a [AdvisoryIdentifier],
    severity: Severity,
    cvss_score_basis_points: Option<u16>,
    epss_score_basis_points: Option<u16>,
    first_detected_at: &'a DateTime<Utc>,
    updated_at: &'a DateTime<Utc>,
}

impl DependabotAlert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alert_number: AlertNumber,
        alert_revision: AlertRevision,
        state: AlertState,
        package_ecosystem: PackageEcosystem,
        package_name: impl AsRef<str>,
        manifest_path: impl AsRef<str>,
        advisory_identifiers: impl IntoIterator<Item = AdvisoryIdentifier>,
        severity: Severity,
        cvss_score_basis_points: Option<u16>,
        epss_score_basis_points: Option<u16>,
        first_detected_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let package = PackageName::new(package_name)?;
        let manifest = ManifestPath::new(manifest_path)?;
        Self::from_digests(
            alert_number,
            alert_revision,
            state,
            package_ecosystem,
            package.digest().clone(),
            manifest.digest().clone(),
            advisory_identifiers,
            severity,
            cvss_score_basis_points,
            epss_score_basis_points,
            first_detected_at,
            updated_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_digests(
        alert_number: AlertNumber,
        alert_revision: AlertRevision,
        state: AlertState,
        package_ecosystem: PackageEcosystem,
        package_digest: Digest,
        manifest_digest: Digest,
        advisory_identifiers: impl IntoIterator<Item = AdvisoryIdentifier>,
        severity: Severity,
        cvss_score_basis_points: Option<u16>,
        epss_score_basis_points: Option<u16>,
        first_detected_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let advisory_identifiers = advisory_identifiers.into_iter().collect::<Vec<_>>();
        if advisory_identifiers.len() > MAX_ADVISORY_IDENTIFIERS {
            return Err(ModelError::TooMany {
                field: "advisory identifiers",
            });
        }
        if package_digest == Digest::zero() || manifest_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "Dependabot package or manifest digest",
            });
        }
        if cvss_score_basis_points.is_some_and(|score| score > 1_000)
            || epss_score_basis_points.is_some_and(|score| score > 10_000)
        {
            return Err(ModelError::Invalid {
                field: "risk score",
            });
        }
        if updated_at < first_detected_at {
            return Err(ModelError::Invalid {
                field: "alert timestamp ordering",
            });
        }
        let dependency_digest = Digest::from_parts(
            "hartevo-github-dependabot-dependency/v1",
            &[
                format!("{package_ecosystem:?}"),
                package_digest.to_string(),
                manifest_digest.to_string(),
            ],
        );
        let mut alert = Self {
            alert_number,
            alert_revision,
            state,
            package_ecosystem,
            dependency_digest,
            package_digest,
            manifest_digest,
            advisory_identifiers,
            severity,
            cvss_score_basis_points,
            epss_score_basis_points,
            first_detected_at,
            updated_at,
            alert_digest: Digest::zero(),
        };
        alert.alert_digest = alert.recomputed_digest();
        Ok(alert)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&AlertBody {
            alert_number: self.alert_number,
            alert_revision: self.alert_revision,
            state: self.state,
            package_ecosystem: self.package_ecosystem.clone(),
            dependency_digest: &self.dependency_digest,
            package_digest: &self.package_digest,
            manifest_digest: &self.manifest_digest,
            advisory_identifiers: &self.advisory_identifiers,
            severity: self.severity,
            cvss_score_basis_points: self.cvss_score_basis_points,
            epss_score_basis_points: self.epss_score_basis_points,
            first_detected_at: &self.first_detected_at,
            updated_at: &self.updated_at,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.package_digest == Digest::zero()
            || self.manifest_digest == Digest::zero()
            || self.dependency_digest == Digest::zero()
            || self.advisory_identifiers.len() > MAX_ADVISORY_IDENTIFIERS
            || self
                .cvss_score_basis_points
                .is_some_and(|score| score > 1_000)
            || self
                .epss_score_basis_points
                .is_some_and(|score| score > 10_000)
            || self.updated_at < self.first_detected_at
            || self.alert_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Dependabot alert digest or bounds",
            });
        }
        Ok(())
    }

    pub fn matches_filter(&self, filter: &AlertFilter) -> bool {
        filter.allows(self.state, self.severity, self.package_ecosystem.clone())
            && filter.allows_package_digest(&self.package_digest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotReadPage {
    pub operation: GithubDependabotReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub alerts: Vec<DependabotAlert>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub etag_digest: Option<Digest>,
    pub not_modified: bool,
    pub page_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadPageBody<'a> {
    operation: GithubDependabotReadOperation,
    query_digest: &'a Digest,
    page_number: u16,
    alerts: &'a [DependabotAlert],
    next_cursor: &'a Option<OpaqueCursor>,
    response_bytes: usize,
    provider_revision: &'a ProviderRevision,
    etag_digest: &'a Option<Digest>,
    not_modified: bool,
}

impl GithubDependabotReadPage {
    pub fn new(
        request: &GithubDependabotReadRequest,
        page_number: u16,
        alerts: Vec<DependabotAlert>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new_with_headers(
            request,
            page_number,
            alerts,
            next_cursor,
            response_bytes,
            provider_revision,
            None,
            false,
        )
    }

    pub fn not_modified(
        request: &GithubDependabotReadRequest,
        page_number: u16,
        etag_digest: Option<Digest>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new_with_headers(
            request,
            page_number,
            Vec::new(),
            None,
            1,
            provider_revision,
            etag_digest,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_headers(
        request: &GithubDependabotReadRequest,
        page_number: u16,
        alerts: Vec<DependabotAlert>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
        etag_digest: Option<Digest>,
        not_modified: bool,
    ) -> Result<Self, ModelError> {
        if page_number == 0 {
            return Err(ModelError::Invalid {
                field: "page number",
            });
        }
        if alerts.len() > MAX_ALERTS_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "alerts per page",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "provider response bytes",
            });
        }
        if not_modified && (!alerts.is_empty() || next_cursor.is_some()) {
            return Err(ModelError::Invalid {
                field: "304 page payload",
            });
        }
        for alert in &alerts {
            alert.validate()?;
        }
        let query_digest = request.query_digest();
        let next_cursor = next_cursor
            .map(|cursor| {
                if let Some(existing) = cursor.binding_digest()
                    && existing != &query_digest
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "next cursor query binding",
                    });
                }
                Ok(cursor.bind(&query_digest))
            })
            .transpose()?;
        let mut page = Self {
            operation: request.operation,
            query_digest,
            page_number,
            alerts,
            next_cursor,
            response_bytes,
            provider_revision,
            etag_digest,
            not_modified,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ReadPageBody {
            operation: self.operation,
            query_digest: &self.query_digest,
            page_number: self.page_number,
            alerts: &self.alerts,
            next_cursor: &self.next_cursor,
            response_bytes: self.response_bytes,
            provider_revision: &self.provider_revision,
            etag_digest: &self.etag_digest,
            not_modified: self.not_modified,
        })
    }

    pub fn validate_for(&self, request: &GithubDependabotReadRequest) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.alerts.len() > MAX_ALERTS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
            || (self.not_modified && (!self.alerts.is_empty() || self.next_cursor.is_some()))
        {
            return Err(ModelError::Invalid {
                field: "GitHub Dependabot page binding",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && cursor.binding_digest() != Some(&request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "next cursor query binding",
            });
        }
        for alert in &self.alerts {
            alert.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotEvidence {
    pub state: DependabotEvidenceState,
    pub alerts: Vec<DependabotAlert>,
    pub partial_reason: Option<PartialReason>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub truncated: bool,
    pub not_modified: bool,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub etag_digest: Option<Digest>,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    state: DependabotEvidenceState,
    alerts: &'a [DependabotAlert],
    partial_reason: Option<PartialReason>,
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    truncated: bool,
    not_modified: bool,
    query_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    repository_digest: &'a Digest,
    ref_digest: &'a Digest,
    commit_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_errors: &'a [ProviderErrorEvidence],
    etag_digest: &'a Option<Digest>,
    provenance: TransportProvenance,
}

impl GithubDependabotEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: DependabotEvidenceState,
        alerts: Vec<DependabotAlert>,
        partial_reason: Option<PartialReason>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        not_modified: bool,
        query_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        repository_digest: Digest,
        ref_digest: Digest,
        commit_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        api_digest: Digest,
        contract_digest: Digest,
        provider_errors: Vec<ProviderErrorEvidence>,
        etag_digest: Option<Digest>,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if alerts.len() > MAX_ALERTS
            || provider_errors.len() > MAX_PROVIDER_ERRORS
            || query_digest == Digest::zero()
            || scope_digest == Digest::zero()
            || permission_digest == Digest::zero()
            || provider_digest == Digest::zero()
            || api_digest == Digest::zero()
            || contract_digest == Digest::zero()
        {
            return Err(ModelError::Invalid {
                field: "Dependabot evidence bounds or digest",
            });
        }
        for alert in &alerts {
            alert.validate()?;
        }
        let mut evidence = Self {
            state,
            alerts,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            not_modified,
            query_digest,
            scope_digest,
            permission_digest,
            repository_digest,
            ref_digest,
            commit_digest,
            provider_digest,
            provider_revision,
            api_digest,
            contract_digest,
            provider_errors,
            etag_digest,
            provenance,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        Ok(evidence)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            state: self.state,
            alerts: &self.alerts,
            partial_reason: self.partial_reason,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            truncated: self.truncated,
            not_modified: self.not_modified,
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            repository_digest: &self.repository_digest,
            ref_digest: &self.ref_digest,
            commit_digest: &self.commit_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            provider_errors: &self.provider_errors,
            etag_digest: &self.etag_digest,
            provenance: self.provenance,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.alerts.len() > MAX_ALERTS
            || self.provider_errors.len() > MAX_PROVIDER_ERRORS
            || self.query_digest == Digest::zero()
            || self.scope_digest == Digest::zero()
            || self.permission_digest == Digest::zero()
            || self.provider_digest == Digest::zero()
            || self.api_digest == Digest::zero()
            || self.contract_digest == Digest::zero()
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Dependabot evidence digest or bounds",
            });
        }
        for alert in &self.alerts {
            alert.validate()?;
        }
        Ok(())
    }

    pub fn open_alert_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|alert| alert.state == AlertState::Open)
            .count()
    }

    pub fn alert_digests(&self) -> BTreeMap<AlertNumber, Digest> {
        self.alerts
            .iter()
            .map(|alert| (alert.alert_number, alert.alert_digest.clone()))
            .collect()
    }
}
