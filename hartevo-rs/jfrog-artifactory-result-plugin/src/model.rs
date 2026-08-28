//! Typed JFrog identities, exact Mission scope, checksums, build-info, and
//! allowlisted metadata projections.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    JfrogArtifactoryResultError, MAX_AQL_RESULTS, MAX_ARTIFACTS, MAX_IDENTIFIER_BYTES, MAX_MODULES,
    MAX_PAGE_SIZE, MAX_PATH_BYTES, MAX_PROPERTIES, Result, digest_serialized, validate_digest,
    validate_identifier, validate_text,
};

/// A SHA-256 digest used as a binding, request, tamper, or redaction fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(crate::sha256_hex(value.as_ref()))
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 32);
        canonical.push_str(label);
        for (name, value) in values {
            canonical.push('|');
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest(&self.0, "digest")
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

macro_rules! define_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
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

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

define_identifier!(RegistrationId, "registrationId");
define_identifier!(MissionId, "missionId");
define_identifier!(ProjectId, "projectId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(OrganizationId, "organizationId");
define_identifier!(RepositoryKey, "repositoryKey");
define_identifier!(BuildName, "buildName");
define_identifier!(BuildNumber, "buildNumber");
define_identifier!(ModuleName, "moduleName");
define_identifier!(ArtifactName, "artifactName");

/// A source revision is retained only as a normalized commit identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !(40..=64).contains(&value.len())
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(JfrogArtifactoryResultError::InvalidIdentifier { field: "commitSha" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Semantic version bound into a registration, independent of crate version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('.');
        let parsed = [parts.next(), parts.next(), parts.next()];
        if parts.next().is_some() || parsed.iter().any(Option::is_none) {
            return Err(JfrogArtifactoryResultError::InvalidIdentifier {
                field: "pluginVersion",
            });
        }
        let mut numbers = [0_u16; 3];
        for (index, part) in parsed.into_iter().enumerate() {
            numbers[index] = part
                .expect("checked version part")
                .parse::<u16>()
                .map_err(|_| JfrogArtifactoryResultError::InvalidIdentifier {
                    field: "pluginVersion",
                })?;
        }
        Ok(Self {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The only credential kinds accepted by this Layer-1 boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
    Oidc,
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiToken => "api_token",
            Self::Oidc => "oidc",
        }
    }
}

/// An opaque host-owned API-token or OIDC handle. The opaque identifier is
/// hashed immediately and is never serialized or exposed in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::ApiToken, opaque_id, revision)
    }

    pub fn oidc(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::Oidc, opaque_id, revision)
    }

    pub fn new(kind: SecretKind, opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secretReference", MAX_IDENTIFIER_BYTES, false)?;
        if revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_parts(
                "jfrog-opaque-secret-reference/v1",
                &[
                    ("kind", kind.as_str().to_owned()),
                    ("opaque_id", opaque_id),
                    ("revision", revision.to_string()),
                ],
            ),
            revision,
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()?;
        if self.revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

fn normalize_https_origin(value: &str) -> Result<String> {
    let candidate = value.strip_suffix('/').unwrap_or(value);
    let remainder = candidate
        .strip_prefix("https://")
        .ok_or(JfrogArtifactoryResultError::InvalidHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains('@')
        || remainder.contains(':')
        || remainder.chars().any(char::is_whitespace)
    {
        return Err(JfrogArtifactoryResultError::InvalidHost);
    }
    let host = remainder.to_ascii_lowercase();
    if host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(JfrogArtifactoryResultError::InvalidHost);
    }
    Ok(format!("https://{host}"))
}

/// The exact HTTPS origin bound to a registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentity {
    pub https_origin: String,
    pub revision: u64,
}

impl HostIdentity {
    pub fn new(https_origin: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(Self {
            https_origin: normalize_https_origin(&https_origin.into())?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if Self::new(self.https_origin.clone(), self.revision)? == *self {
            Ok(())
        } else {
            Err(JfrogArtifactoryResultError::InvalidHost)
        }
    }

    pub fn host(&self) -> &str {
        &self.https_origin
    }
}

macro_rules! define_revisioned_identity {
    ($name:ident, $id:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(JfrogArtifactoryResultError::InvalidScope);
                }
                Ok(Self {
                    id: $id::new(id)?,
                    revision,
                })
            }

            pub fn validate(&self) -> Result<()> {
                self.id.validate()?;
                if self.revision == 0 {
                    return Err(JfrogArtifactoryResultError::InvalidScope);
                }
                Ok(())
            }

            pub fn id(&self) -> &str {
                self.id.as_str()
            }
        }
    };
}

define_revisioned_identity!(MissionIdentity, MissionId, "mission");
define_revisioned_identity!(ProjectIdentity, ProjectId, "project");
define_revisioned_identity!(WorkProductIdentity, WorkProductId, "workProduct");
define_revisioned_identity!(OrganizationIdentity, OrganizationId, "organization");
define_revisioned_identity!(RepositoryIdentity, RepositoryKey, "repository");
define_revisioned_identity!(ModuleIdentity, ModuleName, "module");
define_revisioned_identity!(ArtifactIdentity, ArtifactName, "artifact");

/// An Artifactory repository path with traversal and query syntax refused.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactPath(String);

impl ArtifactPath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "artifactPath", MAX_PATH_BYTES, false)?;
        if value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.contains('?')
            || value.contains('#')
            || value.contains('%')
            || value
                .split('/')
                .any(|segment| segment == "." || segment == "..")
            || value.split('/').any(str::is_empty)
        {
            return Err(JfrogArtifactoryResultError::PathTraversalRefused);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for ArtifactPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A repository path identity includes a revision so replacement or rebind
/// cannot silently change the release objective.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPathIdentity {
    pub path: ArtifactPath,
    pub revision: u64,
}

impl ArtifactPathIdentity {
    pub fn new(path: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(Self {
            path: ArtifactPath::new(path)?,
            revision,
        })
    }

    pub fn as_str(&self) -> &str {
        self.path.as_str()
    }

    pub fn validate(&self) -> Result<()> {
        self.path.validate()?;
        if self.revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(())
    }
}

/// A build name/number pair and the provider-side build-info revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildIdentity {
    pub name: BuildName,
    pub number: BuildNumber,
    pub revision: u64,
}

impl BuildIdentity {
    pub fn new(name: impl Into<String>, number: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(Self {
            name: BuildName::new(name)?,
            number: BuildNumber::new(number)?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.name.validate()?;
        self.number.validate()?;
        if self.revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn number(&self) -> &str {
        self.number.as_str()
    }
}

/// The source revision identity bound to build-info and artifact metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitIdentity {
    pub sha: CommitSha,
    pub revision: u64,
}

impl CommitIdentity {
    pub fn new(sha: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(Self {
            sha: CommitSha::new(sha)?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.sha.validate()?;
        if self.revision == 0 {
            return Err(JfrogArtifactoryResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn sha(&self) -> &str {
        self.sha.as_str()
    }
}

/// The complete cross-authority fence for a JFrog release evidence read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JfrogScope {
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub repository: RepositoryIdentity,
    pub artifact_path: ArtifactPathIdentity,
    pub build: BuildIdentity,
    pub module: ModuleIdentity,
    pub artifact: ArtifactIdentity,
    pub commit: CommitIdentity,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
}

impl JfrogScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: HostIdentity,
        organization: OrganizationIdentity,
        repository: RepositoryIdentity,
        artifact_path: ArtifactPathIdentity,
        build: BuildIdentity,
        module: ModuleIdentity,
        artifact: ArtifactIdentity,
        commit: CommitIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            host,
            organization,
            repository,
            artifact_path,
            build,
            module,
            artifact,
            commit,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.repository.validate()?;
        self.artifact_path.validate()?;
        self.build.validate()?;
        self.module.validate()?;
        self.artifact.validate()?;
        self.commit.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

pub type JfrogArtifactoryScope = JfrogScope;

/// A checksum value is exact hexadecimal metadata, never artifact content.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Checksum(String);

impl Checksum {
    fn new_for_algorithm(value: impl Into<String>, expected_len: usize) -> Result<Self> {
        let value = value.into();
        if value.len() != expected_len
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(JfrogArtifactoryResultError::InvalidIdentifier { field: "checksum" });
        }
        Ok(Self(value))
    }

    pub fn sha256(value: impl Into<String>) -> Result<Self> {
        Self::new_for_algorithm(value, 64)
    }

    pub fn sha1(value: impl Into<String>) -> Result<Self> {
        Self::new_for_algorithm(value, 40)
    }

    pub fn md5(value: impl Into<String>) -> Result<Self> {
        Self::new_for_algorithm(value, 32)
    }

    pub fn from_digest(digest: &Digest) -> Result<Self> {
        Self::sha256(digest.as_str().to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The provider checksum tuple. It carries no bytes and is independently
/// digestible for comparison and proposal fencing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactChecksums {
    pub sha256: Checksum,
    pub sha1: Option<Checksum>,
    pub md5: Option<Checksum>,
}

impl ArtifactChecksums {
    pub fn new(
        sha256: impl Into<String>,
        sha1: Option<String>,
        md5: Option<String>,
    ) -> Result<Self> {
        let checksums = Self {
            sha256: Checksum::sha256(sha256)?,
            sha1: sha1.map(Checksum::sha1).transpose()?,
            md5: md5.map(Checksum::md5).transpose()?,
        };
        checksums.validate()?;
        Ok(checksums)
    }

    pub fn from_sha256_digest(digest: Digest) -> Result<Self> {
        let Digest(value) = digest;
        Self {
            sha256: Checksum::sha256(value)?,
            sha1: None,
            md5: None,
        }
        .tap_validate()
    }

    fn tap_validate(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.sha256.as_str().len() != 64
            || self
                .sha256
                .as_str()
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            || self
                .sha1
                .as_ref()
                .is_some_and(|value| value.as_str().len() != 40)
            || self
                .md5
                .as_ref()
                .is_some_and(|value| value.as_str().len() != 32)
        {
            return Err(JfrogArtifactoryResultError::InvalidIdentifier { field: "checksum" });
        }
        Ok(())
    }
}

impl AsRef<ArtifactChecksums> for ArtifactChecksums {
    fn as_ref(&self) -> &ArtifactChecksums {
        self
    }
}

/// A property is represented by its key and a digest of its value. This keeps
/// arbitrary provider values bounded and prevents accidental secret retention.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PropertyEvidence {
    pub key: String,
    pub value_digest: Digest,
}

impl PropertyEvidence {
    pub fn new(key: impl Into<String>, value: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.into();
        validate_property_key(&key)?;
        Ok(Self {
            key,
            value_digest: Digest::from_text(value),
        })
    }

    pub fn from_digest(key: impl Into<String>, value_digest: Digest) -> Result<Self> {
        let key = key.into();
        validate_property_key(&key)?;
        value_digest.validate()?;
        Ok(Self { key, value_digest })
    }

    pub fn validate(&self) -> Result<()> {
        validate_property_key(&self.key)?;
        self.value_digest.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

fn validate_property_key(key: &str) -> Result<()> {
    validate_text(key, "propertyKey", MAX_IDENTIFIER_BYTES, false)?;
    let lower = key.to_ascii_lowercase();
    if [
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "private",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        return Err(JfrogArtifactoryResultError::InvalidText {
            field: "sensitivePropertyKey",
        });
    }
    Ok(())
}

/// Values intentionally describe state; they are never commands to promote
/// or reject anything in Artifactory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionState {
    NotPromoted,
    Promoted,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromotionEvidence {
    pub state: PromotionState,
    pub build: BuildIdentity,
    pub source_repository: RepositoryIdentity,
    pub target_repository: Option<RepositoryIdentity>,
    pub properties: Vec<PropertyEvidence>,
    pub promotion_revision: u64,
    pub promotion_digest: Digest,
}

impl PromotionEvidence {
    pub fn new(
        scope: &JfrogScope,
        state: PromotionState,
        target_repository: Option<RepositoryIdentity>,
        properties: Vec<PropertyEvidence>,
        promotion_revision: u64,
    ) -> Result<Self> {
        let mut evidence = Self {
            state,
            build: scope.build.clone(),
            source_repository: scope.repository.clone(),
            target_repository,
            properties,
            promotion_revision,
            promotion_digest: Digest::from_text("unsealed-jfrog-promotion"),
        };
        evidence.promotion_digest = evidence.calculate_digest();
        evidence.validate_for_scope(scope)?;
        Ok(evidence)
    }

    pub fn validate_for_scope(&self, scope: &JfrogScope) -> Result<()> {
        self.build.validate()?;
        self.source_repository.validate()?;
        if self.build != scope.build || self.source_repository != scope.repository {
            return Err(JfrogArtifactoryResultError::PromotionMismatch);
        }
        if let Some(target) = &self.target_repository {
            target.validate()?;
        }
        if self.promotion_revision == 0 || self.properties.len() > MAX_PROPERTIES {
            return Err(JfrogArtifactoryResultError::EvidenceLimit);
        }
        for property in &self.properties {
            property.validate()?;
        }
        if self.promotion_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            self.state,
            &self.build,
            &self.source_repository,
            &self.target_repository,
            &self.properties,
            self.promotion_revision,
        ))
    }
}

/// Build-info module metadata is bounded and contains only typed artifact
/// metadata, checksums, properties, and source revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleEvidence {
    pub module: ModuleIdentity,
    pub artifacts: Vec<ArtifactMetadata>,
    pub properties: Vec<PropertyEvidence>,
    pub module_digest: Digest,
}

impl ModuleEvidence {
    pub fn for_scope(
        scope: &JfrogScope,
        artifact: ArtifactMetadata,
        properties: Vec<PropertyEvidence>,
    ) -> Result<Self> {
        let mut evidence = Self {
            module: scope.module.clone(),
            artifacts: vec![artifact],
            properties,
            module_digest: Digest::from_text("unsealed-jfrog-module"),
        };
        evidence.module_digest = evidence.calculate_digest();
        evidence.validate_for_scope(scope)?;
        Ok(evidence)
    }

    pub fn validate_for_scope(&self, scope: &JfrogScope) -> Result<()> {
        self.module.validate()?;
        if self.module != scope.module
            || self.artifacts.len() > MAX_ARTIFACTS
            || self.properties.len() > MAX_PROPERTIES
        {
            return Err(JfrogArtifactoryResultError::EvidenceLimit);
        }
        for artifact in &self.artifacts {
            artifact.validate_for_scope(scope)?;
        }
        for property in &self.properties {
            property.validate()?;
        }
        if self.module_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(&self.module, &self.artifacts, &self.properties))
    }
}

/// Bounded artifact metadata. It deliberately has no byte payload, download
/// URL, raw provider JSON, or log field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub repository: RepositoryIdentity,
    pub artifact_path: ArtifactPathIdentity,
    pub build: BuildIdentity,
    pub module: ModuleIdentity,
    pub artifact: ArtifactIdentity,
    pub source_revision: CommitIdentity,
    pub checksums: ArtifactChecksums,
    pub properties: Vec<PropertyEvidence>,
    pub metadata_digest: Digest,
}

impl ArtifactMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: RepositoryIdentity,
        artifact_path: ArtifactPathIdentity,
        build: BuildIdentity,
        module: ModuleIdentity,
        artifact: ArtifactIdentity,
        source_revision: CommitIdentity,
        checksums: ArtifactChecksums,
        properties: Vec<PropertyEvidence>,
    ) -> Result<Self> {
        let mut metadata = Self {
            repository,
            artifact_path,
            build,
            module,
            artifact,
            source_revision,
            checksums,
            properties,
            metadata_digest: Digest::from_text("unsealed-jfrog-artifact-metadata"),
        };
        metadata.metadata_digest = metadata.calculate_digest();
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn for_scope(
        scope: &JfrogScope,
        checksums: ArtifactChecksums,
        properties: Vec<PropertyEvidence>,
    ) -> Result<Self> {
        Self::new(
            scope.repository.clone(),
            scope.artifact_path.clone(),
            scope.build.clone(),
            scope.module.clone(),
            scope.artifact.clone(),
            scope.commit.clone(),
            checksums,
            properties,
        )
    }

    pub fn validate_for_scope(&self, scope: &JfrogScope) -> Result<()> {
        self.validate()?;
        if self.repository != scope.repository
            || self.artifact_path != scope.artifact_path
            || self.build != scope.build
            || self.module != scope.module
            || self.artifact != scope.artifact
            || self.source_revision != scope.commit
        {
            return Err(JfrogArtifactoryResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.repository.validate()?;
        self.artifact_path.validate()?;
        self.build.validate()?;
        self.module.validate()?;
        self.artifact.validate()?;
        self.source_revision.validate()?;
        self.checksums.validate()?;
        if self.properties.len() > MAX_PROPERTIES {
            return Err(JfrogArtifactoryResultError::EvidenceLimit);
        }
        let mut keys = BTreeSet::new();
        for property in &self.properties {
            property.validate()?;
            if !keys.insert(&property.key) {
                return Err(JfrogArtifactoryResultError::DuplicateEvidence);
            }
        }
        if self.metadata_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::MetadataMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.repository,
            &self.artifact_path,
            &self.build,
            &self.module,
            &self.artifact,
            &self.source_revision,
            &self.checksums,
            &self.properties,
        ))
    }
}

/// Bounded build-info evidence, including the exact build and source revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildInfoEvidence {
    pub build: BuildIdentity,
    pub source_revision: CommitIdentity,
    pub modules: Vec<ModuleEvidence>,
    pub properties: Vec<PropertyEvidence>,
    pub build_info_digest: Digest,
}

impl BuildInfoEvidence {
    pub fn new(
        build: BuildIdentity,
        source_revision: CommitIdentity,
        modules: Vec<ModuleEvidence>,
        properties: Vec<PropertyEvidence>,
    ) -> Result<Self> {
        let mut build_info = Self {
            build,
            source_revision,
            modules,
            properties,
            build_info_digest: Digest::from_text("unsealed-jfrog-build-info"),
        };
        build_info.build_info_digest = build_info.calculate_digest();
        build_info.validate()?;
        Ok(build_info)
    }

    pub fn for_scope(
        scope: &JfrogScope,
        artifact: ArtifactMetadata,
        properties: Vec<PropertyEvidence>,
    ) -> Result<Self> {
        let module = ModuleEvidence::for_scope(scope, artifact, Vec::new())?;
        Self::new(
            scope.build.clone(),
            scope.commit.clone(),
            vec![module],
            properties,
        )
    }

    pub fn validate_for_scope(&self, scope: &JfrogScope) -> Result<()> {
        self.validate()?;
        if self.build != scope.build || self.source_revision != scope.commit {
            return Err(JfrogArtifactoryResultError::BuildInfoRevisionMismatch);
        }
        for module in &self.modules {
            module.validate_for_scope(scope)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.build.validate()?;
        self.source_revision.validate()?;
        if self.modules.len() > MAX_MODULES || self.properties.len() > MAX_PROPERTIES {
            return Err(JfrogArtifactoryResultError::EvidenceLimit);
        }
        for module in &self.modules {
            module.module.validate()?;
            if module.artifacts.len() > MAX_ARTIFACTS {
                return Err(JfrogArtifactoryResultError::EvidenceLimit);
            }
            for artifact in &module.artifacts {
                artifact.validate()?;
            }
        }
        for property in &self.properties {
            property.validate()?;
        }
        if self.build_info_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.build,
            &self.source_revision,
            &self.modules,
            &self.properties,
        ))
    }
}

/// Only descriptive status is exposed by the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Present,
    Missing,
    Promoted,
    Rejected,
    Partial,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
    Truncated,
}

/// All Layer-1 transports are intentionally non-native and non-connected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn claims_connected(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

pub type ProviderProvenance = TransportProvenance;

/// AQL is constructed from exact scope values and has no arbitrary query
/// string input. It represents item metadata only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AqlMetadataQuery {
    pub scope: JfrogScope,
    pub page_size: usize,
    pub offset: usize,
    pub query_digest: Digest,
}

impl AqlMetadataQuery {
    pub fn new(scope: JfrogScope, page_size: usize, offset: usize) -> Result<Self> {
        let mut query = Self {
            scope,
            page_size,
            offset,
            query_digest: Digest::from_text("unsealed-jfrog-aql-query"),
        };
        query.query_digest = query.calculate_digest();
        query.validate()?;
        Ok(query)
    }

    pub fn for_scope(scope: &JfrogScope, page_size: usize, offset: usize) -> Result<Self> {
        Self::new(scope.clone(), page_size, offset)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(JfrogArtifactoryResultError::AqlNotAllowlisted);
        }
        if self.offset > MAX_AQL_RESULTS.saturating_mul(MAX_PAGE_SIZE) {
            return Err(JfrogArtifactoryResultError::EvidenceLimit);
        }
        if self.query_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    /// The generated query contains only exact repo/path/name filters and an
    /// allowlisted metadata field list. It is not accepted as provider input.
    pub fn query_text(&self) -> String {
        format!(
            "items.find({{\"repo\":\"{}\",\"path\":\"{}\",\"name\":\"{}\"}}).include(\"repo\",\"path\",\"name\",\"type\",\"size\",\"sha1\",\"sha256\",\"md5\",\"created\",\"modified\",\"property.key\",\"property.value\").sort({{\"$asc\":[\"repo\",\"path\",\"name\"]}}).offset({}).limit({})",
            escape_aql(self.scope.repository.id()),
            escape_aql(self.scope.artifact_path.as_str()),
            escape_aql(self.scope.artifact.id()),
            self.offset,
            self.page_size,
        )
    }

    pub fn is_allowlisted(&self) -> bool {
        self.validate().is_ok()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope,
            self.page_size,
            self.offset,
            "items",
            [
                "repo",
                "path",
                "name",
                "type",
                "size",
                "sha1",
                "sha256",
                "md5",
                "created",
                "modified",
                "property.key",
                "property.value",
            ],
        ))
    }
}

fn escape_aql(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AqlRange {
    pub start_index: usize,
    pub end_index: usize,
    pub total_matches: usize,
}

impl AqlRange {
    pub fn new(start_index: usize, end_index: usize, total_matches: usize) -> Result<Self> {
        let range = Self {
            start_index,
            end_index,
            total_matches,
        };
        range.validate()?;
        Ok(range)
    }

    pub fn validate(&self) -> Result<()> {
        if self.start_index > self.end_index
            || self.end_index > self.total_matches
            || self.total_matches > MAX_AQL_RESULTS
        {
            return Err(JfrogArtifactoryResultError::EvidenceLimit);
        }
        Ok(())
    }
}

/// One AQL item result with only allowlisted metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AqlMetadataRecord {
    pub repository: RepositoryIdentity,
    pub artifact_path: ArtifactPathIdentity,
    pub artifact: ArtifactIdentity,
    pub artifact_type: String,
    pub size: Option<u64>,
    pub checksums: ArtifactChecksums,
    pub properties: Vec<PropertyEvidence>,
    pub metadata_digest: Digest,
}

impl AqlMetadataRecord {
    pub fn for_scope(
        scope: &JfrogScope,
        checksums: ArtifactChecksums,
        properties: Vec<PropertyEvidence>,
        size: Option<u64>,
    ) -> Result<Self> {
        Self::new(
            scope.repository.clone(),
            scope.artifact_path.clone(),
            scope.artifact.clone(),
            "file".to_owned(),
            size,
            checksums,
            properties,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: RepositoryIdentity,
        artifact_path: ArtifactPathIdentity,
        artifact: ArtifactIdentity,
        artifact_type: String,
        size: Option<u64>,
        checksums: ArtifactChecksums,
        properties: Vec<PropertyEvidence>,
    ) -> Result<Self> {
        validate_text(&artifact_type, "artifactType", 32, false)?;
        if artifact_type != "file" {
            return Err(JfrogArtifactoryResultError::AqlNotAllowlisted);
        }
        let mut record = Self {
            repository,
            artifact_path,
            artifact,
            artifact_type,
            size,
            checksums,
            properties,
            metadata_digest: Digest::from_text("unsealed-jfrog-aql-record"),
        };
        record.metadata_digest = record.calculate_digest();
        record.validate()?;
        Ok(record)
    }

    pub fn validate_for_scope(&self, scope: &JfrogScope) -> Result<()> {
        self.validate()?;
        if self.repository != scope.repository
            || self.artifact_path != scope.artifact_path
            || self.artifact != scope.artifact
        {
            return Err(JfrogArtifactoryResultError::AqlOutOfScope);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.repository.validate()?;
        self.artifact_path.validate()?;
        self.artifact.validate()?;
        if self.artifact_type != "file" || self.properties.len() > MAX_PROPERTIES {
            return Err(JfrogArtifactoryResultError::AqlNotAllowlisted);
        }
        self.checksums.validate()?;
        let mut keys = BTreeSet::new();
        for property in &self.properties {
            property.validate()?;
            if !keys.insert(&property.key) {
                return Err(JfrogArtifactoryResultError::DuplicateEvidence);
            }
        }
        if self.metadata_digest != self.calculate_digest() {
            return Err(JfrogArtifactoryResultError::MetadataMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.repository,
            &self.artifact_path,
            &self.artifact,
            &self.artifact_type,
            self.size,
            &self.checksums,
            &self.properties,
        ))
    }
}

/// An explicit read-only permission allowlist. Unknown or mutating permission
/// names are rejected at registration time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<String>,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut snapshot = Self {
            permissions: permissions.into_iter().map(Into::into).collect(),
            permission_digest: Digest::from_text("unsealed-jfrog-permissions"),
        };
        snapshot.permission_digest = snapshot.calculate_digest();
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_only() -> Self {
        Self::new([
            "host.read",
            "organization.read",
            "repository.read",
            "artifact.path.read",
            "artifact.metadata.read",
            "build.read",
            "build.module.read",
            "commit.read",
            "promotion.read",
            "aql.metadata.query",
            "mission.scope",
        ])
        .expect("static read-only permission snapshot")
    }

    pub fn contains(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<()> {
        const ALLOWED: &[&str] = &[
            "host.read",
            "organization.read",
            "repository.read",
            "artifact.path.read",
            "artifact.metadata.read",
            "build.read",
            "build.module.read",
            "commit.read",
            "promotion.read",
            "aql.metadata.query",
            "mission.scope",
        ];
        if self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !ALLOWED.contains(&permission.as_str()))
            || self.permission_digest != self.calculate_digest()
        {
            return Err(JfrogArtifactoryResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&self.permissions)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> JfrogScope {
        JfrogScope::new(
            HostIdentity::new("https://artifactory.example.com", 1).unwrap(),
            OrganizationIdentity::new("acme", 1).unwrap(),
            RepositoryIdentity::new("release-local", 1).unwrap(),
            ArtifactPathIdentity::new("com/acme/app/1.0.0/app.tgz", 1).unwrap(),
            BuildIdentity::new("release", "42", 3).unwrap(),
            ModuleIdentity::new("app", 1).unwrap(),
            ArtifactIdentity::new("app.tgz", 1).unwrap(),
            CommitIdentity::new("0123456789abcdef0123456789abcdef01234567", 7).unwrap(),
            MissionIdentity::new("mission-1", 9).unwrap(),
            ProjectIdentity::new("project-1", 4).unwrap(),
            WorkProductIdentity::new("wp-1", 2).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn path_traversal_is_refused() {
        for path in [
            "../app.tgz",
            "a/../app.tgz",
            "a\\b",
            "/absolute",
            "a/%2e%2e/b",
        ] {
            assert!(matches!(
                ArtifactPath::new(path),
                Err(JfrogArtifactoryResultError::PathTraversalRefused)
            ));
        }
    }

    #[test]
    fn scope_aql_is_bounded_and_allowlisted() {
        let query = AqlMetadataQuery::for_scope(&scope(), 10, 0).unwrap();
        assert!(query.is_allowlisted());
        assert!(query.query_text().contains("items.find"));
        assert!(query.query_text().contains(".limit(10)"));
        assert!(!query.query_text().contains("archive"));
    }

    #[test]
    fn secret_debug_has_no_opaque_material() {
        let secret = SecretReference::api_token("opaque-token-material", 1).unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("opaque-token-material"));
        assert!(!debug.contains("token-material"));
    }

    #[test]
    fn checksum_and_metadata_digests_are_separate_fences() {
        let checksums = ArtifactChecksums::from_sha256_digest(Digest::from_text("bytes")).unwrap();
        let metadata = ArtifactMetadata::for_scope(&scope(), checksums, Vec::new()).unwrap();
        assert!(metadata.validate_for_scope(&scope()).is_ok());
        assert_ne!(metadata.metadata_digest, metadata.checksums.digest());
    }
}
