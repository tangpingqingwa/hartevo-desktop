use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AwsCodeArtifactProvenanceError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_DEPENDENCIES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES};

pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_OPAQUE_HANDLE_BYTES: usize = 512;
pub const MAX_DEPENDENCY_ITEM_BYTES: usize = 512;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidDigest)
        }
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

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
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

fn valid_component(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'/' | b':' | b'+')
        })
}

fn valid_dependency_requirement(value: &str) -> bool {
    valid_text(value, MAX_DEPENDENCY_ITEM_BYTES, true)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_'
                        | b'.'
                        | b'@'
                        | b'/'
                        | b':'
                        | b'+'
                        | b'^'
                        | b'~'
                        | b'*'
                        | b'<'
                        | b'>'
                        | b'='
                        | b','
                        | b'|'
                        | b' '
                )
        })
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, MAX_ARN_BYTES, false) && value.starts_with("arn:")
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-codeartifact-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

redacted_identifier!(AwsRegion, "region", |value: &str| valid_component(
    value, 64
));
redacted_identifier!(CodeArtifactDomain, "domain", |value: &str| {
    valid_component(value, 50)
});
redacted_identifier!(CodeArtifactRepository, "repository", |value: &str| {
    valid_component(value, 100)
});
redacted_identifier!(PackageFormat, "format", |value: &str| {
    valid_component(value, 32)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
});
redacted_identifier!(PackageNamespace, "namespace", |value: &str| {
    valid_component(value, MAX_IDENTIFIER_BYTES)
});
redacted_identifier!(PackageName, "package", |value: &str| {
    valid_component(value, MAX_IDENTIFIER_BYTES)
});
redacted_identifier!(PackageVersion, "version", |value: &str| {
    valid_component(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: "account" })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-codeartifact-account/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.0.len() == 12 && self.0.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(())
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: "account" })
        }
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&format!("account:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionBinding {
    id: String,
    revision: u64,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_component(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: "mission" });
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-mission-id/v1",
            &[("value", self.id.clone())],
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-mission-binding/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_component(&self.id, MAX_IDENTIFIER_BYTES) && self.revision > 0 {
            Ok(())
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: "mission" })
        }
    }
}

impl fmt::Debug for MissionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBinding")
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectBinding {
    id: String,
    revision: u64,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_component(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: "project" });
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-project-id/v1",
            &[("value", self.id.clone())],
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-project-binding/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_component(&self.id, MAX_IDENTIFIER_BYTES) && self.revision > 0 {
            Ok(())
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidIdentifier { field: "project" })
        }
    }
}

impl fmt::Debug for ProjectBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectBinding")
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductBinding {
    id: String,
    revision: u64,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_component(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsCodeArtifactProvenanceError::InvalidIdentifier {
                field: "work-product",
            });
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-work-product-id/v1",
            &[("value", self.id.clone())],
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-work-product-binding/v1",
            &[
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_component(&self.id, MAX_IDENTIFIER_BYTES) && self.revision > 0 {
            Ok(())
        } else {
            Err(AwsCodeArtifactProvenanceError::InvalidIdentifier {
                field: "work-product",
            })
        }
    }
}

impl fmt::Debug for WorkProductBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductBinding")
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&MissionBinding> for MissionProjection {
    fn from(binding: &MissionBinding) -> Self {
        Self {
            id_digest: binding.id_digest(),
            revision: binding.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&ProjectBinding> for ProjectProjection {
    fn from(binding: &ProjectBinding) -> Self {
        Self {
            id_digest: binding.id_digest(),
            revision: binding.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&WorkProductBinding> for WorkProductProjection {
    fn from(binding: &WorkProductBinding) -> Self {
        Self {
            id_digest: binding.id_digest(),
            revision: binding.revision,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsCodeArtifactProvenanceScope {
    account: AwsAccountId,
    region: AwsRegion,
    domain: CodeArtifactDomain,
    repository: CodeArtifactRepository,
    format: PackageFormat,
    namespace: Option<PackageNamespace>,
    package: PackageName,
    version: PackageVersion,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
}

impl AwsCodeArtifactProvenanceScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        domain: CodeArtifactDomain,
        repository: CodeArtifactRepository,
        format: PackageFormat,
        namespace: Option<PackageNamespace>,
        package: PackageName,
        version: PackageVersion,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            domain,
            repository,
            format,
            namespace,
            package,
            version,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn domain(&self) -> &CodeArtifactDomain {
        &self.domain
    }

    pub fn repository(&self) -> &CodeArtifactRepository {
        &self.repository
    }

    pub fn format(&self) -> &PackageFormat {
        &self.format
    }

    pub fn namespace(&self) -> Option<&PackageNamespace> {
        self.namespace.as_ref()
    }

    pub fn package(&self) -> &PackageName {
        &self.package
    }

    pub fn version(&self) -> &PackageVersion {
        &self.version
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

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-provenance-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("domain", self.domain.digest().as_str().to_owned()),
                ("repository", self.repository.digest().as_str().to_owned()),
                ("format", self.format.digest().as_str().to_owned()),
                (
                    "namespace",
                    self.namespace
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("package", self.package.digest().as_str().to_owned()),
                ("version", self.version.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.domain.validate()?;
        self.repository.validate()?;
        self.format.validate()?;
        self.namespace
            .as_ref()
            .map(PackageNamespace::validate)
            .transpose()?;
        self.package.validate()?;
        self.version.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsCodeArtifactProvenanceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodeArtifactProvenanceScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("domain", &self.domain)
            .field("repository", &self.repository)
            .field("format", &self.format)
            .field("namespace", &self.namespace)
            .field("package", &self.package)
            .field("version", &self.version)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsCodeArtifactProvenanceScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCodeArtifactProvenanceScope", 11)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("domainDigest", &self.domain.digest())?;
        state.serialize_field("repositoryDigest", &self.repository.digest())?;
        state.serialize_field("formatDigest", &self.format.digest())?;
        state.serialize_field(
            "namespaceDigest",
            &self.namespace.as_ref().map(PackageNamespace::digest),
        )?;
        state.serialize_field("packageDigest", &self.package.digest())?;
        state.serialize_field("versionDigest", &self.version.digest())?;
        state.serialize_field("mission", &MissionProjection::from(&self.mission))?;
        state.serialize_field("project", &ProjectProjection::from(&self.project))?;
        state.serialize_field(
            "workProduct",
            &WorkProductProjection::from(&self.work_product),
        )?;
        state.end()
    }
}

/// A credential boundary that stores only an opaque, zeroized handle and its
/// scope-bound digest. It intentionally does not implement `Serialize`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_handle: Zeroizing<String>,
    scope_digest: Digest,
    signing_region: AwsRegion,
    reference_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AwsCodeArtifactProvenanceScope,
    ) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        if !valid_text(&opaque_handle, crate::model::MAX_OPAQUE_HANDLE_BYTES, false) {
            return Err(AwsCodeArtifactProvenanceError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "aws-codeartifact-secret-reference/v1",
            &[
                ("handle", opaque_handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("region", scope.region().digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            opaque_handle: Zeroizing::new(opaque_handle),
            scope_digest,
            signing_region: scope.region().clone(),
            reference_digest,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.signing_region
    }

    pub const fn signing_service(&self) -> &'static str {
        "codeartifact"
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self, scope: &AwsCodeArtifactProvenanceScope) -> Result<()> {
        if self.revoked
            || self.scope_digest != scope.digest()
            || self.signing_region != *scope.region()
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidSecretReference);
        }
        if self.reference_digest
            != Digest::from_parts(
                "aws-codeartifact-secret-reference/v1",
                &[
                    ("handle", self.opaque_handle.to_string()),
                    ("scope", self.scope_digest.as_str().to_owned()),
                    ("region", self.signing_region.digest().as_str().to_owned()),
                ],
            )
        {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.opaque_handle.zeroize();
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("signing_region", &self.signing_region)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<String>,
    pub revision: u64,
    pub permission_digest: Digest,
}

impl fmt::Debug for PermissionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionSnapshot")
            .field("permissions", &self.permissions)
            .field("revision", &self.revision)
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

impl PermissionSnapshot {
    pub fn new<I, S>(permissions: I, revision: u64) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions.into_iter().map(Into::into).collect();
        let snapshot = Self {
            permissions,
            revision,
            permission_digest: Digest::from_text("unsealed-codeartifact-permissions"),
        };
        let mut snapshot = snapshot;
        snapshot.permission_digest = snapshot.recomputed_digest();
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn readonly(revision: u64) -> Result<Self> {
        Self::new(LAYER1_PERMISSIONS, revision)
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub fn allows(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    fn recomputed_digest(&self) -> Digest {
        let permissions = self
            .permissions
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("|");
        Digest::from_parts(
            "aws-codeartifact-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                ("permissions", permissions),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.permission_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub id: String,
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub consent_digest: Digest,
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("revision", &self.revision)
            .field("permissions", &self.permissions)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .field("consent_digest", &self.consent_digest)
            .finish()
    }
}

impl ConsentScope {
    pub fn new<I, S>(id: impl Into<String>, revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        let permissions = permissions.into_iter().map(Into::into).collect();
        let mut consent = Self {
            id,
            revision,
            permissions,
            expires_at: None,
            revoked: false,
            consent_digest: Digest::from_text("unsealed-codeartifact-consent"),
        };
        consent.consent_digest = consent.recomputed_digest();
        consent.validate()?;
        Ok(consent)
    }

    pub fn readonly(id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS)
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Result<Self> {
        self.expires_at = Some(expires_at);
        self.consent_digest = self.recomputed_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn digest(&self) -> Digest {
        self.consent_digest.clone()
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.consent_digest = self.recomputed_digest();
    }

    pub fn is_active_at(&self, observed_at: DateTime<Utc>) -> bool {
        !self.revoked
            && self
                .expires_at
                .is_none_or(|expires_at| observed_at < expires_at)
    }

    fn recomputed_digest(&self) -> Digest {
        let permissions = self
            .permissions
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("|");
        Digest::from_parts(
            "aws-codeartifact-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
                ("permissions", permissions),
                (
                    "expires_at",
                    self.expires_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_component(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.consent_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageVersionStatus {
    Published,
    Unfinished,
    Unlisted,
    Archived,
    Disposed,
}

impl PackageVersionStatus {
    pub const fn as_api(self) -> &'static str {
        match self {
            Self::Published => "PUBLISHED",
            Self::Unfinished => "UNFINISHED",
            Self::Unlisted => "UNLISTED",
            Self::Archived => "ARCHIVED",
            Self::Disposed => "DISPOSED",
        }
    }

    pub fn parse_api(value: &str) -> Result<Self> {
        match value {
            "PUBLISHED" => Ok(Self::Published),
            "UNFINISHED" => Ok(Self::Unfinished),
            "UNLISTED" => Ok(Self::Unlisted),
            "ARCHIVED" => Ok(Self::Archived),
            "DISPOSED" => Ok(Self::Disposed),
            _ => Err(AwsCodeArtifactProvenanceError::InvalidIdentifier {
                field: "package-version-status",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageOrigin {
    External,
    Internal,
}

impl PackageOrigin {
    pub const fn as_api(self) -> &'static str {
        match self {
            Self::External => "EXTERNAL",
            Self::Internal => "INTERNAL",
        }
    }

    pub fn parse_api(value: &str) -> Result<Self> {
        match value {
            "EXTERNAL" => Ok(Self::External),
            "INTERNAL" => Ok(Self::Internal),
            _ => Err(AwsCodeArtifactProvenanceError::InvalidIdentifier {
                field: "package-origin",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VersionSortOrder {
    PublishedTime,
}

impl VersionSortOrder {
    pub const fn as_api(self) -> &'static str {
        match self {
            Self::PublishedTime => "PUBLISHED_TIME",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVersionFilter {
    pub status: Option<PackageVersionStatus>,
    pub max_results: u16,
    pub sort_by: VersionSortOrder,
    filter_digest: Digest,
}

impl PackageVersionFilter {
    pub fn new(
        status: Option<PackageVersionStatus>,
        max_results: u16,
        sort_by: VersionSortOrder,
    ) -> Result<Self> {
        if !(1..=MAX_PAGE_SIZE).contains(&max_results) {
            return Err(AwsCodeArtifactProvenanceError::InvalidRequest);
        }
        let mut filter = Self {
            status,
            max_results,
            sort_by,
            filter_digest: Digest::from_text("unsealed-codeartifact-filter"),
        };
        filter.filter_digest = filter.recomputed_digest();
        Ok(filter)
    }

    pub fn all(max_results: u16) -> Result<Self> {
        Self::new(None, max_results, VersionSortOrder::PublishedTime)
    }

    pub fn digest(&self) -> Digest {
        self.filter_digest.clone()
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-package-version-filter/v1",
            &[
                (
                    "status",
                    self.status
                        .map_or_else(String::new, |value| value.as_api().to_owned()),
                ),
                ("max_results", self.max_results.to_string()),
                ("sort_by", self.sort_by.as_api().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.max_results)
            || self.filter_digest != self.recomputed_digest()
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    token: Zeroizing<String>,
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(token: impl Into<String>, binding_digest: Digest, page_number: u16) -> Result<Self> {
        let token = token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES * 2, false)
            || !(2..=MAX_PAGES).contains(&page_number)
        {
            return Err(AwsCodeArtifactProvenanceError::InvalidRequest);
        }
        binding_digest.validate()?;
        let token_digest = Digest::from_parts(
            "aws-codeartifact-opaque-cursor/v1",
            &[
                ("token", token.clone()),
                ("binding", binding_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
            ],
        );
        Ok(Self {
            token: Zeroizing::new(token),
            token_digest,
            binding_digest,
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn validate_against(&self, binding_digest: &Digest) -> Result<()> {
        if &self.binding_digest != binding_digest
            || self.token_digest
                != Digest::from_parts(
                    "aws-codeartifact-opaque-cursor/v1",
                    &[
                        ("token", self.token.to_string()),
                        ("binding", self.binding_digest.as_str().to_owned()),
                        ("page", self.page_number.to_string()),
                    ],
                )
        {
            return Err(AwsCodeArtifactProvenanceError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Cursor", 3)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
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

#[derive(Clone, Eq, PartialEq)]
pub struct DependencyMetadataInput {
    namespace: Option<PackageNamespace>,
    package: PackageName,
    version_requirement: String,
}

impl DependencyMetadataInput {
    pub fn new(
        namespace: Option<PackageNamespace>,
        package: PackageName,
        version_requirement: impl Into<String>,
    ) -> Result<Self> {
        let version_requirement = version_requirement.into();
        if !valid_dependency_requirement(&version_requirement) {
            return Err(AwsCodeArtifactProvenanceError::InvalidText {
                field: "dependency-version-requirement",
            });
        }
        Ok(Self {
            namespace,
            package,
            version_requirement,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-dependency-item/v1",
            &[
                (
                    "namespace",
                    self.namespace
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("package", self.package.digest().as_str().to_owned()),
                ("requirement", self.version_requirement.clone()),
            ],
        )
    }
}

impl fmt::Debug for DependencyMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DependencyMetadataInput")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencySummary {
    pub dependency_count: u16,
    pub dependency_digest: Digest,
    pub truncated: bool,
}

impl DependencySummary {
    pub fn from_items(items: &[DependencyMetadataInput], truncated: bool) -> Result<Self> {
        if items.len() > MAX_DEPENDENCIES {
            return Err(AwsCodeArtifactProvenanceError::DependencyTruncated);
        }
        let item_digests = items
            .iter()
            .map(DependencyMetadataInput::digest)
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>();
        Ok(Self {
            dependency_count: u16::try_from(items.len())
                .map_err(|_| AwsCodeArtifactProvenanceError::DependencyTruncated)?,
            dependency_digest: Digest::from_parts(
                "aws-codeartifact-dependencies/v1",
                &[
                    ("items", item_digests.join("|")),
                    ("truncated", truncated.to_string()),
                ],
            ),
            truncated,
        })
    }

    pub fn empty() -> Self {
        Self {
            dependency_count: 0,
            dependency_digest: Digest::from_parts(
                "aws-codeartifact-dependencies/v1",
                &[("items", String::new()), ("truncated", "false".to_owned())],
            ),
            truncated: false,
        }
    }

    pub const fn is_complete(&self) -> bool {
        !self.truncated
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PackageVersionObservation {
    version: PackageVersion,
    revision_digest: Digest,
    origin: PackageOrigin,
    status: PackageVersionStatus,
    published_at: Option<DateTime<Utc>>,
    asset_count: u32,
    package_version_arn_digest: Option<Digest>,
    dependency_summary: Option<DependencySummary>,
    metadata_digest: Digest,
}

impl PackageVersionObservation {
    pub fn new(
        version: PackageVersion,
        revision: impl Into<String>,
        origin: PackageOrigin,
        status: PackageVersionStatus,
        published_at: Option<DateTime<Utc>>,
        asset_count: u32,
        package_version_arn: Option<impl Into<String>>,
    ) -> Result<Self> {
        let revision = revision.into();
        if !valid_text(&revision, MAX_IDENTIFIER_BYTES, false) {
            return Err(AwsCodeArtifactProvenanceError::InvalidText {
                field: "package-version-revision",
            });
        }
        let package_version_arn_digest = package_version_arn
            .map(Into::into)
            .map(|arn| {
                if valid_arn(&arn) {
                    Ok(Digest::from_parts(
                        "aws-codeartifact-package-version-arn/v1",
                        &[("arn", arn)],
                    ))
                } else {
                    Err(AwsCodeArtifactProvenanceError::InvalidIdentifier {
                        field: "package-version-arn",
                    })
                }
            })
            .transpose()?;
        let mut observation = Self {
            version,
            revision_digest: Digest::from_parts(
                "aws-codeartifact-package-version-revision/v1",
                &[("revision", revision)],
            ),
            origin,
            status,
            published_at,
            asset_count,
            package_version_arn_digest,
            dependency_summary: None,
            metadata_digest: Digest::from_text("unsealed-codeartifact-metadata"),
        };
        observation.metadata_digest = observation.recomputed_digest();
        observation.validate()?;
        Ok(observation)
    }

    #[must_use]
    pub fn with_dependencies(mut self, dependencies: DependencySummary) -> Self {
        self.dependency_summary = Some(dependencies);
        self.metadata_digest = self.recomputed_digest();
        self
    }

    pub fn version(&self) -> &PackageVersion {
        &self.version
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub const fn origin(&self) -> PackageOrigin {
        self.origin
    }

    pub const fn status(&self) -> PackageVersionStatus {
        self.status
    }

    pub fn published_at(&self) -> Option<DateTime<Utc>> {
        self.published_at
    }

    pub const fn asset_count(&self) -> u32 {
        self.asset_count
    }

    pub fn package_version_arn_digest(&self) -> Option<&Digest> {
        self.package_version_arn_digest.as_ref()
    }

    pub fn dependency_summary(&self) -> Option<&DependencySummary> {
        self.dependency_summary.as_ref()
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-package-version-metadata/v1",
            &[
                ("version", self.version.digest().as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("origin", self.origin.as_api().to_owned()),
                ("status", self.status.as_api().to_owned()),
                (
                    "published_at",
                    self.published_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("asset_count", self.asset_count.to_string()),
                (
                    "package_version_arn",
                    self.package_version_arn_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "dependency_digest",
                    self.dependency_summary
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.dependency_digest.as_str().to_owned()
                        }),
                ),
                (
                    "dependency_count",
                    self.dependency_summary
                        .as_ref()
                        .map_or_else(String::new, |value| value.dependency_count.to_string()),
                ),
                (
                    "dependency_truncated",
                    self.dependency_summary
                        .as_ref()
                        .map_or_else(String::new, |value| value.truncated.to_string()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.version.validate()?;
        self.revision_digest.validate()?;
        self.package_version_arn_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if let Some(dependencies) = &self.dependency_summary {
            dependencies.dependency_digest.validate()?;
            if usize::from(dependencies.dependency_count) > MAX_DEPENDENCIES {
                return Err(AwsCodeArtifactProvenanceError::DependencyTruncated);
            }
        }
        if self.metadata_digest != self.recomputed_digest() {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for PackageVersionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageVersionObservation")
            .field("version", &self.version)
            .field("revision_digest", &self.revision_digest)
            .field("origin", &self.origin)
            .field("status", &self.status)
            .field("published_at", &self.published_at)
            .field("asset_count", &self.asset_count)
            .field(
                "package_version_arn_digest",
                &self.package_version_arn_digest,
            )
            .field("dependency_summary", &self.dependency_summary)
            .field("metadata_digest", &self.metadata_digest)
            .finish()
    }
}

impl Serialize for PackageVersionObservation {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PackageVersionObservation", 9)?;
        state.serialize_field("versionDigest", &self.version.digest())?;
        state.serialize_field("revisionDigest", &self.revision_digest)?;
        state.serialize_field("origin", &self.origin)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("publishedAt", &self.published_at)?;
        state.serialize_field("assetCount", &self.asset_count)?;
        state.serialize_field("packageVersionArnDigest", &self.package_version_arn_digest)?;
        state.serialize_field("dependencySummary", &self.dependency_summary)?;
        state.serialize_field("metadataDigest", &self.metadata_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub list_digest: Digest,
    pub describe_digest: Digest,
    pub dependency_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_version_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
        scope_digest: Digest,
        list_digest: Digest,
        describe_digest: Digest,
        dependency_digest: Option<Digest>,
    ) -> Self {
        let mut evidence = Self {
            plugin_version_digest,
            contract_digest,
            provider_digest,
            permission_digest,
            consent_digest,
            scope_digest,
            list_digest,
            describe_digest,
            dependency_digest,
            evidence_digest: Digest::from_text("unsealed-codeartifact-evidence"),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codeartifact-evidence-digests/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("list", self.list_digest.as_str().to_owned()),
                ("describe", self.describe_digest.as_str().to_owned()),
                (
                    "dependency",
                    self.dependency_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.list_digest,
            &self.describe_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if let Some(digest) = &self.dependency_digest {
            digest.validate()?;
        }
        if self.evidence_digest != self.recomputed_digest() {
            return Err(AwsCodeArtifactProvenanceError::TamperedEvidence);
        }
        Ok(())
    }
}
