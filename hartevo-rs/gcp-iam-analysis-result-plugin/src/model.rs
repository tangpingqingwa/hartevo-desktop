//! Typed, bounded data for the Layer-1 Google Cloud IAM analysis seam.
//!
//! The model deliberately contains no IAM policy JSON, principal address,
//! access token, service-account key, arbitrary resource payload, or raw page
//! cursor.  Provider answers are represented by fingerprints and bounded
//! classification codes so a fixture cannot be mistaken for native authority.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES_PER_OPERATION: usize = 8;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_POLICY_MATCHES: usize = 128;
pub const MAX_ANALYSIS_NODES: usize = 256;
pub const MAX_ANALYSIS_EDGES: usize = 512;
pub const MAX_EXPLANATION_CODES: usize = 32;
pub const MAX_PERMISSIONS: usize = 32;
pub const MAX_HIERARCHY_ITEMS: usize = 64;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESOURCE_NAME_BYTES: usize = 512;

/// Errors raised before a provider is reached.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpIamModelError {
    #[error("{field} is empty, invalid, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be a positive revision")]
    InvalidRevision { field: &'static str },
    #[error("the Google Cloud resource name is not normalized or contains traversal")]
    InvalidResourceName,
    #[error("the IAM permission is not allowlisted")]
    InvalidPermission,
    #[error("{field} exceeded its bound of {maximum}")]
    BoundExceeded { field: &'static str, maximum: usize },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("the IAM analysis scope is invalid")]
    InvalidScope,
    #[error("the opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("the SecretReference is already revoked")]
    AlreadyRevoked,
    #[error("the model digest does not match its immutable fields")]
    DigestMismatch,
    #[error("the bounded provider response is invalid")]
    InvalidResponse,
    #[error("the opaque page cursor does not match the registered query")]
    CursorMismatch,
}

/// A lowercase SHA-256 digest used as the only durable representation of
/// sensitive provider material.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    /// Hashes length-delimited fields so concatenation ambiguity cannot create
    /// a second valid scope or registration digest.
    #[must_use]
    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain.len().to_le_bytes());
        hasher.update(domain.as_bytes());
        for field in fields {
            hasher.update(field.len().to_le_bytes());
            hasher.update(field.as_bytes());
        }
        Self(hex::encode(hasher.finalize()))
    }

    #[must_use]
    pub fn from_serialized<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded GCP IAM values serialize");
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_sha256(self.as_str())
    }

    pub fn validate(&self, field: &'static str) -> Result<(), GcpIamModelError> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(GcpIamModelError::InvalidDigest { field })
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
        self.0.fmt(formatter)
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_opaque(domain: &str, value: &str) -> Digest {
    if is_sha256(value) {
        Digest(value.to_owned())
    } else {
        Digest::from_fields(domain, &[value.to_owned()])
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), GcpIamModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        return Err(GcpIamModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, GcpIamModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn validate(&self) -> Result<(), GcpIamModelError> {
                validate_identifier(&self.0, $field)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = GcpIamModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
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

identifier_type!(OrganizationId, "organization");
identifier_type!(FolderId, "folder");
identifier_type!(GcpProjectId, "Google Cloud project");
identifier_type!(MissionId, "Mission");
identifier_type!(ProjectId, "Hartevo Project");
identifier_type!(WorkProductId, "Work Product");

/// A normalized full resource name. It is scope input, not an arbitrary
/// provider payload; provider responses retain only its digest.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceName(String);

impl ResourceName {
    pub fn new(value: impl Into<String>) -> Result<Self, GcpIamModelError> {
        let value = value.into();
        let normalized = value.trim_end_matches('/').to_owned();
        if normalized.is_empty()
            || normalized.len() > MAX_RESOURCE_NAME_BYTES
            || normalized.trim() != normalized
            || !normalized.starts_with("//")
            || normalized.contains('?')
            || normalized.contains('#')
            || normalized.chars().any(char::is_control)
        {
            return Err(GcpIamModelError::InvalidResourceName);
        }
        let parts = normalized.split('/').collect::<Vec<_>>();
        if parts.len() < 4
            || parts[2..].iter().any(|part| {
                part.is_empty()
                    || *part == "."
                    || *part == ".."
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._:@-".contains(&byte))
            })
        {
            return Err(GcpIamModelError::InvalidResourceName);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        Self::new(self.0.clone()).map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields("gcp-resource-name/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for ResourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceName")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64, field: &'static str) -> Result<Self, GcpIamModelError> {
        if value == 0 {
            Err(GcpIamModelError::InvalidRevision { field })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn validate(self, field: &'static str) -> Result<(), GcpIamModelError> {
        Self::new(self.0, field).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalClass {
    User,
    Group,
    ServiceAccount,
    Domain,
    WorkforceIdentity,
    AllAuthenticatedUsers,
    AllUsers,
    Unknown,
}

impl PrincipalClass {
    #[must_use]
    pub const fn is_broad(self) -> bool {
        matches!(self, Self::AllAuthenticatedUsers | Self::AllUsers)
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PermissionName(String);

impl PermissionName {
    pub fn new(value: impl Into<String>) -> Result<Self, GcpIamModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || value.trim() != value
            || value.contains('*')
            || value.chars().any(char::is_control)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(GcpIamModelError::InvalidPermission);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for PermissionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionName")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for PermissionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A typed principal input accepts an opaque reference and drops it after
/// hashing. Passing a Digest avoids even transient textual identity input.
#[derive(Clone, Debug)]
pub enum PrincipalInput {
    Digest(Digest),
    Opaque(String),
}

impl From<Digest> for PrincipalInput {
    fn from(value: Digest) -> Self {
        Self::Digest(value)
    }
}

impl From<String> for PrincipalInput {
    fn from(value: String) -> Self {
        Self::Opaque(value)
    }
}

impl From<&str> for PrincipalInput {
    fn from(value: &str) -> Self {
        Self::Opaque(value.to_owned())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IamAnalysisQuery {
    pub principal_class: PrincipalClass,
    pub principal_digest: Digest,
    pub resource_name: ResourceName,
    pub permissions: Vec<PermissionName>,
    pub permission_digest: Digest,
    pub query_digest: Digest,
}

impl IamAnalysisQuery {
    pub fn new<P: Into<PrincipalInput>>(
        principal_class: PrincipalClass,
        principal: P,
        resource_name: ResourceName,
        permissions: impl IntoIterator<Item = PermissionName>,
    ) -> Result<Self, GcpIamModelError> {
        let principal_digest = match principal.into() {
            PrincipalInput::Digest(value) => value,
            PrincipalInput::Opaque(value) => {
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    return Err(GcpIamModelError::InvalidSecretReference);
                }
                digest_opaque("gcp-principal-reference/v1", &value)
            }
        };
        principal_digest.validate("principal digest")?;
        let mut permission_set = BTreeSet::new();
        for permission in permissions {
            permission_set.insert(permission);
        }
        if permission_set.is_empty() {
            return Err(GcpIamModelError::InvalidScope);
        }
        if permission_set.len() > MAX_PERMISSIONS {
            return Err(GcpIamModelError::BoundExceeded {
                field: "permissions",
                maximum: MAX_PERMISSIONS,
            });
        }
        let permissions = permission_set.into_iter().collect::<Vec<_>>();
        let permission_digest = Digest::from_fields(
            "gcp-iam-permission-set/v1",
            &permissions
                .iter()
                .map(|permission| permission.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let query_digest = query_digest(
            principal_class,
            &principal_digest,
            &resource_name,
            &permission_digest,
        );
        Ok(Self {
            principal_class,
            principal_digest,
            resource_name,
            permissions,
            permission_digest,
            query_digest,
        })
    }

    pub fn from_opaque_principal(
        principal_class: PrincipalClass,
        principal_reference: impl Into<String>,
        resource_name: ResourceName,
        permissions: impl IntoIterator<Item = PermissionName>,
    ) -> Result<Self, GcpIamModelError> {
        Self::new(
            principal_class,
            PrincipalInput::Opaque(principal_reference.into()),
            resource_name,
            permissions,
        )
    }

    #[must_use]
    pub fn query_digest(&self) -> Digest {
        query_digest(
            self.principal_class,
            &self.principal_digest,
            &self.resource_name,
            &self.permission_digest,
        )
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.principal_digest.validate("principal digest")?;
        self.resource_name.validate()?;
        self.permission_digest.validate("permission digest")?;
        if self.permissions.is_empty() || self.permissions.len() > MAX_PERMISSIONS {
            return Err(GcpIamModelError::BoundExceeded {
                field: "permissions",
                maximum: MAX_PERMISSIONS,
            });
        }
        for permission in &self.permissions {
            permission.validate()?;
        }
        let expected_permission_digest = Digest::from_fields(
            "gcp-iam-permission-set/v1",
            &self
                .permissions
                .iter()
                .map(|permission| permission.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        if self.permissions.windows(2).any(|pair| pair[0] >= pair[1])
            || self.permission_digest != expected_permission_digest
            || self.query_digest != self.query_digest()
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }
}

fn query_digest(
    principal_class: PrincipalClass,
    principal_digest: &Digest,
    resource_name: &ResourceName,
    permission_digest: &Digest,
) -> Digest {
    Digest::from_fields(
        "gcp-iam-analysis-query/v1",
        &[
            format!("{principal_class:?}"),
            principal_digest.as_str().to_owned(),
            resource_name.digest().as_str().to_owned(),
            permission_digest.as_str().to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpHierarchyScope {
    pub organization: OrganizationId,
    pub folders: Vec<FolderId>,
    pub projects: Vec<GcpProjectId>,
    pub hierarchy_revision: Digest,
}

impl GcpHierarchyScope {
    pub fn new(
        organization: impl Into<String>,
        folders: impl IntoIterator<Item = FolderId>,
        projects: impl IntoIterator<Item = GcpProjectId>,
        hierarchy_revision: Digest,
    ) -> Result<Self, GcpIamModelError> {
        let folders = folders.into_iter().collect::<Vec<_>>();
        let projects = projects.into_iter().collect::<Vec<_>>();
        if folders.len() + projects.len() > MAX_HIERARCHY_ITEMS {
            return Err(GcpIamModelError::BoundExceeded {
                field: "hierarchy folders and projects",
                maximum: MAX_HIERARCHY_ITEMS,
            });
        }
        if folders.iter().collect::<BTreeSet<_>>().len() != folders.len()
            || projects.iter().collect::<BTreeSet<_>>().len() != projects.len()
        {
            return Err(GcpIamModelError::Duplicate {
                field: "hierarchy folders or projects",
            });
        }
        hierarchy_revision.validate("hierarchy revision")?;
        Ok(Self {
            organization: OrganizationId::new(organization)?,
            folders,
            projects,
            hierarchy_revision,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.organization.validate()?;
        self.hierarchy_revision.validate("hierarchy revision")?;
        if self.folders.len() + self.projects.len() > MAX_HIERARCHY_ITEMS {
            return Err(GcpIamModelError::BoundExceeded {
                field: "hierarchy folders and projects",
                maximum: MAX_HIERARCHY_ITEMS,
            });
        }
        for folder in &self.folders {
            folder.validate()?;
        }
        for project in &self.projects {
            project.validate()?;
        }
        if self.folders.iter().collect::<BTreeSet<_>>().len() != self.folders.len()
            || self.projects.iter().collect::<BTreeSet<_>>().len() != self.projects.len()
        {
            return Err(GcpIamModelError::Duplicate {
                field: "hierarchy folders or projects",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBindingFingerprint {
    pub binding_fingerprint: Digest,
    pub role_fingerprint: Digest,
}

impl PolicyBindingFingerprint {
    pub fn new(binding: impl AsRef<str>, role: impl AsRef<str>) -> Result<Self, GcpIamModelError> {
        let binding = binding.as_ref();
        let role = role.as_ref();
        if binding.trim().is_empty() || role.trim().is_empty() {
            return Err(GcpIamModelError::InvalidIdentifier {
                field: "policy binding or role fingerprint",
            });
        }
        Self::from_digests(
            digest_opaque("gcp-iam-policy-binding/v1", binding),
            digest_opaque("gcp-iam-role/v1", role),
        )
    }

    pub fn from_digests(
        binding_fingerprint: Digest,
        role_fingerprint: Digest,
    ) -> Result<Self, GcpIamModelError> {
        binding_fingerprint.validate("policy binding fingerprint")?;
        role_fingerprint.validate("role fingerprint")?;
        Ok(Self {
            binding_fingerprint,
            role_fingerprint,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.binding_fingerprint
            .validate("policy binding fingerprint")?;
        self.role_fingerprint.validate("role fingerprint")
    }

    #[must_use]
    pub fn policy_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-iam-policy-binding-set/v1",
            &[
                self.binding_fingerprint.as_str().to_owned(),
                self.role_fingerprint.as_str().to_owned(),
            ],
        )
    }
}

pub type PolicyBindingScope = PolicyBindingFingerprint;
pub type PolicyBinding = PolicyBindingFingerprint;
pub type RoleFingerprint = Digest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, GcpIamModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision, "Mission revision")?,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.id.validate()?;
        self.revision.validate("Mission revision")
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, GcpIamModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision, "Project revision")?,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.id.validate()?;
        self.revision.validate("Project revision")
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, GcpIamModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision, "Work Product revision")?,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.id.validate()?;
        self.revision.validate("Work Product revision")
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceAncestry {
    pub organization_digest: Digest,
    pub folder_digests: Vec<Digest>,
    pub project_digests: Vec<Digest>,
    pub resource_digest: Digest,
    pub hierarchy_revision: Digest,
    pub ancestry_digest: Digest,
}

impl ResourceAncestry {
    #[must_use]
    pub fn from_scope(scope: &GcpIamScope) -> Self {
        let mut ancestry = Self {
            organization_digest: Digest::from_text(scope.hierarchy.organization.as_str()),
            folder_digests: scope
                .hierarchy
                .folders
                .iter()
                .map(|folder| Digest::from_text(folder.as_str()))
                .collect(),
            project_digests: scope
                .hierarchy
                .projects
                .iter()
                .map(|project| Digest::from_text(project.as_str()))
                .collect(),
            resource_digest: scope.resource_name.digest(),
            hierarchy_revision: scope.hierarchy.hierarchy_revision.clone(),
            ancestry_digest: Digest::zero(),
        };
        ancestry.ancestry_digest = Digest::from_serialized(&(
            &ancestry.organization_digest,
            &ancestry.folder_digests,
            &ancestry.project_digests,
            &ancestry.resource_digest,
            &ancestry.hierarchy_revision,
        ));
        ancestry
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.organization_digest.validate("ancestry organization")?;
        self.hierarchy_revision
            .validate("ancestry hierarchy revision")?;
        self.resource_digest.validate("ancestry resource")?;
        if self.folder_digests.len() + self.project_digests.len() > MAX_HIERARCHY_ITEMS
            || self.folder_digests.iter().any(|digest| !digest.is_valid())
            || self.project_digests.iter().any(|digest| !digest.is_valid())
        {
            return Err(GcpIamModelError::BoundExceeded {
                field: "resource ancestry",
                maximum: MAX_HIERARCHY_ITEMS,
            });
        }
        let expected = Digest::from_serialized(&(
            &self.organization_digest,
            &self.folder_digests,
            &self.project_digests,
            &self.resource_digest,
            &self.hierarchy_revision,
        ));
        if expected != self.ancestry_digest {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }
}

/// Scope for exactly one external provider analysis and one Mission decision
/// context. The provider's organization/folder/project hierarchy and the
/// Hartevo Project are deliberately separate fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamScope {
    pub hierarchy: GcpHierarchyScope,
    pub resource_name: ResourceName,
    pub policy_binding: PolicyBindingFingerprint,
    pub query: IamAnalysisQuery,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub work_product: WorkProductScope,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub policy_revision: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
}

impl GcpIamScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hierarchy: GcpHierarchyScope,
        resource_name: ResourceName,
        policy_binding: PolicyBindingFingerprint,
        query: IamAnalysisQuery,
        mission: MissionScope,
        project: ProjectScope,
        work_product: WorkProductScope,
        consent_digest: Digest,
        policy_revision: Digest,
    ) -> Result<Self, GcpIamModelError> {
        hierarchy.validate()?;
        resource_name.validate()?;
        policy_binding.validate()?;
        query.validate()?;
        mission.validate()?;
        project.validate()?;
        work_product.validate()?;
        consent_digest.validate("consent digest")?;
        policy_revision.validate("policy revision")?;
        if query.resource_name != resource_name {
            return Err(GcpIamModelError::InvalidScope);
        }
        let permission_digest = query.permission_digest.clone();
        let query_digest = query.query_digest.clone();
        let mut scope = Self {
            hierarchy,
            resource_name,
            policy_binding,
            query,
            mission,
            project,
            work_product,
            permission_digest,
            consent_digest,
            policy_revision,
            query_digest,
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.compute_scope_digest();
        Ok(scope)
    }

    fn compute_scope_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-iam-analysis-scope/v1",
            &[
                self.hierarchy.digest().as_str().to_owned(),
                self.resource_name.digest().as_str().to_owned(),
                self.policy_binding.policy_digest().as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.policy_revision.as_str().to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.hierarchy.validate()?;
        self.resource_name.validate()?;
        self.query.validate()?;
        self.policy_binding.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.consent_digest.validate("consent digest")?;
        self.policy_revision.validate("policy revision")?;
        if self.query.resource_name != self.resource_name
            || self.query_digest != self.query.query_digest
            || self.permission_digest != self.query.permission_digest
            || self.scope_digest != self.compute_scope_digest()
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn policy_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-iam-policy-revision/v1",
            &[
                self.policy_binding.binding_fingerprint.as_str().to_owned(),
                self.policy_binding.role_fingerprint.as_str().to_owned(),
                self.policy_revision.as_str().to_owned(),
            ],
        )
    }

    #[must_use]
    pub fn hierarchy_revision(&self) -> &Digest {
        &self.hierarchy.hierarchy_revision
    }

    #[must_use]
    pub fn resource_ancestry(&self) -> ResourceAncestry {
        ResourceAncestry::from_scope(self)
    }

    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.hierarchy.organization
    }

    #[must_use]
    pub fn folders(&self) -> &[FolderId] {
        &self.hierarchy.folders
    }

    #[must_use]
    pub fn gcp_projects(&self) -> &[GcpProjectId] {
        &self.hierarchy.projects
    }
}

pub type GcpIamAnalysisScope = GcpIamScope;
pub type AnalysisQuery = IamAnalysisQuery;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    ServiceAccount,
}

/// Opaque host authority reference. The supplied reference identifier is
/// hashed and immediately dropped. This type intentionally implements neither
/// Serialize nor Deserialize, and it never contains credential material.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretReferenceKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GcpIamScope,
        credential_revision: u64,
    ) -> Result<Self, GcpIamModelError> {
        Self::oauth(reference_id, scope, credential_revision)
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &GcpIamScope,
        credential_revision: u64,
    ) -> Result<Self, GcpIamModelError> {
        Self::from_kind(
            SecretReferenceKind::OAuth,
            reference_id.into(),
            scope,
            credential_revision,
        )
    }

    pub fn service_account(
        reference_id: impl Into<String>,
        scope: &GcpIamScope,
        credential_revision: u64,
    ) -> Result<Self, GcpIamModelError> {
        Self::from_kind(
            SecretReferenceKind::ServiceAccount,
            reference_id.into(),
            scope,
            credential_revision,
        )
    }

    fn from_kind(
        kind: SecretReferenceKind,
        reference_id: String,
        scope: &GcpIamScope,
        credential_revision: u64,
    ) -> Result<Self, GcpIamModelError> {
        scope.validate()?;
        if reference_id.trim().is_empty()
            || reference_id.len() > MAX_IDENTIFIER_BYTES
            || reference_id.chars().any(char::is_control)
        {
            return Err(GcpIamModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision, "credential revision")?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "gcp-secret-reference/v1",
            &[
                format!("{kind:?}"),
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
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
    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), GcpIamModelError> {
        if self.revoked {
            Err(GcpIamModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

pub type OAuthSecretReference = SecretReference;
pub type ServiceAccountSecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessClassification {
    Allowed,
    Denied,
    Conditional,
    NoMatch,
    Unknown,
    Partial,
    AccessLost,
}

pub type AccessResultClassification = AccessClassification;
pub type AccessAnalysisClassification = AccessClassification;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisExplanationCode {
    DirectBinding,
    InheritedPolicy,
    GroupMembership,
    DomainMembership,
    ServiceAccountBinding,
    ConditionalBinding,
    MissingPermission,
    DeniedByCondition,
    UnsupportedCondition,
    AccessLost,
    GraphTruncated,
    ProviderPartial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrincipalEvidence {
    pub principal_class: PrincipalClass,
    pub principal_digest: Digest,
    pub redacted: bool,
}

impl PrincipalEvidence {
    pub fn new(
        principal_class: PrincipalClass,
        principal_digest: Digest,
    ) -> Result<Self, GcpIamModelError> {
        principal_digest.validate("principal digest")?;
        Ok(Self {
            principal_class,
            principal_digest,
            redacted: true,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.principal_digest.validate("principal digest")?;
        if !self.redacted {
            return Err(GcpIamModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBindingEvidence {
    pub binding_fingerprint: Digest,
    pub role_fingerprint: Digest,
    pub policy_digest: Digest,
    pub policy_revision: Digest,
    pub resource_digest: Digest,
    pub condition_digest: Option<Digest>,
    pub matched: bool,
}

impl PolicyBindingEvidence {
    pub fn new(
        binding: Digest,
        role: Digest,
        policy_revision: Digest,
        resource_digest: Digest,
        condition_digest: Option<Digest>,
        matched: bool,
    ) -> Result<Self, GcpIamModelError> {
        binding.validate("policy binding fingerprint")?;
        role.validate("role fingerprint")?;
        policy_revision.validate("policy revision")?;
        resource_digest.validate("resource digest")?;
        if let Some(digest) = &condition_digest {
            digest.validate("condition digest")?;
        }
        let policy_digest = Digest::from_fields(
            "gcp-iam-policy-revision/v1",
            &[
                binding.as_str().to_owned(),
                role.as_str().to_owned(),
                policy_revision.as_str().to_owned(),
            ],
        );
        Ok(Self {
            binding_fingerprint: binding,
            role_fingerprint: role,
            policy_digest,
            policy_revision,
            resource_digest,
            condition_digest,
            matched,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.binding_fingerprint
            .validate("policy binding fingerprint")?;
        self.role_fingerprint.validate("role fingerprint")?;
        self.policy_digest.validate("policy digest")?;
        self.policy_revision.validate("policy revision")?;
        self.resource_digest.validate("resource digest")?;
        if let Some(digest) = &self.condition_digest {
            digest.validate("condition digest")?;
        }
        let expected_policy_digest = Digest::from_fields(
            "gcp-iam-policy-revision/v1",
            &[
                self.binding_fingerprint.as_str().to_owned(),
                self.role_fingerprint.as_str().to_owned(),
                self.policy_revision.as_str().to_owned(),
            ],
        );
        if self.policy_digest != expected_policy_digest {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IamPolicyMatch {
    pub resource_digest: Digest,
    pub ancestry: ResourceAncestry,
    pub principal: PrincipalEvidence,
    pub binding: PolicyBindingEvidence,
    pub access: AccessClassification,
    pub explanations: Vec<AnalysisExplanationCode>,
    pub match_digest: Digest,
}

impl IamPolicyMatch {
    pub fn new(
        ancestry: ResourceAncestry,
        principal: PrincipalEvidence,
        binding: PolicyBindingEvidence,
        access: AccessClassification,
        explanations: impl IntoIterator<Item = AnalysisExplanationCode>,
    ) -> Result<Self, GcpIamModelError> {
        let explanations = explanations.into_iter().collect::<Vec<_>>();
        if explanations.len() > MAX_EXPLANATION_CODES {
            return Err(GcpIamModelError::BoundExceeded {
                field: "policy match explanations",
                maximum: MAX_EXPLANATION_CODES,
            });
        }
        ancestry.validate()?;
        principal.validate()?;
        binding.validate()?;
        let mut value = Self {
            resource_digest: ancestry.resource_digest.clone(),
            ancestry,
            principal,
            binding,
            access,
            explanations,
            match_digest: Digest::zero(),
        };
        value.match_digest = value.compute_digest();
        Ok(value)
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.match_digest = Digest::zero();
        Digest::from_serialized(&value)
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.ancestry.validate()?;
        self.principal.validate()?;
        self.binding.validate()?;
        if self.resource_digest != self.ancestry.resource_digest
            || self.binding.resource_digest != self.resource_digest
            || self.explanations.len() > MAX_EXPLANATION_CODES
            || self.match_digest != self.compute_digest()
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageTokenDigest {
    pub digest: Digest,
}

impl PageTokenDigest {
    #[must_use]
    pub fn from_opaque(value: impl AsRef<str>) -> Self {
        Self {
            digest: Digest::from_fields(
                "gcp-cloud-asset-page-token/v1",
                &[value.as_ref().to_owned()],
            ),
        }
    }

    pub fn from_digest(digest: Digest) -> Result<Self, GcpIamModelError> {
        digest.validate("page token digest")?;
        Ok(Self { digest })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.digest.validate("page token digest")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchAllIamPoliciesPage {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub hierarchy_revision: Digest,
    pub policy_revision: Digest,
    pub matches: Vec<IamPolicyMatch>,
    pub next_page_token: Option<PageTokenDigest>,
    pub partial: bool,
    pub access_loss: bool,
    pub redacted: bool,
    pub page_digest: Digest,
}

impl SearchAllIamPoliciesPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        query_digest: Digest,
        hierarchy_revision: Digest,
        policy_revision: Digest,
        matches: Vec<IamPolicyMatch>,
        next_page_token: Option<PageTokenDigest>,
        partial: bool,
        access_loss: bool,
    ) -> Result<Self, GcpIamModelError> {
        for digest in [
            &scope_digest,
            &query_digest,
            &hierarchy_revision,
            &policy_revision,
        ] {
            digest.validate("search page digest")?;
        }
        if matches.len() > MAX_POLICY_MATCHES {
            return Err(GcpIamModelError::BoundExceeded {
                field: "policy matches",
                maximum: MAX_POLICY_MATCHES,
            });
        }
        if let Some(token) = &next_page_token {
            token.validate()?;
        }
        if matches.iter().any(|item| item.validate().is_err()) {
            return Err(GcpIamModelError::InvalidResponse);
        }
        let mut page = Self {
            scope_digest,
            query_digest,
            hierarchy_revision,
            policy_revision,
            matches,
            next_page_token,
            partial,
            access_loss,
            redacted: true,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.compute_digest();
        Ok(page)
    }

    fn compute_digest(&self) -> Digest {
        let mut page = self.clone();
        page.page_digest = Digest::zero();
        Digest::from_serialized(&page)
    }

    pub fn validate_for_scope(&self, scope: &GcpIamScope) -> Result<(), GcpIamModelError> {
        scope.validate()?;
        if self.scope_digest != scope.scope_digest
            || self.query_digest != scope.query_digest
            || self.hierarchy_revision != *scope.hierarchy_revision()
            || self.policy_revision != scope.policy_revision
            || !self.redacted
            || self.matches.len() > MAX_POLICY_MATCHES
            || self.page_digest != self.compute_digest()
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        for item in &self.matches {
            item.validate()?;
            if item.binding.policy_revision != self.policy_revision
                || item.ancestry.hierarchy_revision != self.hierarchy_revision
                || item.ancestry != scope.resource_ancestry()
                || item.binding.binding_fingerprint != scope.policy_binding.binding_fingerprint
                || item.binding.role_fingerprint != scope.policy_binding.role_fingerprint
                || item.binding.policy_digest != scope.policy_digest()
                || item.binding.resource_digest != scope.resource_name.digest()
                || item.principal.principal_class != scope.query.principal_class
                || item.principal.principal_digest != scope.query.principal_digest
            {
                return Err(GcpIamModelError::InvalidResponse);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisNodeKind {
    Principal,
    Group,
    Domain,
    Resource,
    Policy,
    Binding,
    Role,
    Permission,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisNode {
    pub node_digest: Digest,
    pub kind: AnalysisNodeKind,
    pub depth: u16,
    pub redacted: bool,
}

impl AnalysisNode {
    pub fn new(
        kind: AnalysisNodeKind,
        node_digest: Digest,
        depth: u16,
    ) -> Result<Self, GcpIamModelError> {
        node_digest.validate("analysis node")?;
        Ok(Self {
            node_digest,
            kind,
            depth,
            redacted: true,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.node_digest.validate("analysis node")?;
        if !self.redacted {
            return Err(GcpIamModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisEdgeKind {
    PrincipalToBinding,
    GroupToPrincipal,
    DomainToPrincipal,
    BindingToRole,
    RoleToPermission,
    ResourceToPolicy,
    PolicyToBinding,
    InheritedFromParent,
    ConditionFilter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisEdge {
    pub edge_digest: Digest,
    pub source_digest: Digest,
    pub target_digest: Digest,
    pub kind: AnalysisEdgeKind,
    pub explanation: AnalysisExplanationCode,
    pub redacted: bool,
}

impl AnalysisEdge {
    pub fn new(
        source_digest: Digest,
        target_digest: Digest,
        kind: AnalysisEdgeKind,
        explanation: AnalysisExplanationCode,
    ) -> Result<Self, GcpIamModelError> {
        source_digest.validate("analysis edge source")?;
        target_digest.validate("analysis edge target")?;
        let edge_digest = Digest::from_fields(
            "gcp-iam-analysis-edge/v1",
            &[
                source_digest.as_str().to_owned(),
                target_digest.as_str().to_owned(),
                format!("{kind:?}"),
                format!("{explanation:?}"),
            ],
        );
        Ok(Self {
            edge_digest,
            source_digest,
            target_digest,
            kind,
            explanation,
            redacted: true,
        })
    }

    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.edge_digest.validate("analysis edge")?;
        self.source_digest.validate("analysis edge source")?;
        self.target_digest.validate("analysis edge target")?;
        let expected_edge_digest = Digest::from_fields(
            "gcp-iam-analysis-edge/v1",
            &[
                self.source_digest.as_str().to_owned(),
                self.target_digest.as_str().to_owned(),
                format!("{:?}", self.kind),
                format!("{:?}", self.explanation),
            ],
        );
        if !self.redacted || self.edge_digest != expected_edge_digest {
            return Err(GcpIamModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessAnalysisPage {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub hierarchy_revision: Digest,
    pub policy_revision: Digest,
    pub principal: PrincipalEvidence,
    pub resource_digest: Digest,
    pub permission_digest: Digest,
    pub classification: AccessClassification,
    pub explanations: Vec<AnalysisExplanationCode>,
    pub nodes: Vec<AnalysisNode>,
    pub edges: Vec<AnalysisEdge>,
    pub next_page_token: Option<PageTokenDigest>,
    pub partial: bool,
    pub access_loss: bool,
    pub redacted: bool,
    pub graph_digest: Digest,
    pub page_digest: Digest,
}

impl AccessAnalysisPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        query_digest: Digest,
        hierarchy_revision: Digest,
        policy_revision: Digest,
        principal: PrincipalEvidence,
        resource_digest: Digest,
        permission_digest: Digest,
        classification: AccessClassification,
        explanations: Vec<AnalysisExplanationCode>,
        nodes: Vec<AnalysisNode>,
        edges: Vec<AnalysisEdge>,
        next_page_token: Option<PageTokenDigest>,
        partial: bool,
        access_loss: bool,
    ) -> Result<Self, GcpIamModelError> {
        for digest in [
            &scope_digest,
            &query_digest,
            &hierarchy_revision,
            &policy_revision,
            &resource_digest,
            &permission_digest,
        ] {
            digest.validate("analysis page digest")?;
        }
        principal.validate()?;
        if explanations.len() > MAX_EXPLANATION_CODES
            || nodes.len() > MAX_ANALYSIS_NODES
            || edges.len() > MAX_ANALYSIS_EDGES
        {
            return Err(GcpIamModelError::BoundExceeded {
                field: "analysis graph",
                maximum: MAX_ANALYSIS_EDGES,
            });
        }
        for node in &nodes {
            node.validate()?;
        }
        for edge in &edges {
            edge.validate()?;
        }
        if let Some(token) = &next_page_token {
            token.validate()?;
        }
        let graph_digest = Digest::from_serialized(&(&nodes, &edges, &explanations));
        let mut page = Self {
            scope_digest,
            query_digest,
            hierarchy_revision,
            policy_revision,
            principal,
            resource_digest,
            permission_digest,
            classification,
            explanations,
            nodes,
            edges,
            next_page_token,
            partial,
            access_loss,
            redacted: true,
            graph_digest,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.compute_digest();
        Ok(page)
    }

    fn compute_digest(&self) -> Digest {
        let mut page = self.clone();
        page.page_digest = Digest::zero();
        Digest::from_serialized(&page)
    }

    pub fn validate_for_scope(&self, scope: &GcpIamScope) -> Result<(), GcpIamModelError> {
        scope.validate()?;
        if self.scope_digest != scope.scope_digest
            || self.query_digest != scope.query_digest
            || self.hierarchy_revision != *scope.hierarchy_revision()
            || self.policy_revision != scope.policy_revision
            || self.resource_digest != scope.resource_name.digest()
            || self.permission_digest != scope.permission_digest
            || !self.redacted
            || self.explanations.len() > MAX_EXPLANATION_CODES
            || self.nodes.len() > MAX_ANALYSIS_NODES
            || self.edges.len() > MAX_ANALYSIS_EDGES
            || self.graph_digest
                != Digest::from_serialized(&(&self.nodes, &self.edges, &self.explanations))
            || self.page_digest != self.compute_digest()
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        self.principal.validate()?;
        if self.principal.principal_class != scope.query.principal_class
            || self.principal.principal_digest != scope.query.principal_digest
        {
            return Err(GcpIamModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCloudAssetOperation {
    SearchAllIamPolicies,
    AnalyzeIamPolicy,
}

impl GcpCloudAssetOperation {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        true
    }

    #[must_use]
    pub const fn api_method(self) -> &'static str {
        match self {
            Self::SearchAllIamPolicies => "searchAllIamPolicies",
            Self::AnalyzeIamPolicy => "analyzeIamPolicy",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudAssetReceipt {
    pub operation: GcpCloudAssetOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
    pub raw_provider_payload_retained: bool,
    pub raw_page_token_retained: bool,
}

impl GcpCloudAssetReceipt {
    pub fn validate(&self) -> Result<(), GcpIamModelError> {
        self.request_digest.validate("request digest")?;
        self.response_digest.validate("response digest")?;
        self.page_digest.validate("page digest")?;
        if self.status != 200
            || self.response_size > MAX_RESPONSE_BYTES
            || self.provider_revision != crate::GCP_IAM_ANALYSIS_PROVIDER_REVISION
            || self.raw_provider_payload_retained
            || self.raw_page_token_retained
        {
            return Err(GcpIamModelError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamReadRequest {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub hierarchy_revision: Digest,
    pub policy_revision: Digest,
    pub page_size: usize,
    pub max_pages: usize,
    pub max_analysis_nodes: usize,
    pub max_analysis_edges: usize,
    pub include_policy_search: bool,
    pub include_access_analysis: bool,
    pub request_digest: Digest,
}

impl GcpIamReadRequest {
    pub fn new(scope: &GcpIamScope) -> Result<Self, GcpIamModelError> {
        Self::bounded(scope, MAX_PAGE_SIZE, MAX_PAGES_PER_OPERATION)
    }

    pub fn bounded(
        scope: &GcpIamScope,
        page_size: usize,
        max_pages: usize,
    ) -> Result<Self, GcpIamModelError> {
        scope.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(GcpIamModelError::BoundExceeded {
                field: "page size",
                maximum: MAX_PAGE_SIZE,
            });
        }
        if !(1..=MAX_PAGES_PER_OPERATION).contains(&max_pages) {
            return Err(GcpIamModelError::BoundExceeded {
                field: "pages",
                maximum: MAX_PAGES_PER_OPERATION,
            });
        }
        let mut request = Self {
            scope_digest: scope.scope_digest(),
            query_digest: scope.query_digest.clone(),
            hierarchy_revision: scope.hierarchy_revision().clone(),
            policy_revision: scope.policy_revision.clone(),
            page_size,
            max_pages,
            max_analysis_nodes: MAX_ANALYSIS_NODES,
            max_analysis_edges: MAX_ANALYSIS_EDGES,
            include_policy_search: true,
            include_access_analysis: true,
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    #[must_use]
    pub fn search_only(mut self) -> Self {
        self.include_access_analysis = false;
        self.request_digest = self.compute_digest();
        self
    }

    #[must_use]
    pub fn analysis_only(mut self) -> Self {
        self.include_policy_search = false;
        self.request_digest = self.compute_digest();
        self
    }

    #[must_use]
    pub fn with_graph_limits(mut self, max_nodes: usize, max_edges: usize) -> Self {
        self.max_analysis_nodes = max_nodes.min(MAX_ANALYSIS_NODES);
        self.max_analysis_edges = max_edges.min(MAX_ANALYSIS_EDGES);
        self.request_digest = self.compute_digest();
        self
    }

    fn compute_digest(&self) -> Digest {
        let mut request = self.clone();
        request.request_digest = Digest::zero();
        Digest::from_serialized(&request)
    }

    pub fn validate_for_scope(&self, scope: &GcpIamScope) -> Result<(), GcpIamModelError> {
        scope.validate()?;
        if self.scope_digest != scope.scope_digest
            || self.query_digest != scope.query_digest
            || self.hierarchy_revision != *scope.hierarchy_revision()
            || self.policy_revision != scope.policy_revision
            || self.request_digest != self.compute_digest()
            || (!self.include_policy_search && !self.include_access_analysis)
            || !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES_PER_OPERATION).contains(&self.max_pages)
            || self.max_analysis_nodes > MAX_ANALYSIS_NODES
            || self.max_analysis_edges > MAX_ANALYSIS_EDGES
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

impl AdoptionAvailability {
    #[must_use]
    pub const fn is_adopted(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpIamAnalysisEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub consumer_id: String,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub hierarchy_revision: Digest,
    pub policy_digest: Digest,
    pub policy_revision: Digest,
    pub query_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: ProviderProvenance,
    pub operations: Vec<GcpCloudAssetOperation>,
    pub receipts: Vec<GcpCloudAssetReceipt>,
    pub search_pages: Vec<SearchAllIamPoliciesPage>,
    pub analysis_pages: Vec<AccessAnalysisPage>,
    pub partial: bool,
    pub access_loss: bool,
    pub redacted: bool,
    pub raw_policy_retained: bool,
    pub raw_principal_retained: bool,
    pub personal_information_retained: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_page_token_retained: bool,
    pub raw_graph_edges_retained: bool,
    pub native_evidence: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub effective_authorization_claim: bool,
    pub durable_receipt: bool,
    pub adopted_outcome: bool,
    pub evidence_digest: Digest,
}

impl GcpIamAnalysisEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn from_pages(
        scope: &GcpIamScope,
        registration_digest: Digest,
        provenance: ProviderProvenance,
        operations: Vec<GcpCloudAssetOperation>,
        receipts: Vec<GcpCloudAssetReceipt>,
        search_pages: Vec<SearchAllIamPoliciesPage>,
        analysis_pages: Vec<AccessAnalysisPage>,
        partial: bool,
        access_loss: bool,
    ) -> Self {
        Self::from_pages_with_provider_digest(
            scope,
            registration_digest,
            crate::provider_definition_digest_for(provenance),
            provenance,
            operations,
            receipts,
            search_pages,
            analysis_pages,
            partial,
            access_loss,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_pages_with_provider_digest(
        scope: &GcpIamScope,
        registration_digest: Digest,
        provider_digest: Digest,
        provenance: ProviderProvenance,
        operations: Vec<GcpCloudAssetOperation>,
        receipts: Vec<GcpCloudAssetReceipt>,
        search_pages: Vec<SearchAllIamPoliciesPage>,
        analysis_pages: Vec<AccessAnalysisPage>,
        partial: bool,
        access_loss: bool,
    ) -> Self {
        let mut evidence = Self {
            schema_version: crate::GCP_IAM_ANALYSIS_SCHEMA_VERSION.to_owned(),
            contract_version: crate::GCP_IAM_ANALYSIS_CONTRACT_VERSION.to_owned(),
            plugin_version: crate::GCP_IAM_ANALYSIS_PLUGIN_VERSION.to_owned(),
            plugin_version_digest: Digest::from_text(crate::GCP_IAM_ANALYSIS_PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            service_id: crate::GCP_IAM_ANALYSIS_SERVICE_ID.to_owned(),
            provider_id: crate::GCP_IAM_ANALYSIS_PROVIDER_ID.to_owned(),
            provider_version: crate::GCP_IAM_ANALYSIS_PROVIDER_VERSION.to_owned(),
            provider_digest,
            consumer_id: crate::MISSION_GCP_IAM_CONSUMER_ID.to_owned(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.scope_digest(),
            hierarchy_revision: scope.hierarchy_revision().clone(),
            policy_digest: scope.policy_digest(),
            policy_revision: scope.policy_revision.clone(),
            query_digest: scope.query_digest.clone(),
            registration_digest,
            provenance,
            operations,
            receipts,
            search_pages,
            analysis_pages,
            partial,
            access_loss,
            redacted: true,
            raw_policy_retained: false,
            raw_principal_retained: false,
            personal_information_retained: false,
            raw_provider_payload_retained: false,
            raw_page_token_retained: false,
            raw_graph_edges_retained: false,
            native_evidence: false,
            connected: false,
            external_write_performed: false,
            effective_authorization_claim: false,
            durable_receipt: false,
            adopted_outcome: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.compute_evidence_digest();
        evidence
    }

    fn compute_evidence_digest(&self) -> Digest {
        let mut evidence = self.clone();
        evidence.evidence_digest = Digest::zero();
        Digest::from_serialized(&evidence)
    }

    pub fn verify_digest(&self) -> Result<(), GcpIamModelError> {
        if self.evidence_digest == self.compute_evidence_digest() {
            Ok(())
        } else {
            Err(GcpIamModelError::DigestMismatch)
        }
    }

    pub fn validate_for_scope(
        &self,
        scope: &GcpIamScope,
        registration_digest: Option<&Digest>,
    ) -> Result<(), GcpIamModelError> {
        scope.validate()?;
        let has_search_pages = !self.search_pages.is_empty();
        let has_analysis_pages = !self.analysis_pages.is_empty();
        let has_search_operation = self
            .operations
            .contains(&GcpCloudAssetOperation::SearchAllIamPolicies);
        let has_analysis_operation = self
            .operations
            .contains(&GcpCloudAssetOperation::AnalyzeIamPolicy);
        let operations_unique = self
            .operations
            .iter()
            .enumerate()
            .all(|(index, operation)| !self.operations[..index].contains(operation));
        if self.schema_version != crate::GCP_IAM_ANALYSIS_SCHEMA_VERSION
            || self.contract_version != crate::GCP_IAM_ANALYSIS_CONTRACT_VERSION
            || self.plugin_version != crate::GCP_IAM_ANALYSIS_PLUGIN_VERSION
            || self.plugin_version_digest
                != Digest::from_text(crate::GCP_IAM_ANALYSIS_PLUGIN_VERSION)
            || self.contract_digest != crate::contract_digest()
            || self.service_id != crate::GCP_IAM_ANALYSIS_SERVICE_ID
            || self.provider_id != crate::GCP_IAM_ANALYSIS_PROVIDER_ID
            || self.provider_version != crate::GCP_IAM_ANALYSIS_PROVIDER_VERSION
            || self.provider_digest != crate::provider_definition_digest_for(self.provenance)
            || self.consumer_id != crate::MISSION_GCP_IAM_CONSUMER_ID
            || self.permission_digest != scope.permission_digest
            || self.scope_digest != scope.scope_digest
            || self.hierarchy_revision != *scope.hierarchy_revision()
            || self.policy_digest != scope.policy_digest()
            || self.policy_revision != scope.policy_revision
            || self.query_digest != scope.query_digest
            || registration_digest.is_some_and(|digest| digest != &self.registration_digest)
            || !self.redacted
            || self.raw_policy_retained
            || self.raw_principal_retained
            || self.personal_information_retained
            || self.raw_provider_payload_retained
            || self.raw_page_token_retained
            || self.raw_graph_edges_retained
            || self.native_evidence
            || self.connected
            || self.external_write_performed
            || self.effective_authorization_claim
            || self.durable_receipt
            || self.adopted_outcome
            || self.operations.is_empty()
            || self.operations.len() > 2
            || !operations_unique
            || has_search_operation != has_search_pages
            || has_analysis_operation != has_analysis_pages
            || self.receipts.len() != self.search_pages.len() + self.analysis_pages.len()
            || self.search_pages.len() > MAX_PAGES_PER_OPERATION
            || self.analysis_pages.len() > MAX_PAGES_PER_OPERATION
        {
            return Err(GcpIamModelError::InvalidResponse);
        }
        self.contract_digest.validate("contract digest")?;
        self.provider_digest.validate("provider digest")?;
        self.permission_digest.validate("permission digest")?;
        self.scope_digest.validate("scope digest")?;
        self.hierarchy_revision.validate("hierarchy revision")?;
        self.policy_digest.validate("policy digest")?;
        self.policy_revision.validate("policy revision")?;
        self.query_digest.validate("query digest")?;
        self.registration_digest.validate("registration digest")?;
        if self.provenance.is_native() {
            return Err(GcpIamModelError::InvalidResponse);
        }
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        for page in &self.search_pages {
            page.validate_for_scope(scope)?;
        }
        for page in &self.analysis_pages {
            page.validate_for_scope(scope)?;
        }
        let has_partial = self.search_pages.iter().any(|page| page.partial)
            || self.analysis_pages.iter().any(|page| page.partial);
        let has_access_loss = self.search_pages.iter().any(|page| page.access_loss)
            || self.analysis_pages.iter().any(|page| page.access_loss);
        if self.partial != has_partial || self.access_loss != has_access_loss {
            return Err(GcpIamModelError::InvalidResponse);
        }
        let mut receipt_index = 0;
        for page in &self.search_pages {
            let receipt = self
                .receipts
                .get(receipt_index)
                .ok_or(GcpIamModelError::InvalidResponse)?;
            if receipt.operation != GcpCloudAssetOperation::SearchAllIamPolicies
                || receipt.page_digest != page.page_digest
            {
                return Err(GcpIamModelError::InvalidResponse);
            }
            receipt_index += 1;
        }
        for page in &self.analysis_pages {
            let receipt = self
                .receipts
                .get(receipt_index)
                .ok_or(GcpIamModelError::InvalidResponse)?;
            if receipt.operation != GcpCloudAssetOperation::AnalyzeIamPolicy
                || receipt.page_digest != page.page_digest
            {
                return Err(GcpIamModelError::InvalidResponse);
            }
            receipt_index += 1;
        }
        self.verify_digest()
    }
}

pub(crate) fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serialized(value)
}
