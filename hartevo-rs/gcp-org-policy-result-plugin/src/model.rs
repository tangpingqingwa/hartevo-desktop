//! Typed, bounded and redacted model types for Organization Policy evidence.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::LAYER1_PERMISSIONS;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESOURCE_NAME_BYTES: usize = 2_048;
pub const MAX_PAGE_TOKEN_BYTES: usize = 8_192;
pub const MAX_CONSTRAINTS: usize = 256;
pub const MAX_POLICY_ITEMS: usize = 4_096;
pub const MAX_PAGE_COUNT: u16 = 32;
pub const MAX_PAGE_SIZE: u16 = 100;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a valid digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("page size must be between one and {MAX_PAGE_SIZE}")]
    InvalidPageSize,
    #[error("page count must be between one and {MAX_PAGE_COUNT}")]
    InvalidPageCount,
    #[error("item count must be between one and {MAX_POLICY_ITEMS}")]
    InvalidItemCount,
    #[error("opaque page token is invalid")]
    InvalidPageToken,
    #[error("registration or secret reference is revoked")]
    Revoked,
    #[error("registration is already in the requested terminal state")]
    AlreadyTerminal,
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
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn valid_hartevo_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_google_numeric_id(value: &str) -> bool {
    (1..=30).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_google_project_id(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_constraint_id(value: &str) -> bool {
    value.starts_with("constraints/")
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value["constraints/".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn valid_resource_id(value: &str) -> bool {
    value.len() <= MAX_RESOURCE_NAME_BYTES
        && value.starts_with("//")
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                if !($validator)(&value) {
                    return Err(ModelError::Invalid { field: $field });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identifier_type!(OrganizationId, "organization id", valid_google_numeric_id);
identifier_type!(FolderId, "folder id", valid_google_numeric_id);
identifier_type!(
    GcpProjectId,
    "Google Cloud project id",
    valid_google_project_id
);
identifier_type!(ProjectId, "Project id", valid_hartevo_identifier);
identifier_type!(MissionId, "Mission id", valid_hartevo_identifier);
identifier_type!(WorkProductId, "Work Product id", valid_hartevo_identifier);
identifier_type!(ConstraintId, "constraint id", valid_constraint_id);

/// A Google Cloud resource name outside the organization/folder/project forms.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_resource_id(&value) {
            return Err(ModelError::Invalid {
                field: "resource name",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The exact GCP hierarchy/resource scope accepted by this Layer-1 plugin.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "id")]
pub enum GcpResource {
    Organization(OrganizationId),
    Folder(FolderId),
    Project(GcpProjectId),
    Resource(ResourceId),
}

impl GcpResource {
    pub fn organization(id: OrganizationId) -> Self {
        Self::Organization(id)
    }

    pub fn folder(id: FolderId) -> Self {
        Self::Folder(id)
    }

    pub fn project(id: GcpProjectId) -> Self {
        Self::Project(id)
    }

    pub fn resource(id: ResourceId) -> Self {
        Self::Resource(id)
    }

    pub fn canonical_name(&self) -> String {
        match self {
            Self::Organization(id) => format!("organizations/{}", id.as_str()),
            Self::Folder(id) => format!("folders/{}", id.as_str()),
            Self::Project(id) => format!("projects/{}", id.as_str()),
            Self::Resource(id) => id.as_str().to_owned(),
        }
    }

    pub fn organization_id(&self) -> Option<&OrganizationId> {
        match self {
            Self::Organization(id) => Some(id),
            Self::Folder(_) | Self::Project(_) | Self::Resource(_) => None,
        }
    }

    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::Organization(_) => ResourceKind::Organization,
            Self::Folder(_) => ResourceKind::Folder,
            Self::Project(_) => ResourceKind::Project,
            Self::Resource(_) => ResourceKind::Resource,
        }
    }
}

impl fmt::Display for GcpResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.canonical_name().fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceKind {
    Organization,
    Folder,
    Project,
    Resource,
}

/// A lower-case SHA-256 digest used as an immutable fence or evidence handle.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
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

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "policy id", MAX_RESOURCE_NAME_BYTES)?;
        if value.chars().any(char::is_control) || value.chars().any(char::is_whitespace) {
            return Err(ModelError::Invalid { field: "policy id" });
        }
        Ok(Self(value))
    }

    pub fn for_resource(resource: &GcpResource, constraint: &ConstraintId) -> Self {
        Self(format!(
            "{}/policies/{}",
            resource.canonical_name(),
            constraint.as_str()
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::Invalid { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type PolicyRevision = Revision;
pub type ProjectRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    pub project_id: ProjectId,
    pub project_revision: ProjectRevision,
    pub mission_id: MissionId,
    pub mission_revision: MissionRevision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: WorkProductRevision,
    pub consent_digest: Digest,
}

impl MissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        project_revision: ProjectRevision,
        mission_id: MissionId,
        mission_revision: MissionRevision,
        work_product_id: WorkProductId,
        work_product_revision: WorkProductRevision,
        consent_digest: Digest,
    ) -> Self {
        Self {
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            consent_digest,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-org-policy-mission-scope/v1",
            &[
                ("project", self.project_id.as_str().to_owned()),
                ("project_revision", self.project_revision.get().to_string()),
                ("mission", self.mission_id.as_str().to_owned()),
                ("mission_revision", self.mission_revision.get().to_string()),
                ("work_product", self.work_product_id.as_str().to_owned()),
                (
                    "work_product_revision",
                    self.work_product_revision.get().to_string(),
                ),
                ("consent", self.consent_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionScope {
    pub permissions: BTreeSet<String>,
    pub permission_revision: Revision,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new<I, S>(
        permissions: I,
        permission_revision: Revision,
        consent_digest: Digest,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        if permissions
            .iter()
            .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(ModelError::Invalid {
                field: "permission allowlist",
            });
        }
        let permission_digest = Digest::from_parts(
            "gcp-org-policy-permissions/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("revision", permission_revision.get().to_string()),
                ("consent", consent_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            permissions,
            permission_revision,
            consent_digest,
            permission_digest,
        })
    }

    pub fn all(permission_revision: Revision, consent_digest: Digest) -> Result<Self, ModelError> {
        Self::new(
            LAYER1_PERMISSIONS.iter().copied(),
            permission_revision,
            consent_digest,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyScope {
    pub organization: OrganizationId,
    pub resource: GcpResource,
    pub allowed_constraints: BTreeSet<ConstraintId>,
    pub policy_revision: PolicyRevision,
    pub mission: MissionScope,
    pub permissions: PermissionScope,
    pub scope_digest: Digest,
}

impl GcpOrgPolicyScope {
    pub fn new<I>(
        organization: OrganizationId,
        resource: GcpResource,
        allowed_constraints: I,
        policy_revision: PolicyRevision,
        mission: MissionScope,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = ConstraintId>,
    {
        let allowed_constraints = allowed_constraints.into_iter().collect::<BTreeSet<_>>();
        if allowed_constraints.is_empty() {
            return Err(ModelError::Empty {
                field: "constraint allowlist",
            });
        }
        if allowed_constraints.len() > MAX_CONSTRAINTS {
            return Err(ModelError::BoundExceeded {
                field: "constraint allowlist",
            });
        }
        let scope_digest = Digest::from_parts(
            "gcp-org-policy-scope/v1",
            &[
                ("organization", organization.as_str().to_owned()),
                ("resource", resource.canonical_name()),
                (
                    "constraints",
                    allowed_constraints
                        .iter()
                        .map(ConstraintId::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("policy_revision", policy_revision.get().to_string()),
                ("mission", mission.digest().as_str().to_owned()),
                (
                    "permissions",
                    permissions.permission_digest.as_str().to_owned(),
                ),
            ],
        );
        Ok(Self {
            organization,
            resource,
            allowed_constraints,
            policy_revision,
            mission,
            permissions,
            scope_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn contains_constraint(&self, constraint: &ConstraintId) -> bool {
        self.allowed_constraints.contains(constraint)
    }

    pub fn gcp_project_id(&self) -> Option<&GcpProjectId> {
        match &self.resource {
            GcpResource::Project(project) => Some(project),
            GcpResource::Organization(_) | GcpResource::Folder(_) | GcpResource::Resource(_) => {
                None
            }
        }
    }
}

/// The only accepted authentication modes. The host resolves the opaque
/// reference in a later layer; this crate never accepts credential material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpAuthKind {
    OAuth,
    ServiceAccount,
}

pub type GoogleAuthKind = GcpAuthKind;

/// An opaque, scope-bound host keyring reference. It intentionally does not
/// implement `Serialize`, and its debug form contains only digests.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GcpAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GcpOrgPolicyScope,
        credential_revision: Revision,
        auth_kind: GcpAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_hartevo_identifier(&reference_id) {
            return Err(ModelError::Invalid {
                field: "opaque secret reference id",
            });
        }
        let reference_digest = Digest::from_parts(
            "gcp-org-policy-secret-reference/v1",
            &[
                ("reference", reference_id),
                ("scope", scope.scope_digest.as_str().to_owned()),
                ("credential_revision", credential_revision.get().to_string()),
                ("auth_kind", format!("{auth_kind:?}")),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.scope_digest.clone(),
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn auth_kind(&self) -> GcpAuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyTerminal)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

/// A page token is retained only inside the provider seam. Public evidence
/// carries its digest and never serializes or prints the token value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self(value))
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("gcp-org-policy-page-token/v1", &[("token", self.0.clone())])
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub max_items: usize,
    pub page_size: u16,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: 4,
            max_items: 128,
            page_size: 50,
        }
    }
}

impl ReadBounds {
    pub fn new(max_pages: u16, max_items: usize, page_size: u16) -> Result<Self, ModelError> {
        if !(1..=MAX_PAGE_COUNT).contains(&max_pages) {
            return Err(ModelError::InvalidPageCount);
        }
        if !(1..=MAX_POLICY_ITEMS).contains(&max_items) {
            return Err(ModelError::InvalidItemCount);
        }
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(ModelError::InvalidPageSize);
        }
        Ok(Self {
            max_pages,
            max_items,
            page_size,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReadOperation {
    ListPolicies,
    GetPolicy,
    GetEffectivePolicy,
    ListAvailableConstraints,
}

impl ReadOperation {
    pub const ALL: [Self; 4] = [
        Self::ListPolicies,
        Self::GetPolicy,
        Self::GetEffectivePolicy,
        Self::ListAvailableConstraints,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicySource {
    Current,
    Inherited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyRuleMode {
    Enforced,
    DryRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyState {
    Current,
    Inherited,
    DryRun,
}

impl PolicyState {
    pub const fn from_parts(source: PolicySource, mode: PolicyRuleMode) -> Self {
        match mode {
            PolicyRuleMode::DryRun => Self::DryRun,
            PolicyRuleMode::Enforced => match source {
                PolicySource::Current => Self::Current,
                PolicySource::Inherited => Self::Inherited,
            },
        }
    }
}

/// Untrusted policy material is normalized at construction. Only digests of
/// values, members, etags and timestamps survive into the typed object.
pub struct UntrustedPolicy {
    resource: GcpResource,
    constraint: ConstraintId,
    policy_id: PolicyId,
    policy_revision: PolicyRevision,
    source: PolicySource,
    rule_mode: PolicyRuleMode,
    etag_digest: Digest,
    update_time_digest: Digest,
    rule_digest: Digest,
    policy_digest: Digest,
}

impl fmt::Debug for UntrustedPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedPolicy")
            .field("resource", &self.resource)
            .field("constraint", &self.constraint)
            .field("policy_id", &self.policy_id)
            .field("policy_revision", &self.policy_revision)
            .field("source", &self.source)
            .field("rule_mode", &self.rule_mode)
            .field("etag_digest", &self.etag_digest)
            .field("update_time_digest", &self.update_time_digest)
            .field("rule_digest", &self.rule_digest)
            .field("policy_digest", &self.policy_digest)
            .finish()
    }
}

impl UntrustedPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I, S>(
        resource: GcpResource,
        constraint: ConstraintId,
        policy_id: PolicyId,
        policy_revision: PolicyRevision,
        source: PolicySource,
        rule_mode: PolicyRuleMode,
        etag: impl AsRef<str>,
        update_time: impl AsRef<str>,
        raw_rule_values: impl AsRef<str>,
        raw_members: I,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let etag = etag.as_ref();
        let update_time = update_time.as_ref();
        let raw_rule_values = raw_rule_values.as_ref();
        validate_text(etag, "policy etag", MAX_IDENTIFIER_BYTES)?;
        validate_text(update_time, "policy update time", MAX_IDENTIFIER_BYTES)?;
        validate_text(
            raw_rule_values,
            "policy rule values",
            MAX_RESOURCE_NAME_BYTES,
        )?;
        let mut members_digest_input = String::new();
        for (index, member) in raw_members.into_iter().enumerate() {
            let member = member.as_ref();
            validate_text(member, "policy member", MAX_RESOURCE_NAME_BYTES)?;
            if index > 0 {
                members_digest_input.push('\u{1f}');
            }
            members_digest_input.push_str(member);
        }
        let etag_digest = Digest::from_text(etag);
        let update_time_digest = Digest::from_text(update_time);
        let values_digest = Digest::from_text(raw_rule_values);
        let members_digest = Digest::from_text(members_digest_input);
        let rule_digest = Digest::from_parts(
            "gcp-org-policy-rule/v1",
            &[
                ("values", values_digest.as_str().to_owned()),
                ("members", members_digest.as_str().to_owned()),
            ],
        );
        let policy_digest = Digest::from_parts(
            "gcp-org-policy/v1",
            &[
                ("resource", resource.canonical_name()),
                ("constraint", constraint.as_str().to_owned()),
                ("policy", policy_id.as_str().to_owned()),
                ("revision", policy_revision.get().to_string()),
                ("source", format!("{source:?}")),
                ("mode", format!("{rule_mode:?}")),
                ("etag", etag_digest.as_str().to_owned()),
                ("update_time", update_time_digest.as_str().to_owned()),
                ("rule", rule_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            resource,
            constraint,
            policy_id,
            policy_revision,
            source,
            rule_mode,
            etag_digest,
            update_time_digest,
            rule_digest,
            policy_digest,
        })
    }

    pub fn into_summary(self) -> PolicySummary {
        PolicySummary {
            resource: self.resource,
            constraint: self.constraint,
            policy_id: self.policy_id,
            policy_revision: self.policy_revision,
            source: self.source,
            rule_mode: self.rule_mode,
            state: PolicyState::from_parts(self.source, self.rule_mode),
            etag_digest: self.etag_digest,
            update_time_digest: self.update_time_digest,
            rule_digest: self.rule_digest,
            policy_digest: self.policy_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    pub resource: GcpResource,
    pub constraint: ConstraintId,
    pub policy_id: PolicyId,
    pub policy_revision: PolicyRevision,
    pub source: PolicySource,
    pub rule_mode: PolicyRuleMode,
    pub state: PolicyState,
    pub etag_digest: Digest,
    pub update_time_digest: Digest,
    pub rule_digest: Digest,
    pub policy_digest: Digest,
}

impl PolicySummary {
    #[allow(clippy::too_many_arguments)]
    pub fn from_digests(
        resource: GcpResource,
        constraint: ConstraintId,
        policy_id: PolicyId,
        policy_revision: PolicyRevision,
        source: PolicySource,
        rule_mode: PolicyRuleMode,
        etag_digest: Digest,
        update_time_digest: Digest,
        rule_digest: Digest,
    ) -> Self {
        let state = PolicyState::from_parts(source, rule_mode);
        let policy_digest = Digest::from_parts(
            "gcp-org-policy/v1",
            &[
                ("resource", resource.canonical_name()),
                ("constraint", constraint.as_str().to_owned()),
                ("policy", policy_id.as_str().to_owned()),
                ("revision", policy_revision.get().to_string()),
                ("source", format!("{source:?}")),
                ("mode", format!("{rule_mode:?}")),
                ("etag", etag_digest.as_str().to_owned()),
                ("update_time", update_time_digest.as_str().to_owned()),
                ("rule", rule_digest.as_str().to_owned()),
            ],
        );
        Self {
            resource,
            constraint,
            policy_id,
            policy_revision,
            source,
            rule_mode,
            state,
            etag_digest,
            update_time_digest,
            rule_digest,
            policy_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.state != PolicyState::from_parts(self.source, self.rule_mode) {
            return Err(ModelError::Invalid {
                field: "policy state",
            });
        }
        let expected = Self::from_digests(
            self.resource.clone(),
            self.constraint.clone(),
            self.policy_id.clone(),
            self.policy_revision,
            self.source,
            self.rule_mode,
            self.etag_digest.clone(),
            self.update_time_digest.clone(),
            self.rule_digest.clone(),
        );
        if expected.policy_digest != self.policy_digest {
            return Err(ModelError::Invalid {
                field: "policy digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    Managed,
    Custom,
}

pub struct UntrustedAvailableConstraint {
    constraint: ConstraintId,
    revision: Revision,
    kind: ConstraintKind,
    definition_digest: Digest,
}

impl fmt::Debug for UntrustedAvailableConstraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedAvailableConstraint")
            .field("constraint", &self.constraint)
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .field("definition_digest", &self.definition_digest)
            .finish()
    }
}

impl UntrustedAvailableConstraint {
    pub fn new(
        constraint: ConstraintId,
        revision: Revision,
        kind: ConstraintKind,
        raw_definition: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        validate_text(
            raw_definition.as_ref(),
            "constraint definition",
            MAX_RESOURCE_NAME_BYTES,
        )?;
        Ok(Self {
            constraint,
            revision,
            kind,
            definition_digest: Digest::from_text(raw_definition.as_ref().as_bytes()),
        })
    }

    pub fn into_summary(self) -> AvailableConstraintSummary {
        AvailableConstraintSummary {
            constraint: self.constraint,
            revision: self.revision,
            kind: self.kind,
            definition_digest: self.definition_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableConstraintSummary {
    pub constraint: ConstraintId,
    pub revision: Revision,
    pub kind: ConstraintKind,
    pub definition_digest: Digest,
}

impl AvailableConstraintSummary {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.constraint.as_str().is_empty() || self.definition_digest.as_str().len() != 64 {
            Err(ModelError::Invalid {
                field: "available constraint",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub page_token_digests: Vec<Digest>,
    pub next_page_token_digest: Option<Digest>,
    pub request_digests: Vec<Digest>,
    pub pagination_digest: Digest,
}

impl PaginationEvidence {
    pub fn new(
        pages_observed: u16,
        items_observed: usize,
        complete: bool,
        page_token_digests: Vec<Digest>,
        next_page_token_digest: Option<Digest>,
        request_digests: Vec<Digest>,
    ) -> Self {
        let pagination_digest = Digest::from_parts(
            "gcp-org-policy-pagination/v1",
            &[
                ("pages", pages_observed.to_string()),
                ("items", items_observed.to_string()),
                ("complete", complete.to_string()),
                (
                    "tokens",
                    page_token_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_page_token_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "requests",
                    request_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            pages_observed,
            items_observed,
            complete,
            page_token_digests,
            next_page_token_digest,
            request_digests,
            pagination_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_policy_values_removed: bool,
    pub raw_policy_members_removed: bool,
    pub raw_constraint_definition_removed: bool,
    pub pii_removed: bool,
    pub secret_material_removed: bool,
    pub raw_page_tokens_removed: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            raw_policy_values_removed: true,
            raw_policy_members_removed: true,
            raw_constraint_definition_removed: true,
            pii_removed: true,
            secret_material_removed: true,
            raw_page_tokens_removed: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub pagination_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    ReviewOnly,
}
