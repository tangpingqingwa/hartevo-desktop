//! Typed, bounded and redacted models for the Layer-1 Spanner management seam.
//!
//! The public evidence model has no representation for SQL, sessions, DDL,
//! DML, rows, schemas, IAM policies, labels, endpoints, key names, or
//! descriptions. Resource identifiers are retained only inside typed request
//! values and serialize as digests.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE};

pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 8;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque page token")]
    InvalidCursor { field: &'static str },
    #[error("{field} is outside the Layer-1 bound")]
    OutOfBounds { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} has an invalid timestamp ordering")]
    InvalidTimestamp { field: &'static str },
    #[error("the permission snapshot is empty or contains a forbidden permission")]
    InvalidPermissions,
    #[error("the secret reference is invalid, revoked, or not scope-bound")]
    InvalidSecretReference,
    #[error("the registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._:/+-@".contains(&byte)))
    {
        Err(ModelError::InvalidIdentifier { field })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &Digest, field: &'static str) -> Result<(), ModelError> {
    if value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field })
    }
}

fn validate_timestamp_order(
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    field: &'static str,
) -> Result<(), ModelError> {
    if created_at <= updated_at {
        Ok(())
    } else {
        Err(ModelError::InvalidTimestamp { field })
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let digest = Self(value);
        validate_digest(&digest, "digest")?;
        Ok(digest)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).unwrap_or_default())
}

macro_rules! bounded_identifier {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("gcp-spanner-", $label, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<(), ModelError> {
                validate_identifier(&self.0, $label)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.digest().as_str())
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

bounded_identifier!(OrganizationId, "organization-id");
bounded_identifier!(FolderId, "folder-id");
bounded_identifier!(GcpProjectId, "gcp-project-id");
bounded_identifier!(InstanceId, "instance-id");
bounded_identifier!(DatabaseId, "database-id");
bounded_identifier!(InstanceConfigId, "instance-config-id");
bounded_identifier!(OperationId, "operation-id");
bounded_identifier!(MissionId, "mission-id");
bounded_identifier!(WorkProductId, "work-product-id");

pub type GcpOrganizationId = OrganizationId;
pub type GcpFolderId = FolderId;
pub type ProjectId = GcpProjectId;
pub type GcpInstanceId = InstanceId;
pub type SpannerInstanceId = InstanceId;
pub type SpannerDatabaseId = DatabaseId;
pub type SpannerInstanceConfigId = InstanceConfigId;
pub type LongRunningOperationId = OperationId;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: GcpProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: GcpProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-project-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()
    }
}

pub type ProjectIdentity = ProjectBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-mission-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()
    }
}

pub type MissionIdentity = MissionBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-work-product-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()
    }
}

pub type WorkProductIdentity = WorkProductBinding;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpannerDialect {
    GoogleStandardSql,
    PostgreSql,
}

impl SpannerDialect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleStandardSql => "GOOGLE_STANDARD_SQL",
            Self::PostgreSql => "POSTGRESQL",
        }
    }

    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        match value.as_ref() {
            "GOOGLE_STANDARD_SQL" | "google_standard_sql" => Ok(Self::GoogleStandardSql),
            "POSTGRESQL" | "postgresql" => Ok(Self::PostgreSql),
            _ => Err(ModelError::Invalid {
                field: "database dialect",
            }),
        }
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

pub type DatabaseDialect = SpannerDialect;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpannerInstanceState {
    Creating,
    Ready,
    Updating,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpannerDatabaseState {
    Creating,
    Ready,
    Updating,
    Restoring,
    BackingUp,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpannerOperationState {
    Pending,
    Running,
    Done,
    Failed,
    Cancelled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Oauth,
    ServiceAccount,
}

impl SecretKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth2",
            Self::ServiceAccount => "service_account",
        }
    }
}

/// Opaque OAuth or service-account handle. The caller-supplied material is
/// hashed and zeroized immediately; `SecretReference` deliberately does not
/// implement `Serialize` or `Display`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::unbound(SecretKind::Oauth, opaque_handle, revision)
    }

    pub fn oauth(
        opaque_handle: impl Into<String>,
        scope: &GcpSpannerDatabaseScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::bound(SecretKind::Oauth, opaque_handle, scope, revision)
    }

    pub fn service_account(
        opaque_handle: impl Into<String>,
        scope: &GcpSpannerDatabaseScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::bound(SecretKind::ServiceAccount, opaque_handle, scope, revision)
    }

    fn unbound(
        kind: SecretKind,
        opaque_handle: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let mut handle = opaque_handle.into();
        let revision = Revision::new(revision)?;
        if handle.is_empty()
            || handle.len() > MAX_IDENTIFIER_BYTES
            || handle.trim() != handle
            || handle.chars().any(char::is_control)
        {
            handle.zeroize();
            return Err(ModelError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "gcp-spanner-opaque-secret-reference/v1",
            &[
                ("kind", kind.as_str().to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.get().to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind,
            reference_digest,
            scope_digest: Digest::from_text("unbound-gcp-spanner-secret-scope"),
            revision,
            revoked: false,
        })
    }

    fn bound(
        kind: SecretKind,
        opaque_handle: impl Into<String>,
        scope: &GcpSpannerDatabaseScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let mut reference = Self::unbound(kind, opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "gcp-spanner-opaque-secret-reference/v1",
            &[
                ("kind", kind.as_str().to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", reference.revision.get().to_string()),
            ],
        );
        Ok(reference)
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
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
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &GcpSpannerDatabaseScope) -> Result<(), ModelError> {
        if self.revision.get() == 0 || self.revoked || self.scope_digest != scope.digest() {
            return Err(ModelError::InvalidSecretReference);
        }
        validate_digest(&self.reference_digest, "secret reference digest")
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpSpannerPermission {
    InstancesGet,
    DatabasesGet,
    OperationsGet,
    InstancesList,
    DatabasesList,
    MissionScope,
}

impl GcpSpannerPermission {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InstancesGet => "spanner.instances.get",
            Self::DatabasesGet => "spanner.databases.get",
            Self::OperationsGet => "spanner.operations.get",
            Self::InstancesList => "spanner.instances.list",
            Self::DatabasesList => "spanner.databases.list",
            Self::MissionScope => "mission.scope",
        }
    }
}

impl Ord for GcpSpannerPermission {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for GcpSpannerPermission {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: BTreeSet<GcpSpannerPermission>,
    revision: Revision,
}

impl PermissionSnapshot {
    pub fn least_privilege(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                GcpSpannerPermission::InstancesGet,
                GcpSpannerPermission::DatabasesGet,
                GcpSpannerPermission::OperationsGet,
                GcpSpannerPermission::InstancesList,
                GcpSpannerPermission::DatabasesList,
                GcpSpannerPermission::MissionScope,
            ],
            revision,
        )
    }

    pub fn new(
        permissions: impl IntoIterator<Item = GcpSpannerPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let snapshot = Self {
            permissions,
            revision: Revision::new(revision)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<GcpSpannerPermission> {
        &self.permissions
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-permission-snapshot/v1",
            &[
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .map(GcpSpannerPermission::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if self.permissions.is_empty()
            || !self
                .permissions
                .contains(&GcpSpannerPermission::InstancesGet)
            || !self
                .permissions
                .contains(&GcpSpannerPermission::DatabasesGet)
            || !self
                .permissions
                .contains(&GcpSpannerPermission::MissionScope)
        {
            return Err(ModelError::InvalidPermissions);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSelector {
    pub operation: Option<OperationId>,
}

impl From<OperationId> for OperationSelector {
    fn from(operation: OperationId) -> Self {
        Self {
            operation: Some(operation),
        }
    }
}

impl From<Option<OperationId>> for OperationSelector {
    fn from(operation: Option<OperationId>) -> Self {
        Self { operation }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GcpSpannerDatabaseScope {
    organization: OrganizationId,
    folder: FolderId,
    project: GcpProjectId,
    instance: InstanceId,
    database: DatabaseId,
    dialect: SpannerDialect,
    instance_config: InstanceConfigId,
    operation: OperationSelector,
    project_binding: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
}

impl GcpSpannerDatabaseScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new<O: Into<OperationSelector>>(
        organization: OrganizationId,
        folder: FolderId,
        project: GcpProjectId,
        instance: InstanceId,
        database: DatabaseId,
        dialect: SpannerDialect,
        instance_config: InstanceConfigId,
        operation: O,
        project_binding: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            organization,
            folder,
            project,
            instance,
            database,
            dialect,
            instance_config,
            operation: operation.into(),
            project_binding,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    #[must_use]
    pub fn folder(&self) -> &FolderId {
        &self.folder
    }

    #[must_use]
    pub fn project(&self) -> &GcpProjectId {
        &self.project
    }

    #[must_use]
    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }

    #[must_use]
    pub fn database(&self) -> &DatabaseId {
        &self.database
    }

    #[must_use]
    pub const fn dialect(&self) -> SpannerDialect {
        self.dialect
    }

    #[must_use]
    pub fn instance_config(&self) -> &InstanceConfigId {
        &self.instance_config
    }

    #[must_use]
    pub fn operation(&self) -> Option<&OperationId> {
        self.operation.operation.as_ref()
    }

    #[must_use]
    pub fn project_binding(&self) -> &ProjectBinding {
        &self.project_binding
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
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-database-scope/v1",
            &[
                (
                    "organization",
                    self.organization.digest().as_str().to_owned(),
                ),
                ("folder", self.folder.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
                ("database", self.database.digest().as_str().to_owned()),
                ("dialect", self.dialect.digest().as_str().to_owned()),
                (
                    "instance_config",
                    self.instance_config.digest().as_str().to_owned(),
                ),
                (
                    "operation",
                    self.operation
                        .operation
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "project_binding",
                    self.project_binding.digest().as_str().to_owned(),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        self.organization.validate()?;
        self.folder.validate()?;
        self.project.validate()?;
        self.instance.validate()?;
        self.database.validate()?;
        self.instance_config.validate()?;
        if let Some(operation) = &self.operation.operation {
            operation.validate()?;
        }
        self.project_binding.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

impl Serialize for GcpSpannerDatabaseScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GcpSpannerDatabaseScope", 11)?;
        state.serialize_field("organizationDigest", &self.organization.digest())?;
        state.serialize_field("folderDigest", &self.folder.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("instanceDigest", &self.instance.digest())?;
        state.serialize_field("databaseDigest", &self.database.digest())?;
        state.serialize_field("dialect", &self.dialect)?;
        state.serialize_field("instanceConfigDigest", &self.instance_config.digest())?;
        state.serialize_field(
            "operationDigest",
            &self.operation.operation.as_ref().map(OperationId::digest),
        )?;
        state.serialize_field("projectBindingDigest", &self.project_binding.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.end()
    }
}

impl fmt::Debug for GcpSpannerDatabaseScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpSpannerDatabaseScope")
            .field("digest", &self.digest())
            .field("dialect", &self.dialect)
            .field("operation_present", &self.operation.operation.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationPosture {
    pub encrypted: bool,
    pub encryption_key_reference_digest: Option<Digest>,
    pub configuration_digest: Digest,
    pub instance_config_digest: Digest,
    pub posture_digest: Digest,
}

impl ConfigurationPosture {
    pub fn new(
        encrypted: bool,
        encryption_key_reference_digest: Option<Digest>,
        configuration_digest: Digest,
        instance_config_digest: Digest,
    ) -> Result<Self, ModelError> {
        validate_digest(&configuration_digest, "configuration digest")?;
        validate_digest(&instance_config_digest, "instance config digest")?;
        if let Some(digest) = &encryption_key_reference_digest {
            validate_digest(digest, "encryption key reference digest")?;
        }
        let posture_digest = Digest::from_parts(
            "gcp-spanner-configuration-posture/v1",
            &[
                ("encrypted", encrypted.to_string()),
                (
                    "encryption_key",
                    encryption_key_reference_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("configuration", configuration_digest.as_str().to_owned()),
                (
                    "instance_config",
                    instance_config_digest.as_str().to_owned(),
                ),
            ],
        );
        Ok(Self {
            encrypted,
            encryption_key_reference_digest,
            configuration_digest,
            instance_config_digest,
            posture_digest,
        })
    }

    pub fn from_raw(
        encrypted: bool,
        encryption_key_name: Option<&str>,
        configuration_reference: &str,
        instance_config: &InstanceConfigId,
    ) -> Result<Self, ModelError> {
        let encryption_key_reference_digest = encryption_key_name.map(|key_name| {
            Digest::from_parts(
                "gcp-spanner-encryption-key-reference/v1",
                &[("key_name", key_name.to_owned())],
            )
        });
        Self::new(
            encrypted,
            encryption_key_reference_digest,
            Digest::from_parts(
                "gcp-spanner-configuration-reference/v1",
                &[("reference", configuration_reference.to_owned())],
            ),
            instance_config.digest(),
        )
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.posture_digest
    }

    pub(crate) fn validate_against(
        &self,
        scope: &GcpSpannerDatabaseScope,
    ) -> Result<(), ModelError> {
        if self.instance_config_digest != scope.instance_config.digest() {
            return Err(ModelError::ScopeMismatch {
                field: "instance config",
            });
        }
        validate_digest(&self.posture_digest, "configuration posture digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceMetadataInput {
    pub instance: InstanceId,
    pub state: SpannerInstanceState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub configuration: ConfigurationPosture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceMetadata {
    pub instance: InstanceId,
    pub state: SpannerInstanceState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub configuration: ConfigurationPosture,
    pub metadata_digest: Digest,
}

impl InstanceMetadata {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        input: InstanceMetadataInput,
    ) -> Result<Self, ModelError> {
        if input.instance != scope.instance {
            return Err(ModelError::ScopeMismatch { field: "instance" });
        }
        validate_timestamp_order(input.created_at, input.updated_at, "instance")?;
        input.configuration.validate_against(scope)?;
        let metadata_digest = Digest::from_parts(
            "gcp-spanner-instance-metadata/v1",
            &[
                ("instance", input.instance.digest().as_str().to_owned()),
                ("state", format!("{:?}", input.state)),
                ("created", input.created_at.to_rfc3339()),
                ("updated", input.updated_at.to_rfc3339()),
                (
                    "configuration",
                    input.configuration.digest().as_str().to_owned(),
                ),
            ],
        );
        Ok(Self {
            instance: input.instance,
            state: input.state,
            created_at: input.created_at,
            updated_at: input.updated_at,
            configuration: input.configuration,
            metadata_digest,
        })
    }

    pub fn validate_against(&self, scope: &GcpSpannerDatabaseScope) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            scope,
            InstanceMetadataInput {
                instance: self.instance.clone(),
                state: self.state,
                created_at: self.created_at,
                updated_at: self.updated_at,
                configuration: self.configuration.clone(),
            },
        )?;
        if rebuilt.metadata_digest != self.metadata_digest {
            return Err(ModelError::Invalid {
                field: "instance metadata digest",
            });
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = Digest::from_parts(
            "gcp-spanner-instance-metadata/v1",
            &[
                ("instance", self.instance.digest().as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("created", self.created_at.to_rfc3339()),
                ("updated", self.updated_at.to_rfc3339()),
                (
                    "configuration",
                    self.configuration.digest().as_str().to_owned(),
                ),
            ],
        );
        if expected == self.metadata_digest {
            Ok(())
        } else {
            Err(ModelError::Invalid {
                field: "instance metadata digest",
            })
        }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseMetadataInput {
    pub project: GcpProjectId,
    pub instance: InstanceId,
    pub database: DatabaseId,
    pub dialect: SpannerDialect,
    pub state: SpannerDatabaseState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub configuration: ConfigurationPosture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseMetadata {
    pub project: GcpProjectId,
    pub instance: InstanceId,
    pub database: DatabaseId,
    pub dialect: SpannerDialect,
    pub state: SpannerDatabaseState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub configuration: ConfigurationPosture,
    pub metadata_digest: Digest,
}

impl DatabaseMetadata {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        input: DatabaseMetadataInput,
    ) -> Result<Self, ModelError> {
        if input.project != scope.project {
            return Err(ModelError::ScopeMismatch { field: "project" });
        }
        if input.instance != scope.instance {
            return Err(ModelError::ScopeMismatch { field: "instance" });
        }
        if input.database != scope.database {
            return Err(ModelError::ScopeMismatch { field: "database" });
        }
        if input.dialect != scope.dialect {
            return Err(ModelError::ScopeMismatch {
                field: "database dialect",
            });
        }
        validate_timestamp_order(input.created_at, input.updated_at, "database")?;
        input.configuration.validate_against(scope)?;
        let metadata_digest = Digest::from_parts(
            "gcp-spanner-database-metadata/v1",
            &[
                ("project", input.project.digest().as_str().to_owned()),
                ("instance", input.instance.digest().as_str().to_owned()),
                ("database", input.database.digest().as_str().to_owned()),
                ("dialect", input.dialect.as_str().to_owned()),
                ("state", format!("{:?}", input.state)),
                ("created", input.created_at.to_rfc3339()),
                ("updated", input.updated_at.to_rfc3339()),
                (
                    "configuration",
                    input.configuration.digest().as_str().to_owned(),
                ),
            ],
        );
        Ok(Self {
            project: input.project,
            instance: input.instance,
            database: input.database,
            dialect: input.dialect,
            state: input.state,
            created_at: input.created_at,
            updated_at: input.updated_at,
            configuration: input.configuration,
            metadata_digest,
        })
    }

    pub fn validate_against(&self, scope: &GcpSpannerDatabaseScope) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            scope,
            DatabaseMetadataInput {
                project: self.project.clone(),
                instance: self.instance.clone(),
                database: self.database.clone(),
                dialect: self.dialect,
                state: self.state,
                created_at: self.created_at,
                updated_at: self.updated_at,
                configuration: self.configuration.clone(),
            },
        )?;
        if rebuilt.metadata_digest != self.metadata_digest {
            return Err(ModelError::Invalid {
                field: "database metadata digest",
            });
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = Digest::from_parts(
            "gcp-spanner-database-metadata/v1",
            &[
                ("project", self.project.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
                ("database", self.database.digest().as_str().to_owned()),
                ("dialect", self.dialect.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("created", self.created_at.to_rfc3339()),
                ("updated", self.updated_at.to_rfc3339()),
                (
                    "configuration",
                    self.configuration.digest().as_str().to_owned(),
                ),
            ],
        );
        if expected == self.metadata_digest {
            Ok(())
        } else {
            Err(ModelError::Invalid {
                field: "database metadata digest",
            })
        }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationMetadataInput {
    pub operation: OperationId,
    pub database: DatabaseId,
    pub state: SpannerOperationState,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_digest: Option<Digest>,
}

impl OperationMetadataInput {
    pub fn new(
        operation: OperationId,
        database: DatabaseId,
        state: SpannerOperationState,
        started_at: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
        error_message: Option<&str>,
    ) -> Result<Self, ModelError> {
        let error_digest = error_message.map(|message| {
            Digest::from_parts(
                "gcp-spanner-operation-error/v1",
                &[("message", message.to_owned())],
            )
        });
        if let Some(completed_at) = completed_at {
            if completed_at < started_at {
                return Err(ModelError::InvalidTimestamp { field: "operation" });
            }
        }
        Ok(Self {
            operation,
            database,
            state,
            started_at,
            completed_at,
            error_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationMetadata {
    pub operation: OperationId,
    pub database: DatabaseId,
    pub state: SpannerOperationState,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl OperationMetadata {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        input: OperationMetadataInput,
    ) -> Result<Self, ModelError> {
        let expected_operation = scope
            .operation
            .operation
            .as_ref()
            .ok_or(ModelError::ScopeMismatch { field: "operation" })?;
        if input.operation != *expected_operation {
            return Err(ModelError::ScopeMismatch { field: "operation" });
        }
        if input.database != scope.database {
            return Err(ModelError::ScopeMismatch { field: "database" });
        }
        if let Some(completed_at) = input.completed_at {
            if completed_at < input.started_at {
                return Err(ModelError::InvalidTimestamp { field: "operation" });
            }
        }
        let metadata_digest = Digest::from_parts(
            "gcp-spanner-operation-metadata/v1",
            &[
                ("operation", input.operation.digest().as_str().to_owned()),
                ("database", input.database.digest().as_str().to_owned()),
                ("state", format!("{:?}", input.state)),
                ("started", input.started_at.to_rfc3339()),
                (
                    "completed",
                    input
                        .completed_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "error",
                    input
                        .error_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            operation: input.operation,
            database: input.database,
            state: input.state,
            started_at: input.started_at,
            completed_at: input.completed_at,
            error_digest: input.error_digest,
            metadata_digest,
        })
    }

    pub fn validate_against(&self, scope: &GcpSpannerDatabaseScope) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            scope,
            OperationMetadataInput {
                operation: self.operation.clone(),
                database: self.database.clone(),
                state: self.state,
                started_at: self.started_at,
                completed_at: self.completed_at,
                error_digest: self.error_digest.clone(),
            },
        )?;
        if rebuilt.metadata_digest != self.metadata_digest {
            return Err(ModelError::Invalid {
                field: "operation metadata digest",
            });
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = Digest::from_parts(
            "gcp-spanner-operation-metadata/v1",
            &[
                ("operation", self.operation.digest().as_str().to_owned()),
                ("database", self.database.digest().as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("started", self.started_at.to_rfc3339()),
                (
                    "completed",
                    self.completed_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        if expected == self.metadata_digest {
            Ok(())
        } else {
            Err(ModelError::Invalid {
                field: "operation metadata digest",
            })
        }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceListItem {
    pub instance: InstanceId,
    pub state: SpannerInstanceState,
    pub item_digest: Digest,
}

impl InstanceListItem {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        instance: InstanceId,
        state: SpannerInstanceState,
    ) -> Result<Self, ModelError> {
        if instance != scope.instance {
            return Err(ModelError::ScopeMismatch { field: "instance" });
        }
        let item_digest = Digest::from_parts(
            "gcp-spanner-instance-list-item/v1",
            &[
                ("instance", instance.digest().as_str().to_owned()),
                ("state", format!("{:?}", state)),
            ],
        );
        Ok(Self {
            instance,
            state,
            item_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = Digest::from_parts(
            "gcp-spanner-instance-list-item/v1",
            &[
                ("instance", self.instance.digest().as_str().to_owned()),
                ("state", format!("{state:?}", state = self.state)),
            ],
        );
        if expected == self.item_digest {
            Ok(())
        } else {
            Err(ModelError::Invalid {
                field: "instance list item digest",
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseListItem {
    pub project: GcpProjectId,
    pub instance: InstanceId,
    pub database: DatabaseId,
    pub dialect: SpannerDialect,
    pub state: SpannerDatabaseState,
    pub item_digest: Digest,
}

impl DatabaseListItem {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        project: GcpProjectId,
        instance: InstanceId,
        database: DatabaseId,
        dialect: SpannerDialect,
        state: SpannerDatabaseState,
    ) -> Result<Self, ModelError> {
        if project != scope.project {
            return Err(ModelError::ScopeMismatch { field: "project" });
        }
        if instance != scope.instance {
            return Err(ModelError::ScopeMismatch { field: "instance" });
        }
        if database != scope.database {
            return Err(ModelError::ScopeMismatch { field: "database" });
        }
        if dialect != scope.dialect {
            return Err(ModelError::ScopeMismatch {
                field: "database dialect",
            });
        }
        let item_digest = Digest::from_parts(
            "gcp-spanner-database-list-item/v1",
            &[
                ("project", project.digest().as_str().to_owned()),
                ("instance", instance.digest().as_str().to_owned()),
                ("database", database.digest().as_str().to_owned()),
                ("dialect", dialect.as_str().to_owned()),
                ("state", format!("{:?}", state)),
            ],
        );
        Ok(Self {
            project,
            instance,
            database,
            dialect,
            state,
            item_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = Digest::from_parts(
            "gcp-spanner-database-list-item/v1",
            &[
                ("project", self.project.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
                ("database", self.database.digest().as_str().to_owned()),
                ("dialect", self.dialect.as_str().to_owned()),
                ("state", format!("{state:?}", state = self.state)),
            ],
        );
        if expected == self.item_digest {
            Ok(())
        } else {
            Err(ModelError::Invalid {
                field: "database list item digest",
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaquePageToken {
    token_digest: Digest,
    scope_digest: Digest,
    parent_digest: Digest,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        raw_token: impl Into<String>,
        scope: &GcpSpannerDatabaseScope,
        parent_digest: Digest,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let mut raw_token = raw_token.into();
        if raw_token.is_empty()
            || raw_token.len() > MAX_CURSOR_BYTES
            || raw_token.trim() != raw_token
            || raw_token.chars().any(char::is_control)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            raw_token.zeroize();
            return Err(ModelError::InvalidCursor {
                field: "page token",
            });
        }
        validate_digest(&parent_digest, "page token parent digest")?;
        let token_digest = Digest::from_parts(
            "gcp-spanner-opaque-page-token/v1",
            &[
                ("token", raw_token.clone()),
                ("scope", scope.digest().as_str().to_owned()),
                ("parent", parent_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
            ],
        );
        raw_token.zeroize();
        Ok(Self {
            token_digest,
            scope_digest: scope.digest(),
            parent_digest,
            page_number,
        })
    }

    #[must_use]
    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn parent_digest(&self) -> &Digest {
        &self.parent_digest
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(
        &self,
        scope: &GcpSpannerDatabaseScope,
        parent_digest: &Digest,
        expected_page: u16,
    ) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.parent_digest != *parent_digest
            || self.page_number != expected_page
        {
            return Err(ModelError::ScopeMismatch {
                field: "page token",
            });
        }
        validate_digest(&self.token_digest, "page token digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub instance_digest: Option<Digest>,
    pub database_digest: Option<Digest>,
    pub operation_digest: Option<Digest>,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[must_use]
    pub fn calculate(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-evidence-digests/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                (
                    "contract_version",
                    self.contract_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "instance",
                    self.instance_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "database",
                    self.database_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "operation",
                    self.operation_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("request", self.request_digest.as_str().to_owned()),
                ("response", self.response_digest.as_str().to_owned()),
            ],
        )
    }
}

pub fn validate_response_bytes(response_bytes: u64) -> Result<(), ModelError> {
    if response_bytes <= crate::MAX_RESPONSE_BYTES {
        Ok(())
    } else {
        Err(ModelError::OutOfBounds {
            field: "response bytes",
        })
    }
}

pub fn validate_page_size(page_size: u16) -> Result<(), ModelError> {
    if (1..=MAX_PAGE_SIZE).contains(&page_size) {
        Ok(())
    } else {
        Err(ModelError::OutOfBounds { field: "page size" })
    }
}
