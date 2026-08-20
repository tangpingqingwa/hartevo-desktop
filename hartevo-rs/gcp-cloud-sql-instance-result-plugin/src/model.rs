use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    API_REVISION, BLOCKED_ENV, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_VERSION, PROVIDER_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_OPERATION_ERROR_CATEGORIES: usize = 8;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid: {field}")]
    InvalidScope { field: &'static str },
    #[error("permission fence does not contain the Layer-1 read allowlist")]
    InvalidPermissionFence,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("response is empty or exceeds the Layer-1 byte ceiling")]
    InvalidResponseBytes,
    #[error("opaque page token is empty, too large, or incorrectly bound")]
    InvalidPageToken,
    #[error("timestamp is invalid")]
    InvalidTimestamp,
    #[error("duplicate or out-of-order instance evidence")]
    DuplicateEvidence,
    #[error("evidence digest does not match its immutable fields")]
    DigestMismatch,
    #[error("operation status regressed")]
    OperationRegression,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("secret reference was already revoked")]
    AlreadyRevoked,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already in a terminal state")]
    RegistrationTerminal,
}

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
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if is_digest(&self.0) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
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

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("gcp-cloud-sql-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }
    };
}

identifier!(OrganizationId, "organization");
identifier!(ProjectId, "cloud-project");
identifier!(InstanceId, "instance");
identifier!(Region, "region");
identifier!(DatabaseVersion, "database-version");
identifier!(DatabaseEdition, "database-edition");
identifier!(OperationId, "operation");
identifier!(MissionId, "mission");
identifier!(WorkProductId, "work-product");
identifier!(RegistrationId, "registration");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SettingsVersion(u64);

impl SettingsVersion {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    OAuth,
    ServiceAccount,
}

pub type GcpAuthKind = AuthKind;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    InstancesGet,
    InstancesList,
    OperationsGet,
    MissionScope,
}

impl PermissionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstancesGet => "cloudsql.instances.get",
            Self::InstancesList => "cloudsql.instances.list",
            Self::OperationsGet => "cloudsql.operations.get",
            Self::MissionScope => "mission.scope",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub revision: Revision,
    pub actions: BTreeSet<PermissionAction>,
    pub digest: Digest,
}

impl PermissionFence {
    pub fn new(
        revision: Revision,
        actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let actions = actions.into_iter().collect::<BTreeSet<_>>();
        if actions.is_empty() {
            return Err(ModelError::InvalidPermissionFence);
        }
        let digest = Digest::from_parts(
            "gcp-cloud-sql-permission-fence/v1",
            &[
                ("revision", revision.get().to_string()),
                (
                    "actions",
                    actions
                        .iter()
                        .map(|action| action.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Ok(Self {
            revision,
            actions,
            digest,
        })
    }

    pub fn read_only(revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            revision,
            [
                PermissionAction::InstancesGet,
                PermissionAction::InstancesList,
                PermissionAction::OperationsGet,
                PermissionAction::MissionScope,
            ],
        )
    }

    pub fn for_layer_one(revision: u64) -> Result<Self, ModelError> {
        Self::read_only(Revision::new(revision)?)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn allows_layer_one_reads(&self) -> bool {
        [
            PermissionAction::InstancesGet,
            PermissionAction::InstancesList,
            PermissionAction::OperationsGet,
            PermissionAction::MissionScope,
        ]
        .into_iter()
        .all(|action| self.actions.contains(&action))
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if self.actions.is_empty() || !self.allows_layer_one_reads() {
            return Err(ModelError::InvalidPermissionFence);
        }
        let expected = Self::new(self.revision, self.actions.clone())?;
        if self.digest != expected.digest {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    id: ProjectId,
    revision: Revision,
    digest: Digest,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        let digest = Digest::from_parts(
            "gcp-cloud-sql-project-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.get().to_string()),
            ],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

pub type ProjectScope = ProjectBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    id: MissionId,
    revision: Revision,
    digest: Digest,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        let digest = Digest::from_parts(
            "gcp-cloud-sql-mission-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.get().to_string()),
            ],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

pub type MissionScope = MissionBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    id: WorkProductId,
    revision: Revision,
    digest: Digest,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        let digest = Digest::from_parts(
            "gcp-cloud-sql-work-product-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.get().to_string()),
            ],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

pub type WorkProductScope = WorkProductBinding;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum OperationType {
    Create,
    Update,
    Delete,
    Restart,
    Failover,
    Backup,
    Restore,
    Unknown,
}

impl OperationType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Restart => "RESTART",
            Self::Failover => "FAILOVER",
            Self::Backup => "BACKUP",
            Self::Restore => "RESTORE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Pending,
    Running,
    Done,
    Failed,
    Unknown,
}

impl OperationStatus {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Running => 1,
            Self::Done | Self::Failed => 2,
            Self::Unknown => 0,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationBinding {
    id: OperationId,
    operation_type: OperationType,
    digest: Digest,
}

impl OperationBinding {
    pub fn new(id: OperationId, operation_type: OperationType) -> Self {
        let digest = Digest::from_parts(
            "gcp-cloud-sql-operation-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("type", operation_type.as_str().to_owned()),
            ],
        );
        Self {
            id,
            operation_type,
            digest,
        }
    }

    pub fn id(&self) -> &OperationId {
        &self.id
    }

    pub const fn operation_type(&self) -> OperationType {
        self.operation_type
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GcpCloudSqlInstanceScope {
    organization_id: OrganizationId,
    cloud_project_id: ProjectId,
    instance_id: InstanceId,
    region: Region,
    database_version: DatabaseVersion,
    settings_version: SettingsVersion,
    operation: OperationBinding,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission: PermissionFence,
    consent_digest: Digest,
    expected_topology_digest: Option<Digest>,
    scope_digest: Digest,
}

#[allow(clippy::too_many_arguments)]
impl GcpCloudSqlInstanceScope {
    pub fn new(
        organization_id: OrganizationId,
        cloud_project_id: ProjectId,
        instance_id: InstanceId,
        region: Region,
        database_version: DatabaseVersion,
        settings_version: SettingsVersion,
        operation: OperationBinding,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission: PermissionFence,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut scope = Self {
            organization_id,
            cloud_project_id,
            instance_id,
            region,
            database_version,
            settings_version,
            operation,
            project,
            mission,
            work_product,
            permission,
            consent_digest,
            expected_topology_digest: None,
            scope_digest: Digest::zero(),
        };
        scope.recompute_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_instance(
        organization_id: OrganizationId,
        cloud_project_id: ProjectId,
        instance_id: InstanceId,
        region: Region,
        database_version: DatabaseVersion,
        settings_version: SettingsVersion,
        operation: OperationBinding,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission: PermissionFence,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            organization_id,
            cloud_project_id,
            instance_id,
            region,
            database_version,
            settings_version,
            operation,
            project,
            mission,
            work_product,
            permission,
            consent_digest,
        )
    }

    pub fn with_topology_fence(mut self, topology_digest: Digest) -> Result<Self, ModelError> {
        topology_digest.validate()?;
        self.expected_topology_digest = Some(topology_digest);
        self.recompute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub fn cloud_project_id(&self) -> &ProjectId {
        &self.cloud_project_id
    }

    pub fn project_id(&self) -> &ProjectId {
        self.cloud_project_id()
    }

    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    pub fn region(&self) -> &Region {
        &self.region
    }

    pub fn database_version(&self) -> &DatabaseVersion {
        &self.database_version
    }

    pub const fn settings_version(&self) -> SettingsVersion {
        self.settings_version
    }

    pub fn operation(&self) -> &OperationBinding {
        &self.operation
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission.digest()
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn expected_topology_digest(&self) -> Option<&Digest> {
        self.expected_topology_digest.as_ref()
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        self.digest()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permission.validate()?;
        self.consent_digest.validate()?;
        if self.consent_digest.is_zero() {
            return Err(ModelError::InvalidScope {
                field: "consent digest",
            });
        }
        if self
            .expected_topology_digest
            .as_ref()
            .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(ModelError::InvalidDigest);
        }
        if self.scope_digest != self.calculate_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn recompute_digest(&mut self) {
        self.scope_digest = self.calculate_digest();
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-instance-scope/v1",
            &[
                (
                    "organization",
                    self.organization_id.digest().as_str().to_owned(),
                ),
                (
                    "cloud_project",
                    self.cloud_project_id.digest().as_str().to_owned(),
                ),
                ("instance", self.instance_id.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "database_version",
                    self.database_version.digest().as_str().to_owned(),
                ),
                ("settings_version", self.settings_version.get().to_string()),
                ("operation", self.operation.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("permission", self.permission.digest().as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                (
                    "topology",
                    self.expected_topology_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

impl fmt::Debug for GcpCloudSqlInstanceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudSqlInstanceScope")
            .field("organization_digest", &self.organization_id.digest())
            .field("cloud_project_digest", &self.cloud_project_id.digest())
            .field("instance_digest", &self.instance_id.digest())
            .field("region_digest", &self.region.digest())
            .field("database_version_digest", &self.database_version.digest())
            .field("settings_version", &self.settings_version)
            .field("operation_digest", &self.operation.digest())
            .field("project", &self.project.digest())
            .field("mission", &self.mission.digest())
            .field("work_product", &self.work_product.digest())
            .field("permission_digest", &self.permission.digest())
            .field("consent_digest", &self.consent_digest)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl Serialize for GcpCloudSqlInstanceScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GcpCloudSqlInstanceScope", 15)?;
        state.serialize_field("organizationDigest", &self.organization_id.digest())?;
        state.serialize_field("cloudProjectDigest", &self.cloud_project_id.digest())?;
        state.serialize_field("instanceDigest", &self.instance_id.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("databaseVersionDigest", &self.database_version.digest())?;
        state.serialize_field("settingsVersion", &self.settings_version)?;
        state.serialize_field("operationDigest", &self.operation.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.serialize_field("permissionDigest", &self.permission.digest())?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("expectedTopologyDigest", &self.expected_topology_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("layer", &EVIDENCE_LEVEL)?;
        state.end()
    }
}

pub type GcpCloudSqlScope = GcpCloudSqlInstanceScope;

/// Opaque reference to a host keyring entry. The raw reference id never lives
/// in this type, is never serialized, and is never included in Debug output.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: AuthKind,
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
        scope: &GcpCloudSqlInstanceScope,
        credential_revision: Revision,
        auth_kind: AuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier {
                field: "secret reference",
            });
        }
        scope.validate()?;
        let reference_digest = Digest::from_parts(
            "gcp-cloud-sql-secret-reference/v1",
            &[
                ("reference", reference_id),
                ("scope", scope.digest().as_str().to_owned()),
                ("revision", credential_revision.get().to_string()),
                ("auth_kind", format!("{auth_kind:?}")),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.digest().clone(),
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &GcpCloudSqlInstanceScope,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, scope, Revision::new(1)?, AuthKind::OAuth)
    }

    pub fn for_cloud_sql(
        reference_id: impl Into<String>,
        scope: &GcpCloudSqlInstanceScope,
    ) -> Result<Self, ModelError> {
        Self::for_scope(reference_id, scope)
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

    pub const fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub(crate) fn validate(&self, scope: &GcpCloudSqlInstanceScope) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::SecretRevoked);
        }
        if self.scope_digest != *scope.digest() {
            return Err(ModelError::InvalidScope {
                field: "secret reference scope",
            });
        }
        self.reference_digest.validate()
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

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        raw_token: impl Into<String>,
        binding_digest: Digest,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let raw_token = raw_token.into();
        if raw_token.is_empty()
            || raw_token.len() > MAX_IDENTIFIER_BYTES
            || page_number < 2
            || binding_digest.validate().is_err()
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "gcp-cloud-sql-page-token/v1",
                &[
                    ("token", raw_token),
                    ("binding", binding_digest.as_str().to_owned()),
                    ("page", page_number.to_string()),
                ],
            ),
            binding_digest,
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn digest(&self) -> &Digest {
        self.token_digest()
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaquePageToken", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => BLOCKED_ENV,
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

    pub const fn provider_receipt(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        self.connected()
    }

    pub const fn is_native(self) -> bool {
        self.native()
    }

    pub const fn is_first_party(self) -> bool {
        self.first_party()
    }
}

pub type TransportProvenance = ProviderProvenance;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    MalformedResponse,
    BlockedEnvironment,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    MissingPageToken,
    PageBudget,
    PageLoop,
    ResponseCap,
    DatabaseVersionDrift,
    SettingsVersionDrift,
    TopologyDrift,
    ReplicaDrift,
    OperationDrift,
    Conflict,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_category_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(kind: ProviderErrorKind, status_code: Option<u16>, category: &str) -> Self {
        Self {
            kind,
            status_code,
            error_category_digest: Digest::from_text(category),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstanceState {
    Runnable,
    Maintenance,
    Suspended,
    Failed,
    PendingCreate,
    PendingDelete,
    Unknown,
}

impl InstanceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runnable => "RUNNABLE",
            Self::Maintenance => "MAINTENANCE",
            Self::Suspended => "SUSPENDED",
            Self::Failed => "FAILED",
            Self::PendingCreate => "PENDING_CREATE",
            Self::PendingDelete => "PENDING_DELETE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityType {
    Zonal,
    Regional,
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPolicySummary {
    pub enabled: bool,
    pub point_in_time_recovery: bool,
    pub retained_backup_count: Option<u16>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenancePolicySummary {
    pub window_present: bool,
    pub version_digest: Option<Digest>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageSummary {
    pub disk_size_bytes: Option<u64>,
    pub storage_auto_resize: bool,
    pub storage_auto_resize_limit_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceSnapshotInput {
    pub state: InstanceState,
    pub database_version: DatabaseVersion,
    pub edition: Option<DatabaseEdition>,
    pub zone_digest: Option<Digest>,
    pub availability_type: AvailabilityType,
    pub replica_count: u16,
    pub read_replica_count: u16,
    pub high_availability: bool,
    pub settings_version: SettingsVersion,
    pub backup: BackupPolicySummary,
    pub maintenance: MaintenancePolicySummary,
    pub storage: StorageSummary,
    pub observed_at: DateTime<Utc>,
}

impl InstanceSnapshotInput {
    pub fn minimal(
        state: InstanceState,
        database_version: DatabaseVersion,
        settings_version: SettingsVersion,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            state,
            database_version,
            edition: None,
            zone_digest: None,
            availability_type: AvailabilityType::Unknown,
            replica_count: 0,
            read_replica_count: 0,
            high_availability: false,
            settings_version,
            backup: BackupPolicySummary::default(),
            maintenance: MaintenancePolicySummary::default(),
            storage: StorageSummary::default(),
            observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSqlInstanceSnapshot {
    pub project_digest: Digest,
    pub instance_digest: Digest,
    pub region_digest: Digest,
    pub zone_digest: Option<Digest>,
    pub state: InstanceState,
    pub database_version: DatabaseVersion,
    pub edition: Option<DatabaseEdition>,
    pub availability_type: AvailabilityType,
    pub replica_count: u16,
    pub read_replica_count: u16,
    pub high_availability: bool,
    pub topology_digest: Digest,
    pub settings_version: SettingsVersion,
    pub backup: BackupPolicySummary,
    pub maintenance: MaintenancePolicySummary,
    pub storage: StorageSummary,
    pub observed_at: DateTime<Utc>,
    pub snapshot_digest: Digest,
}

impl CloudSqlInstanceSnapshot {
    pub fn new(
        scope: &GcpCloudSqlInstanceScope,
        input: InstanceSnapshotInput,
    ) -> Result<Self, ModelError> {
        if input.observed_at.timestamp() < 0 {
            return Err(ModelError::InvalidTimestamp);
        }
        if input
            .zone_digest
            .as_ref()
            .is_some_and(|digest| digest.validate().is_err())
            || input
                .maintenance
                .version_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
        {
            return Err(ModelError::InvalidDigest);
        }
        let topology_digest = Digest::from_parts(
            "gcp-cloud-sql-topology/v1",
            &[
                ("availability", format!("{:?}", input.availability_type)),
                ("replicas", input.replica_count.to_string()),
                ("read_replicas", input.read_replica_count.to_string()),
                ("high_availability", input.high_availability.to_string()),
            ],
        );
        let mut snapshot = Self {
            project_digest: scope.cloud_project_id().digest(),
            instance_digest: scope.instance_id().digest(),
            region_digest: scope.region().digest(),
            zone_digest: input.zone_digest,
            state: input.state,
            database_version: input.database_version,
            edition: input.edition,
            availability_type: input.availability_type,
            replica_count: input.replica_count,
            read_replica_count: input.read_replica_count,
            high_availability: input.high_availability,
            topology_digest,
            settings_version: input.settings_version,
            backup: input.backup,
            maintenance: input.maintenance,
            storage: input.storage,
            observed_at: input.observed_at,
            snapshot_digest: Digest::zero(),
        };
        snapshot.snapshot_digest = snapshot.calculate_digest();
        snapshot.validate_against(scope)?;
        Ok(snapshot)
    }

    pub fn minimal(
        scope: &GcpCloudSqlInstanceScope,
        state: InstanceState,
        database_version: DatabaseVersion,
        settings_version: SettingsVersion,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            InstanceSnapshotInput::minimal(state, database_version, settings_version, observed_at),
        )
    }

    pub fn validate_against(&self, scope: &GcpCloudSqlInstanceScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.project_digest != scope.cloud_project_id().digest()
            || self.instance_digest != scope.instance_id().digest()
            || self.region_digest != scope.region().digest()
            || self.database_version != *scope.database_version()
            || self.settings_version != scope.settings_version()
            || self
                .zone_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || scope
                .expected_topology_digest()
                .is_some_and(|digest| digest != &self.topology_digest)
            || self.snapshot_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.snapshot_digest != self.calculate_digest() {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn topology_digest(&self) -> &Digest {
        &self.topology_digest
    }

    fn calculate_digest(&self) -> Digest {
        digest_serialized(
            "gcp-cloud-sql-instance-snapshot/v1",
            &[
                self.project_digest.as_str(),
                self.instance_digest.as_str(),
                self.region_digest.as_str(),
                self.zone_digest.as_ref().map_or("", Digest::as_str),
                self.state.as_str(),
                self.database_version.as_str(),
                self.edition.as_ref().map_or("", DatabaseEdition::as_str),
                &format!("{:?}", self.availability_type),
                &self.replica_count.to_string(),
                &self.read_replica_count.to_string(),
                &self.high_availability.to_string(),
                self.topology_digest.as_str(),
                &self.settings_version.get().to_string(),
                &self.backup.enabled.to_string(),
                &self.backup.point_in_time_recovery.to_string(),
                &self
                    .backup
                    .retained_backup_count
                    .unwrap_or_default()
                    .to_string(),
                &self.maintenance.window_present.to_string(),
                self.maintenance
                    .version_digest
                    .as_ref()
                    .map_or("", Digest::as_str),
                &self.storage.disk_size_bytes.unwrap_or_default().to_string(),
                &self.storage.storage_auto_resize.to_string(),
                &self
                    .storage
                    .storage_auto_resize_limit_bytes
                    .unwrap_or_default()
                    .to_string(),
                &self.observed_at.to_rfc3339(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSnapshotInput {
    pub operation_type: OperationType,
    pub status: OperationStatus,
    pub start_time_digest: Option<Digest>,
    pub end_time_digest: Option<Digest>,
    pub error_category_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSqlOperationSnapshot {
    pub operation_digest: Digest,
    pub operation_type: OperationType,
    pub status: OperationStatus,
    pub start_time_digest: Option<Digest>,
    pub end_time_digest: Option<Digest>,
    pub error_category_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub snapshot_digest: Digest,
}

impl CloudSqlOperationSnapshot {
    pub fn new(
        scope: &GcpCloudSqlInstanceScope,
        input: OperationSnapshotInput,
    ) -> Result<Self, ModelError> {
        if input.observed_at.timestamp() < 0 {
            return Err(ModelError::InvalidTimestamp);
        }
        for digest in [
            input.start_time_digest.as_ref(),
            input.end_time_digest.as_ref(),
            input.error_category_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        let mut snapshot = Self {
            operation_digest: scope.operation().digest().clone(),
            operation_type: input.operation_type,
            status: input.status,
            start_time_digest: input.start_time_digest,
            end_time_digest: input.end_time_digest,
            error_category_digest: input.error_category_digest,
            observed_at: input.observed_at,
            snapshot_digest: Digest::zero(),
        };
        snapshot.snapshot_digest = snapshot.calculate_digest();
        snapshot.validate_against(scope)?;
        Ok(snapshot)
    }

    pub fn validate_against(&self, scope: &GcpCloudSqlInstanceScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.operation_digest != *scope.operation().digest()
            || self.operation_type != scope.operation().operation_type()
            || self.snapshot_digest != self.calculate_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.snapshot_digest != self.calculate_digest() {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn merge(&self, newer: &Self) -> Result<Self, ModelError> {
        if self.operation_digest != newer.operation_digest
            || self.operation_type != newer.operation_type
            || newer.status.rank() < self.status.rank()
            || (self.status.is_terminal() && newer.status != self.status)
        {
            return Err(ModelError::OperationRegression);
        }
        Ok(newer.clone())
    }

    fn calculate_digest(&self) -> Digest {
        digest_serialized(
            "gcp-cloud-sql-operation-snapshot/v1",
            &[
                self.operation_digest.as_str(),
                self.operation_type.as_str(),
                &format!("{:?}", self.status),
                self.start_time_digest.as_ref().map_or("", Digest::as_str),
                self.end_time_digest.as_ref().map_or("", Digest::as_str),
                self.error_category_digest
                    .as_ref()
                    .map_or("", Digest::as_str),
                &self.observed_at.to_rfc3339(),
            ],
        )
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
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub instance_digest: Digest,
    pub settings_version_digest: Digest,
    pub operation_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn new(
        provider_digest: Digest,
        scope: &GcpCloudSqlInstanceScope,
        instance: Option<&CloudSqlInstanceSnapshot>,
        operation: Option<&CloudSqlOperationSnapshot>,
    ) -> Self {
        Self::new_with_api(
            provider_digest,
            Digest::from_text(API_REVISION),
            scope,
            instance,
            operation,
        )
    }

    pub fn new_with_api(
        provider_digest: Digest,
        api_digest: Digest,
        scope: &GcpCloudSqlInstanceScope,
        instance: Option<&CloudSqlInstanceSnapshot>,
        operation: Option<&CloudSqlOperationSnapshot>,
    ) -> Self {
        let mut result = Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::from_text(crate::CONTRACT_DIGEST_INPUT),
            provider_digest,
            api_digest,
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            scope_digest: scope.digest().clone(),
            instance_digest: instance
                .map_or_else(Digest::zero, |value| value.instance_digest.clone()),
            settings_version_digest: instance.map_or_else(Digest::zero, |value| {
                Digest::from_text(value.settings_version.get().to_string())
            }),
            operation_digest: operation.map_or_else(
                || scope.operation().digest().clone(),
                |value| value.operation_digest.clone(),
            ),
            evidence_digest: Digest::zero(),
        };
        result.evidence_digest = result.calculate_digest();
        result
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.instance_digest,
            &self.settings_version_digest,
            &self.operation_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        Ok(())
    }

    pub fn base_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        digest_serialized(
            "gcp-cloud-sql-evidence-digests/v1",
            &[
                self.plugin_version_digest.as_str(),
                self.contract_digest.as_str(),
                self.provider_digest.as_str(),
                self.api_digest.as_str(),
                self.permission_digest.as_str(),
                self.consent_digest.as_str(),
                self.scope_digest.as_str(),
                self.instance_digest.as_str(),
                self.settings_version_digest.as_str(),
                self.operation_digest.as_str(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCloudSqlResultState {
    Runnable,
    Maintenance,
    Suspended,
    Failed,
    PendingCreate,
    PendingDelete,
    OperationRunning,
    OperationDone,
    OperationFailed,
    Absent,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Replay,
    ReplayConflict,
    Revoked,
}

impl GcpCloudSqlResultState {
    pub const fn is_non_adoptable(&self) -> bool {
        !matches!(
            self,
            Self::Runnable
                | Self::Maintenance
                | Self::Suspended
                | Self::Failed
                | Self::PendingCreate
                | Self::PendingDelete
                | Self::OperationRunning
                | Self::OperationDone
                | Self::OperationFailed
        )
    }
}

pub type EvidenceState = GcpCloudSqlResultState;

pub fn result_state_for_instance(state: InstanceState) -> GcpCloudSqlResultState {
    match state {
        InstanceState::Runnable => GcpCloudSqlResultState::Runnable,
        InstanceState::Maintenance => GcpCloudSqlResultState::Maintenance,
        InstanceState::Suspended => GcpCloudSqlResultState::Suspended,
        InstanceState::Failed | InstanceState::Unknown => GcpCloudSqlResultState::Failed,
        InstanceState::PendingCreate => GcpCloudSqlResultState::PendingCreate,
        InstanceState::PendingDelete => GcpCloudSqlResultState::PendingDelete,
    }
}

pub fn result_state_for_operation(status: OperationStatus) -> GcpCloudSqlResultState {
    match status {
        OperationStatus::Pending | OperationStatus::Running | OperationStatus::Unknown => {
            GcpCloudSqlResultState::OperationRunning
        }
        OperationStatus::Done => GcpCloudSqlResultState::OperationDone,
        OperationStatus::Failed => GcpCloudSqlResultState::OperationFailed,
    }
}

pub(crate) fn digest_serialized(domain: &str, fields: &[&str]) -> Digest {
    let mut bytes = Vec::new();
    append_field(&mut bytes, domain);
    for (index, value) in fields.iter().enumerate() {
        append_field(&mut bytes, &index.to_string());
        append_field(&mut bytes, value);
    }
    Digest::from_bytes(&bytes)
}

#[allow(dead_code)]
pub(crate) fn contract_metadata_digest() -> Digest {
    Digest::from_parts(
        "gcp-cloud-sql-contract-metadata/v1",
        &[
            ("contract_version", CONTRACT_VERSION.to_owned()),
            ("provider", PROVIDER_ID.to_owned()),
            ("api", API_REVISION.to_owned()),
        ],
    )
}
