//! Bounded, digest-bound and redacted data types for the AlloyDB Layer-1 seam.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_TOKEN_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES_PER_OPERATION: usize = 1;
pub const MAX_OPERATIONS_PER_READ: usize = 2;
pub const MAX_CPU_COUNT: u32 = 1_024;
pub const MAX_NODE_COUNT: u32 = 64;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains control characters or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains an invalid identifier character")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a valid SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a positive revision")]
    InvalidRevision { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} is outside the exact AlloyDB scope")]
    ScopeMismatch { field: &'static str },
    #[error("the AlloyDB permission allowlist is invalid")]
    InvalidPermission,
    #[error("the secret reference is revoked")]
    SecretRevoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(ProjectId, "project id");
bounded_identifier!(Location, "location");
bounded_identifier!(ClusterId, "cluster id");
bounded_identifier!(InstanceId, "instance id");
bounded_identifier!(MissionId, "mission id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(DeploymentId, "deployment id");

/// A positive caller-owned revision number. It is never inferred from a
/// provider response; the response must match the exact value in scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            return Err(ModelError::InvalidRevision { field: "revision" });
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Lower-case SHA-256 digest used for all public evidence fences.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(value)))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn from_parts(label: &str, fields: &[(&str, String)]) -> Self {
        let mut material = String::from(label);
        for (name, value) in fields {
            material.push('\0');
            material.push_str(name);
            material.push('=');
            material.push_str(value);
        }
        Self::from_text(&material)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::InvalidText {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlloyDbReadOperation {
    GetCluster,
    GetInstance,
}

impl AlloyDbReadOperation {
    pub const ALL: [Self; MAX_OPERATIONS_PER_READ] = [Self::GetCluster, Self::GetInstance];

    pub const fn api_operation(self) -> &'static str {
        match self {
            Self::GetCluster => "projects.locations.clusters.get",
            Self::GetInstance => "projects.locations.clusters.instances.get",
        }
    }

    pub const fn method(self) -> &'static str {
        "GET"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub deployment_id: DeploymentId,
    pub deployment_revision: Revision,
}

impl MissionBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mission_id: MissionId,
        mission_revision: Revision,
        project_id: ProjectId,
        project_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        deployment_id: DeploymentId,
        deployment_revision: Revision,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            work_product_id,
            work_product_revision,
            deployment_id,
            deployment_revision,
        })
    }

    pub fn minimal(
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let deployment_id = DeploymentId::new("layer1")?;
        Self::new(
            mission_id,
            revision,
            project_id,
            revision,
            work_product_id,
            revision,
            deployment_id,
            revision,
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-mission-binding/v1",
            &[
                ("mission", self.mission_id.as_str().to_owned()),
                (
                    "mission_revision",
                    self.mission_revision.value().to_string(),
                ),
                ("project", self.project_id.as_str().to_owned()),
                (
                    "project_revision",
                    self.project_revision.value().to_string(),
                ),
                ("work_product", self.work_product_id.as_str().to_owned()),
                (
                    "work_product_revision",
                    self.work_product_revision.value().to_string(),
                ),
                ("deployment", self.deployment_id.as_str().to_owned()),
                (
                    "deployment_revision",
                    self.deployment_revision.value().to_string(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbTarget {
    pub project_id: ProjectId,
    pub location: Location,
    pub cluster_id: ClusterId,
    pub instance_id: InstanceId,
    pub resource_revision: Revision,
}

impl GcpAlloyDbTarget {
    pub fn new(
        project_id: ProjectId,
        location: Location,
        cluster_id: ClusterId,
        instance_id: InstanceId,
        resource_revision: Revision,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            project_id,
            location,
            cluster_id,
            instance_id,
            resource_revision,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-target/v1",
            &[
                ("project", self.project_id.as_str().to_owned()),
                ("location", self.location.as_str().to_owned()),
                ("cluster", self.cluster_id.as_str().to_owned()),
                ("instance", self.instance_id.as_str().to_owned()),
                ("revision", self.resource_revision.value().to_string()),
            ],
        )
    }

    pub fn cluster_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-cluster-target/v1",
            &[
                ("project", self.project_id.as_str().to_owned()),
                ("location", self.location.as_str().to_owned()),
                ("cluster", self.cluster_id.as_str().to_owned()),
                ("revision", self.resource_revision.value().to_string()),
            ],
        )
    }

    pub fn instance_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-instance-target/v1",
            &[
                ("project", self.project_id.as_str().to_owned()),
                ("location", self.location.as_str().to_owned()),
                ("cluster", self.cluster_id.as_str().to_owned()),
                ("instance", self.instance_id.as_str().to_owned()),
                ("revision", self.resource_revision.value().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub permission_revision: Revision,
    pub allowed_operations: BTreeSet<AlloyDbReadOperation>,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        permission_revision: Revision,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let allowed_operations = AlloyDbReadOperation::ALL.into_iter().collect();
        let value = Self {
            permission_revision,
            allowed_operations,
            permission_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn read_only(permission_revision: Revision) -> Self {
        let allowed_operations = AlloyDbReadOperation::ALL
            .into_iter()
            .collect::<BTreeSet<_>>();
        let permission_digest = Digest::from_parts(
            "gcp-alloydb-permission/v1",
            &[
                ("revision", permission_revision.value().to_string()),
                (
                    "operations",
                    AlloyDbReadOperation::ALL
                        .iter()
                        .map(|operation| operation.api_operation())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            permission_revision,
            allowed_operations,
            permission_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.allowed_operations.len() != AlloyDbReadOperation::ALL.len()
            || AlloyDbReadOperation::ALL
                .iter()
                .any(|operation| !self.allowed_operations.contains(operation))
        {
            return Err(ModelError::InvalidPermission);
        }
        Ok(())
    }

    pub fn allows(&self, operation: AlloyDbReadOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbClusterScope {
    pub target: GcpAlloyDbTarget,
    pub mission: MissionBinding,
    pub permissions: PermissionScope,
    pub scope_digest: Digest,
}

impl GcpAlloyDbClusterScope {
    pub fn new(
        target: GcpAlloyDbTarget,
        mission: MissionBinding,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        if target.project_id != mission.project_id {
            return Err(ModelError::ScopeMismatch {
                field: "project id",
            });
        }
        permissions.validate()?;
        let scope_digest = Digest::from_parts(
            "gcp-alloydb-scope/v1",
            &[
                ("target", target.digest().as_str().to_owned()),
                ("mission", mission.digest().as_str().to_owned()),
                ("permission", permissions.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            target,
            mission,
            permissions,
            scope_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.target.project_id != self.mission.project_id {
            return Err(ModelError::ScopeMismatch {
                field: "project id",
            });
        }
        self.permissions.validate()?;
        let expected = Digest::from_parts(
            "gcp-alloydb-scope/v1",
            &[
                ("target", self.target.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("permission", self.permissions.digest().as_str().to_owned()),
            ],
        );
        if self.scope_digest != expected {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.target.project_id
    }

    pub fn location(&self) -> &Location {
        &self.target.location
    }

    pub fn cluster_id(&self) -> &ClusterId {
        &self.target.cluster_id
    }

    pub fn instance_id(&self) -> &InstanceId {
        &self.target.instance_id
    }

    pub fn resource_revision(&self) -> Revision {
        self.target.resource_revision
    }
}

/// An opaque credential/secret handle. The caller's reference is hashed and
/// discarded immediately; it is not serializable, clone-debuggable, or
/// available to the Layer-1 provider.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference: impl AsRef<str>,
        scope: &GcpAlloyDbClusterScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        validate_text(reference, "secret reference", MAX_IDENTIFIER_BYTES)?;
        let reference_hash = Digest::from_text(reference);
        let reference_digest = Digest::from_parts(
            "gcp-alloydb-secret-reference/v1",
            &[
                ("reference", reference_hash.as_str().to_owned()),
                ("scope", scope.digest().as_str().to_owned()),
                (
                    "credential_revision",
                    credential_revision.value().to_string(),
                ),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.digest().clone(),
            credential_revision,
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

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::SecretRevoked);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
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

impl fmt::Display for ProviderProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

/// Only a digest and bounded page number survive; the raw provider token is
/// never retained or emitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    token_digest: Digest,
    page_number: usize,
    operation: AlloyDbReadOperation,
}

impl OpaquePageToken {
    pub fn new(
        raw_token: impl AsRef<str>,
        scope_digest: &Digest,
        operation: AlloyDbReadOperation,
        page_number: usize,
    ) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        validate_text(raw_token, "page token", MAX_PAGE_TOKEN_BYTES)?;
        if page_number == 0 || page_number > MAX_PAGES_PER_OPERATION {
            return Err(ModelError::BoundExceeded {
                field: "page number",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "gcp-alloydb-page-token/v1",
                &[
                    ("token", Digest::from_text(raw_token).as_str().to_owned()),
                    ("scope", scope_digest.as_str().to_owned()),
                    ("operation", operation.api_operation().to_owned()),
                    ("page", page_number.to_string()),
                ],
            ),
            page_number,
            operation,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> usize {
        self.page_number
    }

    pub const fn operation(&self) -> AlloyDbReadOperation {
        self.operation
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Ready,
    Creating,
    Updating,
    Deleting,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityType {
    Zonal,
    Regional,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterType {
    Primary,
    Secondary,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseVersion {
    Postgres14,
    Postgres15,
    Postgres16,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceType {
    Primary,
    ReadPool,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterPosture {
    pub lifecycle_state: LifecycleState,
    pub cluster_type: ClusterType,
    pub availability_type: AvailabilityType,
    pub database_version: DatabaseVersion,
    pub instance_count: u32,
    pub resource_revision: Revision,
}

impl ClusterPosture {
    pub fn new(
        lifecycle_state: LifecycleState,
        cluster_type: ClusterType,
        availability_type: AvailabilityType,
        database_version: DatabaseVersion,
        instance_count: u32,
        resource_revision: Revision,
    ) -> Result<Self, ModelError> {
        if instance_count > MAX_NODE_COUNT {
            return Err(ModelError::BoundExceeded {
                field: "cluster instance count",
            });
        }
        Ok(Self {
            lifecycle_state,
            cluster_type,
            availability_type,
            database_version,
            instance_count,
            resource_revision,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-cluster-posture/v1",
            &[
                ("state", format!("{:?}", self.lifecycle_state)),
                ("cluster_type", format!("{:?}", self.cluster_type)),
                ("availability", format!("{:?}", self.availability_type)),
                ("database_version", format!("{:?}", self.database_version)),
                ("instance_count", self.instance_count.to_string()),
                ("revision", self.resource_revision.value().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstancePosture {
    pub lifecycle_state: LifecycleState,
    pub instance_type: InstanceType,
    pub availability_type: AvailabilityType,
    pub cpu_count: u32,
    pub node_count: u32,
    pub resource_revision: Revision,
}

impl InstancePosture {
    pub fn new(
        lifecycle_state: LifecycleState,
        instance_type: InstanceType,
        availability_type: AvailabilityType,
        cpu_count: u32,
        node_count: u32,
        resource_revision: Revision,
    ) -> Result<Self, ModelError> {
        if cpu_count == 0 || cpu_count > MAX_CPU_COUNT {
            return Err(ModelError::BoundExceeded {
                field: "instance cpu count",
            });
        }
        if node_count == 0 || node_count > MAX_NODE_COUNT {
            return Err(ModelError::BoundExceeded {
                field: "instance node count",
            });
        }
        Ok(Self {
            lifecycle_state,
            instance_type,
            availability_type,
            cpu_count,
            node_count,
            resource_revision,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-instance-posture/v1",
            &[
                ("state", format!("{:?}", self.lifecycle_state)),
                ("instance_type", format!("{:?}", self.instance_type)),
                ("availability", format!("{:?}", self.availability_type)),
                ("cpu_count", self.cpu_count.to_string()),
                ("node_count", self.node_count.to_string()),
                ("revision", self.resource_revision.value().to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Ready,
    StaleRevision,
    ScopeDrift,
    PermissionLoss,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Truncated,
    PaginationLoop,
    RegistrationRevoked,
    ReplayConflict,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub secret_material_redacted: bool,
    pub connection_info_redacted: bool,
    pub endpoints_redacted: bool,
    pub credentials_redacted: bool,
    pub users_redacted: bool,
    pub sql_rows_redacted: bool,
    pub raw_provider_payload_redacted: bool,
    pub raw_bodies_redacted: bool,
    pub raw_page_tokens_redacted: bool,
}

impl RedactionSummary {
    pub const fn complete() -> Self {
        Self {
            secret_material_redacted: true,
            connection_info_redacted: true,
            endpoints_redacted: true,
            credentials_redacted: true,
            users_redacted: true,
            sql_rows_redacted: true,
            raw_provider_payload_redacted: true,
            raw_bodies_redacted: true,
            raw_page_tokens_redacted: true,
        }
    }

    pub const fn is_complete(&self) -> bool {
        self.secret_material_redacted
            && self.connection_info_redacted
            && self.endpoints_redacted
            && self.credentials_redacted
            && self.users_redacted
            && self.sql_rows_redacted
            && self.raw_provider_payload_redacted
            && self.raw_bodies_redacted
            && self.raw_page_tokens_redacted
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl AuthorityBoundary {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub const fn is_below_kernel_authority(self) -> bool {
        !self.connected
            && !self.native
            && !self.first_party
            && !self.durable_provider_receipt
            && !self.truth_authority
            && !self.consent_authority
            && !self.effect_authority
            && !self.receipt_authority
            && !self.verification_authority
            && !self.outcome_authority
            && !self.work_product_adoption
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub cluster_pages: usize,
    pub instance_pages: usize,
    pub complete: bool,
    pub continuation_token_digests: Vec<Digest>,
}

impl PaginationEvidence {
    pub const fn complete() -> Self {
        Self {
            cluster_pages: 1,
            instance_pages: 1,
            complete: true,
            continuation_token_digests: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub secret_reference_digest: Digest,
    pub cluster_response_digest: Option<Digest>,
    pub instance_response_digest: Option<Digest>,
    pub evidence_digest: Digest,
}
