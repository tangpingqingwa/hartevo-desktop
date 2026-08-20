//! Bounded, digest-only Bigtable scope and posture models.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_RESOURCE_NAME_BYTES: usize = 512;
pub(crate) const MAX_FAMILIES: usize = 256;
pub(crate) const MAX_CLUSTERS: usize = 64;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 4096;
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_SERVE_NODES: u32 = 100_000;
pub(crate) const MAX_POLICY_AGE_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;
pub(crate) const MAX_POLICY_AGE_MILLIS: u64 = MAX_POLICY_AGE_SECONDS * 1_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("resource name is malformed or outside the exact project/instance scope")]
    InvalidResourceName,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("bounded value is invalid")]
    InvalidValue,
    #[error("too many column families")]
    TooManyFamilies,
    #[error("too many clusters")]
    TooManyClusters,
    #[error("opaque page token is empty or too large")]
    InvalidPageToken,
    #[error("opaque page token is not bound to this request")]
    PageTokenBindingMismatch,
    #[error("immutable evidence digest does not match its fields")]
    DigestMismatch,
    #[error("response exceeds the Layer-1 safety ceiling")]
    ResponseTooLarge,
    #[error("response is truncated or unexpectedly paginated")]
    TruncatedResponse,
    #[error("duplicate bounded evidence entry")]
    Duplicate,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("secret reference is already revoked")]
    SecretAlreadyRevoked,
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
    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! identifier_type {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                valid_identifier(&value)
                    .then_some(Self(value))
                    .ok_or(ModelError::InvalidIdentifier)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_fields(
                    concat!(stringify!($name), "/v1"),
                    std::slice::from_ref(&self.0),
                )
            }

            #[must_use]
            pub fn redacted(&self) -> String {
                format!("{}:{}", stringify!($name), &self.digest().as_str()[..16])
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
                self.0.fmt(formatter)
            }
        }
    };
}

identifier_type!(ProjectId);
identifier_type!(InstanceId);
identifier_type!(TableId);
identifier_type!(ClusterId);
identifier_type!(MissionId);
identifier_type!(WorkProductId);
identifier_type!(ServiceId);
identifier_type!(ProviderId);
identifier_type!(ConsumerId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        (value != 0)
            .then_some(Self(value))
            .ok_or(ModelError::InvalidValue)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TableResource {
    project: ProjectId,
    instance: InstanceId,
    table: TableId,
    raw: String,
}

impl TableResource {
    #[must_use]
    pub fn new(project: ProjectId, instance: InstanceId, table: TableId) -> Self {
        let raw = format!(
            "projects/{}/instances/{}/tables/{}",
            project.as_str(),
            instance.as_str(),
            table.as_str()
        );
        Self {
            project,
            instance,
            table,
            raw,
        }
    }

    pub fn from_name(
        name: impl Into<String>,
        project: &ProjectId,
        instance: &InstanceId,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        let prefix = format!(
            "projects/{}/instances/{}/tables/",
            project.as_str(),
            instance.as_str()
        );
        let Some(table) = name.strip_prefix(&prefix) else {
            return Err(ModelError::InvalidResourceName);
        };
        if name.len() > MAX_RESOURCE_NAME_BYTES || !valid_identifier(table) {
            return Err(ModelError::InvalidResourceName);
        }
        Ok(Self::new(
            project.clone(),
            instance.clone(),
            TableId::new(table)?,
        ))
    }

    #[must_use]
    pub fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }
    #[must_use]
    pub fn table(&self) -> &TableId {
        &self.table
    }
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-table-resource/v1",
            std::slice::from_ref(&self.raw),
        )
    }
}

impl fmt::Debug for TableResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableResource")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClusterResource {
    project: ProjectId,
    instance: InstanceId,
    cluster: ClusterId,
    raw: String,
}

impl ClusterResource {
    #[must_use]
    pub fn new(project: ProjectId, instance: InstanceId, cluster: ClusterId) -> Self {
        let raw = format!(
            "projects/{}/instances/{}/clusters/{}",
            project.as_str(),
            instance.as_str(),
            cluster.as_str()
        );
        Self {
            project,
            instance,
            cluster,
            raw,
        }
    }

    pub fn from_name(
        name: impl Into<String>,
        project: &ProjectId,
        instance: &InstanceId,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        let prefix = format!(
            "projects/{}/instances/{}/clusters/",
            project.as_str(),
            instance.as_str()
        );
        let Some(cluster) = name.strip_prefix(&prefix) else {
            return Err(ModelError::InvalidResourceName);
        };
        if name.len() > MAX_RESOURCE_NAME_BYTES || !valid_identifier(cluster) {
            return Err(ModelError::InvalidResourceName);
        }
        Ok(Self::new(
            project.clone(),
            instance.clone(),
            ClusterId::new(cluster)?,
        ))
    }

    #[must_use]
    pub fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }
    #[must_use]
    pub fn cluster(&self) -> &ClusterId {
        &self.cluster
    }
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-cluster-resource/v1",
            std::slice::from_ref(&self.raw),
        )
    }
}

impl fmt::Debug for ClusterResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterResource")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseProjection {
    pub project_digest: Digest,
    pub instance_digest: Digest,
    pub database_digest: Digest,
}

impl DatabaseProjection {
    #[must_use]
    pub fn for_scope(project: &ProjectId, instance: &InstanceId) -> Self {
        let project_digest = project.digest();
        let instance_digest = instance.digest();
        let database_digest = Digest::from_fields(
            "gcp-bigtable-database/v1",
            &[
                project_digest.as_str().to_owned(),
                instance_digest.as_str().to_owned(),
            ],
        );
        Self {
            project_digest,
            instance_digest,
            database_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResourceScopeProjection {
    pub database: DatabaseProjection,
    pub table_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpBigtableTableScope {
    project: ProjectId,
    instance: InstanceId,
    table: TableResource,
    mission: MissionId,
    work_product: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl GcpBigtableTableScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        instance: InstanceId,
        table: TableResource,
        mission: MissionId,
        work_product: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        if table.project() != &project || table.instance() != &instance {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "gcp-bigtable-table-scope/v1",
            &[
                project.digest().as_str().to_owned(),
                instance.digest().as_str().to_owned(),
                table.digest().as_str().to_owned(),
                mission.digest().as_str().to_owned(),
                work_product.digest().as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            project,
            instance,
            table,
            mission,
            work_product,
            work_product_revision,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn from_ids(
        project: ProjectId,
        instance: InstanceId,
        table: TableId,
        mission: MissionId,
        work_product: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            project.clone(),
            instance.clone(),
            TableResource::new(project, instance, table),
            mission,
            work_product,
            work_product_revision,
            permission_digest,
            consent_digest,
        )
    }

    #[must_use]
    pub fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }
    #[must_use]
    pub fn table(&self) -> &TableResource {
        &self.table
    }
    #[must_use]
    pub fn mission(&self) -> &MissionId {
        &self.mission
    }
    #[must_use]
    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product
    }
    #[must_use]
    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }
    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }
    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }
    #[must_use]
    pub fn database_projection(&self) -> DatabaseProjection {
        DatabaseProjection::for_scope(&self.project, &self.instance)
    }
    #[must_use]
    pub fn provider_resource_projection(&self) -> ProviderResourceScopeProjection {
        ProviderResourceScopeProjection {
            database: self.database_projection(),
            table_digest: self.table.digest(),
        }
    }

    pub(crate) fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product_revision,
        }
    }
}

pub type GcpBigtableScope = GcpBigtableTableScope;
pub type GcpBigtableTableResultScope = GcpBigtableTableScope;

/// A non-serializing reference to a keyring entry. The caller's raw reference
/// is hashed at construction and never retained.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
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
        scope: &GcpBigtableTableScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "gcp-bigtable-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
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
    pub const fn auth_kind(&self) -> GoogleAuthKind {
        self.auth_kind
    }
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::SecretAlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GarbageCollectionRuleKind {
    Unspecified,
    MaxVersions,
    MaxAge,
    Union,
    Intersection,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GarbageCollectionProjection {
    pub kind: GarbageCollectionRuleKind,
    pub max_versions: Option<u32>,
    pub max_age_seconds: Option<u64>,
    pub max_age_millis: Option<u64>,
    pub child_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GarbageCollectionRule {
    Unspecified,
    MaxVersions(u32),
    MaxAgeSeconds(u64),
    MaxAgeMillis(u64),
    Union(u16),
    Intersection(u16),
    Unknown,
}

impl GarbageCollectionRule {
    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::MaxVersions(value) if *value == 0 => Err(ModelError::InvalidValue),
            Self::MaxAgeSeconds(value) if *value == 0 || *value > MAX_POLICY_AGE_SECONDS => {
                Err(ModelError::InvalidValue)
            }
            Self::MaxAgeMillis(value) if *value == 0 || *value > MAX_POLICY_AGE_MILLIS => {
                Err(ModelError::InvalidValue)
            }
            Self::Union(value) | Self::Intersection(value) if *value == 0 => {
                Err(ModelError::InvalidValue)
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn projection(&self) -> GarbageCollectionProjection {
        match self {
            Self::Unspecified => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::Unspecified,
                max_versions: None,
                max_age_seconds: None,
                max_age_millis: None,
                child_count: 0,
            },
            Self::MaxVersions(value) => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::MaxVersions,
                max_versions: Some(*value),
                max_age_seconds: None,
                max_age_millis: None,
                child_count: 0,
            },
            Self::MaxAgeSeconds(value) => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::MaxAge,
                max_versions: None,
                max_age_seconds: Some(*value),
                max_age_millis: Some(*value * 1_000),
                child_count: 0,
            },
            Self::MaxAgeMillis(value) => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::MaxAge,
                max_versions: None,
                max_age_seconds: None,
                max_age_millis: Some(*value),
                child_count: 0,
            },
            Self::Union(value) => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::Union,
                max_versions: None,
                max_age_seconds: None,
                max_age_millis: None,
                child_count: *value,
            },
            Self::Intersection(value) => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::Intersection,
                max_versions: None,
                max_age_seconds: None,
                max_age_millis: None,
                child_count: *value,
            },
            Self::Unknown => GarbageCollectionProjection {
                kind: GarbageCollectionRuleKind::Unknown,
                max_versions: None,
                max_age_seconds: None,
                max_age_millis: None,
                child_count: 0,
            },
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let projection = self.projection();
        Digest::from_fields(
            "gcp-bigtable-gc-rule/v1",
            &[
                format!("{:?}", projection.kind),
                projection
                    .max_versions
                    .map_or_else(String::new, |v| v.to_string()),
                projection
                    .max_age_seconds
                    .map_or_else(String::new, |v| v.to_string()),
                projection
                    .max_age_millis
                    .map_or_else(String::new, |v| v.to_string()),
                projection.child_count.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnFamilyProjection {
    pub family_digest: Digest,
    pub gc_rule: GarbageCollectionProjection,
    pub value_type_digest: Option<Digest>,
    pub configuration_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ColumnFamily {
    name: String,
    gc_rule: GarbageCollectionRule,
    value_type_digest: Option<Digest>,
    configuration_digest: Digest,
}

impl ColumnFamily {
    pub fn new(
        name: impl Into<String>,
        gc_rule: GarbageCollectionRule,
    ) -> Result<Self, ModelError> {
        Self::new_with_value_type(name, gc_rule, None)
    }

    pub fn new_with_value_type(
        name: impl Into<String>,
        gc_rule: GarbageCollectionRule,
        value_type_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        if !valid_identifier(&name) {
            return Err(ModelError::InvalidIdentifier);
        }
        gc_rule.validate()?;
        let configuration_digest =
            Self::compute_digest(&name, &gc_rule, value_type_digest.as_ref());
        Ok(Self {
            name,
            gc_rule,
            value_type_digest,
            configuration_digest,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn family_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-column-family/v1",
            std::slice::from_ref(&self.name),
        )
    }
    #[must_use]
    pub fn gc_rule(&self) -> &GarbageCollectionRule {
        &self.gc_rule
    }
    #[must_use]
    pub fn value_type_digest(&self) -> Option<&Digest> {
        self.value_type_digest.as_ref()
    }
    #[must_use]
    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
    #[must_use]
    pub fn projection(&self) -> ColumnFamilyProjection {
        ColumnFamilyProjection {
            family_digest: self.family_digest(),
            gc_rule: self.gc_rule.projection(),
            value_type_digest: self.value_type_digest.clone(),
            configuration_digest: self.configuration_digest.clone(),
        }
    }
    pub fn validate_digest(&self) -> Result<(), ModelError> {
        (self.configuration_digest
            == Self::compute_digest(&self.name, &self.gc_rule, self.value_type_digest.as_ref()))
        .then_some(())
        .ok_or(ModelError::DigestMismatch)
    }
    fn compute_digest(
        name: &str,
        rule: &GarbageCollectionRule,
        value_type: Option<&Digest>,
    ) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-column-family-configuration/v1",
            &[
                Digest::from_text(name).as_str().to_owned(),
                rule.digest().as_str().to_owned(),
                value_type.map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for ColumnFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ColumnFamily")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableGranularity {
    Millis,
    Micros,
    Unspecified,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableClusterState {
    StateNotKnown,
    Planned,
    Creating,
    Ready,
    Deleting,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableClusterStateProjection {
    pub cluster_digest: Digest,
    pub state: TableClusterState,
    pub state_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TableClusterStateEntry {
    cluster: ClusterResource,
    state: TableClusterState,
    state_digest: Digest,
}

impl TableClusterStateEntry {
    pub fn new(cluster: ClusterResource, state: TableClusterState) -> Self {
        let state_digest = Digest::from_fields(
            "gcp-bigtable-table-cluster-state/v1",
            &[cluster.digest().as_str().to_owned(), format!("{state:?}")],
        );
        Self {
            cluster,
            state,
            state_digest,
        }
    }
    #[must_use]
    pub fn cluster(&self) -> &ClusterResource {
        &self.cluster
    }
    #[must_use]
    pub const fn state(&self) -> TableClusterState {
        self.state
    }
    #[must_use]
    pub fn projection(&self) -> TableClusterStateProjection {
        TableClusterStateProjection {
            cluster_digest: self.cluster.digest(),
            state: self.state,
            state_digest: self.state_digest.clone(),
        }
    }
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.state_digest.clone()
    }
}

impl fmt::Debug for TableClusterStateEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableClusterStateEntry")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableProjection {
    pub database: DatabaseProjection,
    pub table_digest: Digest,
    pub schema_digest: Digest,
    pub family_count: u16,
    pub family_digest: Digest,
    pub cluster_count: u16,
    pub cluster_state_digest: Digest,
    pub granularity: TableGranularity,
    pub deletion_protection: Option<bool>,
    pub change_stream_enabled: bool,
    pub configuration_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TableConfiguration {
    resource: TableResource,
    families: Vec<ColumnFamily>,
    cluster_states: Vec<TableClusterStateEntry>,
    granularity: TableGranularity,
    deletion_protection: Option<bool>,
    change_stream_enabled: bool,
    schema_digest: Digest,
    family_digest: Digest,
    cluster_state_digest: Digest,
    configuration_digest: Digest,
}

impl TableConfiguration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: TableResource,
        families: Vec<ColumnFamily>,
        cluster_states: Vec<TableClusterStateEntry>,
        granularity: TableGranularity,
        deletion_protection: Option<bool>,
        change_stream_enabled: bool,
    ) -> Result<Self, ModelError> {
        if families.len() > MAX_FAMILIES {
            return Err(ModelError::TooManyFamilies);
        }
        if cluster_states.len() > MAX_CLUSTERS {
            return Err(ModelError::TooManyClusters);
        }
        let mut family_keys = BTreeSet::new();
        for family in &families {
            family.validate_digest()?;
            if !family_keys.insert(family.family_digest()) {
                return Err(ModelError::Duplicate);
            }
            if family.name().is_empty() {
                return Err(ModelError::InvalidValue);
            }
        }
        let mut cluster_keys = BTreeSet::new();
        for entry in &cluster_states {
            if entry.cluster.project() != resource.project()
                || entry.cluster.instance() != resource.instance()
            {
                return Err(ModelError::InvalidScope);
            }
            if !cluster_keys.insert(entry.cluster.digest()) {
                return Err(ModelError::Duplicate);
            }
        }
        let schema_digest = Digest::from_fields(
            "gcp-bigtable-schema/v1",
            &[
                resource.digest().as_str().to_owned(),
                families
                    .iter()
                    .map(|f| f.configuration_digest().as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                format!("{granularity:?}"),
            ],
        );
        let family_digest = Digest::from_fields(
            "gcp-bigtable-family-set/v1",
            &[families
                .iter()
                .map(|f| f.family_digest().as_str().to_owned())
                .collect::<Vec<_>>()
                .join(",")],
        );
        let cluster_state_digest = Digest::from_fields(
            "gcp-bigtable-table-cluster-state-set/v1",
            &[cluster_states
                .iter()
                .map(|e| e.digest().as_str().to_owned())
                .collect::<Vec<_>>()
                .join(",")],
        );
        let configuration_digest = Self::compute_digest(
            &resource,
            &schema_digest,
            &family_digest,
            &cluster_state_digest,
            granularity,
            deletion_protection,
            change_stream_enabled,
        );
        Ok(Self {
            resource,
            families,
            cluster_states,
            granularity,
            deletion_protection,
            change_stream_enabled,
            schema_digest,
            family_digest,
            cluster_state_digest,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn resource(&self) -> &TableResource {
        &self.resource
    }
    #[must_use]
    pub fn families(&self) -> &[ColumnFamily] {
        &self.families
    }
    #[must_use]
    pub fn cluster_states(&self) -> &[TableClusterStateEntry] {
        &self.cluster_states
    }
    #[must_use]
    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }
    #[must_use]
    pub fn family_digest(&self) -> &Digest {
        &self.family_digest
    }
    #[must_use]
    pub fn cluster_state_digest(&self) -> &Digest {
        &self.cluster_state_digest
    }
    #[must_use]
    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
    #[must_use]
    pub const fn granularity(&self) -> TableGranularity {
        self.granularity
    }
    #[must_use]
    pub const fn deletion_protection(&self) -> Option<bool> {
        self.deletion_protection
    }
    #[must_use]
    pub const fn change_stream_enabled(&self) -> bool {
        self.change_stream_enabled
    }
    #[must_use]
    pub fn projection(&self) -> TableProjection {
        TableProjection {
            database: DatabaseProjection::for_scope(
                self.resource.project(),
                self.resource.instance(),
            ),
            table_digest: self.resource.digest(),
            schema_digest: self.schema_digest.clone(),
            family_count: self.families.len() as u16,
            family_digest: self.family_digest.clone(),
            cluster_count: self.cluster_states.len() as u16,
            cluster_state_digest: self.cluster_state_digest.clone(),
            granularity: self.granularity,
            deletion_protection: self.deletion_protection,
            change_stream_enabled: self.change_stream_enabled,
            configuration_digest: self.configuration_digest.clone(),
        }
    }
    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            &self.resource,
            &self.schema_digest,
            &self.family_digest,
            &self.cluster_state_digest,
            self.granularity,
            self.deletion_protection,
            self.change_stream_enabled,
        );
        (expected == self.configuration_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
    fn compute_digest(
        resource: &TableResource,
        schema: &Digest,
        family: &Digest,
        cluster: &Digest,
        granularity: TableGranularity,
        deletion: Option<bool>,
        change_stream: bool,
    ) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-table-configuration/v1",
            &[
                resource.digest().as_str().to_owned(),
                schema.as_str().to_owned(),
                family.as_str().to_owned(),
                cluster.as_str().to_owned(),
                format!("{granularity:?}"),
                deletion.map_or_else(String::new, |v| v.to_string()),
                change_stream.to_string(),
            ],
        )
    }
}

impl fmt::Debug for TableConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableConfiguration")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterState {
    Ready,
    Creating,
    Updating,
    Deleting,
    StateUnspecified,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterStorageType {
    Ssd,
    Hdd,
    Unspecified,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterProjection {
    pub cluster_digest: Digest,
    pub location_digest: Option<Digest>,
    pub state: ClusterState,
    pub serve_nodes: Option<u32>,
    pub storage_type: ClusterStorageType,
    pub encryption_digest: Option<Digest>,
    pub configuration_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClusterConfiguration {
    resource: ClusterResource,
    location_digest: Option<Digest>,
    state: ClusterState,
    serve_nodes: Option<u32>,
    storage_type: ClusterStorageType,
    encryption_digest: Option<Digest>,
    configuration_digest: Digest,
}

impl ClusterConfiguration {
    pub fn new(
        resource: ClusterResource,
        location_digest: Option<Digest>,
        state: ClusterState,
        serve_nodes: Option<u32>,
        storage_type: ClusterStorageType,
        encryption_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if serve_nodes.is_some_and(|v| v > MAX_SERVE_NODES) {
            return Err(ModelError::InvalidValue);
        }
        let configuration_digest = Self::compute_digest(
            &resource,
            location_digest.as_ref(),
            state,
            serve_nodes,
            storage_type,
            encryption_digest.as_ref(),
        );
        Ok(Self {
            resource,
            location_digest,
            state,
            serve_nodes,
            storage_type,
            encryption_digest,
            configuration_digest,
        })
    }
    #[must_use]
    pub fn resource(&self) -> &ClusterResource {
        &self.resource
    }
    #[must_use]
    pub fn location_digest(&self) -> Option<&Digest> {
        self.location_digest.as_ref()
    }
    #[must_use]
    pub const fn state(&self) -> ClusterState {
        self.state
    }
    #[must_use]
    pub const fn serve_nodes(&self) -> Option<u32> {
        self.serve_nodes
    }
    #[must_use]
    pub const fn storage_type(&self) -> ClusterStorageType {
        self.storage_type
    }
    #[must_use]
    pub fn encryption_digest(&self) -> Option<&Digest> {
        self.encryption_digest.as_ref()
    }
    #[must_use]
    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
    #[must_use]
    pub fn projection(&self) -> ClusterProjection {
        ClusterProjection {
            cluster_digest: self.resource.digest(),
            location_digest: self.location_digest.clone(),
            state: self.state,
            serve_nodes: self.serve_nodes,
            storage_type: self.storage_type,
            encryption_digest: self.encryption_digest.clone(),
            configuration_digest: self.configuration_digest.clone(),
        }
    }
    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            &self.resource,
            self.location_digest.as_ref(),
            self.state,
            self.serve_nodes,
            self.storage_type,
            self.encryption_digest.as_ref(),
        );
        (expected == self.configuration_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
    fn compute_digest(
        resource: &ClusterResource,
        location: Option<&Digest>,
        state: ClusterState,
        nodes: Option<u32>,
        storage: ClusterStorageType,
        encryption: Option<&Digest>,
    ) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-cluster-configuration/v1",
            &[
                resource.digest().as_str().to_owned(),
                location.map_or_else(String::new, |v| v.as_str().to_owned()),
                format!("{state:?}"),
                nodes.map_or_else(String::new, |v| v.to_string()),
                format!("{storage:?}"),
                encryption.map_or_else(String::new, |v| v.as_str().to_owned()),
            ],
        )
    }
}

impl fmt::Debug for ClusterConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterConfiguration")
            .field("projection", &self.projection())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TablePosture {
    Ready,
    Creating,
    Degraded,
    Partial,
    AccessLost,
    ProviderUnknown,
    Stale,
    Tampered,
    Pagination,
    Truncated,
    Misconfigured,
    Revoked,
}

impl TablePosture {
    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub database_digest: Digest,
    pub table_digest: Option<Digest>,
    pub schema_digest: Option<Digest>,
    pub family_digest: Option<Digest>,
    pub cluster_digest: Option<Digest>,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
    pub result_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    MalformedResponse,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: String,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

/// A page token is immediately reduced to a digest and must be bound to an
/// exact scope/request before it can be used. Bigtable GET is unpaged today.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u8,
}

impl OpaquePageToken {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let bytes = value.as_ref();
        if bytes.is_empty()
            || bytes.len() > MAX_PAGE_TOKEN_BYTES
            || bytes.iter().any(u8::is_ascii_whitespace)
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self {
            token_digest: Digest::from_bytes(bytes),
            binding_digest: Digest::from_text("unbound-bigtable-page-token"),
            page_number: 1,
        })
    }
    pub fn bound(
        value: impl AsRef<[u8]>,
        scope_digest: &Digest,
        request_digest: &Digest,
    ) -> Result<Self, ModelError> {
        let mut token = Self::new(value)?;
        token.binding_digest = Self::binding(scope_digest, request_digest);
        Ok(token)
    }
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.token_digest.clone()
    }
    #[must_use]
    pub const fn page_number(&self) -> u8 {
        self.page_number
    }
    pub fn validate_binding(
        &self,
        scope_digest: &Digest,
        request_digest: &Digest,
    ) -> Result<(), ModelError> {
        (self.binding_digest == Self::binding(scope_digest, request_digest))
            .then_some(())
            .ok_or(ModelError::PageTokenBindingMismatch)
    }
    fn binding(scope: &Digest, request: &Digest) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-page-token-binding/v1",
            &[scope.as_str().to_owned(), request.as_str().to_owned()],
        )
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
