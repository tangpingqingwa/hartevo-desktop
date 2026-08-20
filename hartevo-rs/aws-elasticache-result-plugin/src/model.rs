use std::{fmt, time::Duration as StdDuration};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsElastiCacheError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_EVENTS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_SERVICE_UPDATES,
};

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
            Err(AwsElastiCacheError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsElastiCacheError::InvalidDigest)
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

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
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

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! typed_id {
    ($name:ident, $field:literal, $validator:expr, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsElastiCacheError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsElastiCacheError::InvalidIdentifier { field: $field })
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

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.digest().0)
            }
        }
    };
}

typed_id!(
    AwsAccountId,
    "account",
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()),
    "aws-elasticache-account/v1"
);
typed_id!(
    AwsRegion,
    "region",
    |value: &str| valid_identifier(value, 64),
    "aws-elasticache-region/v1"
);
typed_id!(
    CacheClusterId,
    "cache-cluster",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-elasticache-cache-cluster/v1"
);
typed_id!(
    ReplicationGroupId,
    "replication-group",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-elasticache-replication-group/v1"
);
typed_id!(
    ProjectId,
    "project",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "hartevo-project/v1"
);
typed_id!(
    MissionId,
    "mission",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "hartevo-mission/v1"
);
typed_id!(
    WorkProductId,
    "work-product",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "hartevo-work-product/v1"
);
typed_id!(
    NodeGroupId,
    "node-group",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-elasticache-node-group/v1"
);

pub type AccountId = AwsAccountId;
pub type Region = AwsRegion;
pub type CacheResource = ElastiCacheResource;
pub type AwsElastiCacheResource = ElastiCacheResource;
pub type AwsElastiCacheSecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsElastiCacheError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Result<Self> {
        id.validate()?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-project-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl Serialize for ProjectBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ProjectBinding", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Result<Self> {
        id.validate()?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-mission-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl Serialize for MissionBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MissionBinding", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Result<Self> {
        id.validate()?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-work-product-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl Serialize for WorkProductBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("WorkProductBinding", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEngine {
    Redis,
    Valkey,
    Memcached,
    Unknown,
}

impl CacheEngine {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Redis => "redis",
            Self::Valkey => "valkey",
            Self::Memcached => "memcached",
            Self::Unknown => "unknown",
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-engine/v1",
            &[("engine", self.as_str().to_owned())],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGroupBinding {
    pub id: NodeGroupId,
    pub revision: Revision,
}

impl NodeGroupBinding {
    pub fn new(id: NodeGroupId, revision: Revision) -> Result<Self> {
        id.validate()?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-node-group-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

impl Serialize for NodeGroupBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("NodeGroupBinding", 2)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventWindow {
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    pub revision: Revision,
}

impl EventWindow {
    pub fn new(
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        revision: Revision,
    ) -> Result<Self> {
        if let (Some(start), Some(end)) = (start_time, end_time)
            && (start > end || end - start > Duration::days(31))
        {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        Ok(Self {
            start_time,
            end_time,
            revision,
        })
    }

    pub fn unbounded() -> Self {
        Self {
            start_time: None,
            end_time: None,
            revision: Revision(1),
        }
    }

    pub fn recent(
        observed_at: DateTime<Utc>,
        duration: Duration,
        revision: Revision,
    ) -> Result<Self> {
        Self::new(Some(observed_at - duration), Some(observed_at), revision)
    }

    pub fn start_time(&self) -> Option<DateTime<Utc>> {
        self.start_time
    }

    pub fn end_time(&self) -> Option<DateTime<Utc>> {
        self.end_time
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-event-window/v1",
            &[
                (
                    "start",
                    self.start_time
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "end",
                    self.end_time
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("revision", self.revision.value().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        Self::new(self.start_time, self.end_time, self.revision).map(|_| ())
    }
}

impl Serialize for EventWindow {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("EventWindow", 4)?;
        state.serialize_field("startTime", &self.start_time)?;
        state.serialize_field("endTime", &self.end_time)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("windowDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElastiCacheResourceKind {
    CacheCluster,
    ReplicationGroup,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ElastiCacheResource {
    CacheCluster {
        id: CacheClusterId,
        revision: Revision,
    },
    ReplicationGroup {
        id: ReplicationGroupId,
        revision: Revision,
    },
}

impl ElastiCacheResource {
    pub fn cache_cluster(id: CacheClusterId, revision: Revision) -> Self {
        Self::CacheCluster { id, revision }
    }

    pub fn replication_group(id: ReplicationGroupId, revision: Revision) -> Self {
        Self::ReplicationGroup { id, revision }
    }

    pub const fn kind(&self) -> ElastiCacheResourceKind {
        match self {
            Self::CacheCluster { .. } => ElastiCacheResourceKind::CacheCluster,
            Self::ReplicationGroup { .. } => ElastiCacheResourceKind::ReplicationGroup,
        }
    }

    pub fn id_digest(&self) -> Digest {
        match self {
            Self::CacheCluster { id, .. } => id.digest(),
            Self::ReplicationGroup { id, .. } => id.digest(),
        }
    }

    pub const fn revision(&self) -> Revision {
        match self {
            Self::CacheCluster { revision, .. } | Self::ReplicationGroup { revision, .. } => {
                *revision
            }
        }
    }

    pub fn id_as_str(&self) -> &str {
        match self {
            Self::CacheCluster { id, .. } => id.as_str(),
            Self::ReplicationGroup { id, .. } => id.as_str(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-resource/v1",
            &[
                ("kind", format!("{:?}", self.kind())),
                ("id", self.id_digest().to_string()),
                ("revision", self.revision().value().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::CacheCluster { id, .. } => id.validate(),
            Self::ReplicationGroup { id, .. } => id.validate(),
        }
    }
}

impl fmt::Debug for ElastiCacheResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElastiCacheResource")
            .field("kind", &self.kind())
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision())
            .finish()
    }
}

impl Serialize for ElastiCacheResource {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ElastiCacheResource", 3)?;
        state.serialize_field("kind", &self.kind())?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("revision", &self.revision())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsElastiCacheScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub resource: ElastiCacheResource,
    pub engine: CacheEngine,
    pub node_group: Option<NodeGroupBinding>,
    pub failover: FailoverPosture,
    pub event_window: EventWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub scope_revision: Revision,
}

impl AwsElastiCacheScope {
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        resource: ElastiCacheResource,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        Self::with_details(
            account_id,
            region,
            resource,
            CacheEngine::Unknown,
            None,
            FailoverPosture::Unknown,
            EventWindow::unbounded(),
            project,
            mission,
            work_product,
            Revision::new(1)?,
        )
    }

    pub fn with_details(
        account_id: AwsAccountId,
        region: AwsRegion,
        resource: ElastiCacheResource,
        engine: CacheEngine,
        node_group: Option<NodeGroupBinding>,
        failover: FailoverPosture,
        event_window: EventWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        scope_revision: Revision,
    ) -> Result<Self> {
        let scope = Self {
            account_id,
            region,
            resource,
            engine,
            node_group,
            failover,
            event_window,
            project,
            mission,
            work_product,
            scope_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_scope_revision(
        account_id: AwsAccountId,
        region: AwsRegion,
        resource: ElastiCacheResource,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        scope_revision: Revision,
    ) -> Result<Self> {
        Self::with_details(
            account_id,
            region,
            resource,
            CacheEngine::Unknown,
            None,
            FailoverPosture::Unknown,
            EventWindow::unbounded(),
            project,
            mission,
            work_product,
            scope_revision,
        )
    }

    pub fn cache_cluster(
        account_id: AwsAccountId,
        region: AwsRegion,
        id: CacheClusterId,
        resource_revision: Revision,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        Self::new(
            account_id,
            region,
            ElastiCacheResource::cache_cluster(id, resource_revision),
            project,
            mission,
            work_product,
        )
    }

    pub fn replication_group(
        account_id: AwsAccountId,
        region: AwsRegion,
        id: ReplicationGroupId,
        resource_revision: Revision,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        Self::new(
            account_id,
            region,
            ElastiCacheResource::replication_group(id, resource_revision),
            project,
            mission,
            work_product,
        )
    }

    pub fn for_cache_cluster(
        account_id: AwsAccountId,
        region: AwsRegion,
        id: CacheClusterId,
        resource_revision: Revision,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        Self::cache_cluster(
            account_id,
            region,
            id,
            resource_revision,
            project,
            mission,
            work_product,
        )
    }

    pub fn for_replication_group(
        account_id: AwsAccountId,
        region: AwsRegion,
        id: ReplicationGroupId,
        resource_revision: Revision,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        Self::replication_group(
            account_id,
            region,
            id,
            resource_revision,
            project,
            mission,
            work_product,
        )
    }

    pub fn engine(&self) -> CacheEngine {
        self.engine
    }

    pub fn node_group(&self) -> Option<&NodeGroupBinding> {
        self.node_group.as_ref()
    }

    pub fn failover(&self) -> FailoverPosture {
        self.failover
    }

    pub fn event_window(&self) -> &EventWindow {
        &self.event_window
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-scope/v1",
            &[
                ("account", self.account_id.digest().to_string()),
                ("region", self.region.digest().to_string()),
                ("resource", self.resource.digest().to_string()),
                ("engine", self.engine.digest().to_string()),
                (
                    "node_group",
                    self.node_group
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                ("failover", format!("{:?}", self.failover)),
                ("event_window", self.event_window.digest().to_string()),
                ("project", self.project.digest().to_string()),
                ("mission", self.mission.digest().to_string()),
                ("work_product", self.work_product.digest().to_string()),
                ("scope_revision", self.scope_revision.value().to_string()),
            ],
        )
    }

    pub fn permission_scope_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-permission-scope/v1",
            &[
                ("account", self.account_id.digest().to_string()),
                ("region", self.region.digest().to_string()),
                ("resource", self.resource.digest().to_string()),
            ],
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
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

    pub fn resource_revision(&self) -> Revision {
        self.resource.revision()
    }

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.resource.validate()?;
        if let Some(node_group) = &self.node_group {
            node_group.validate()?;
        }
        self.event_window.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        Ok(())
    }
}

impl fmt::Debug for AwsElastiCacheScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElastiCacheScope")
            .field("account", &self.account_id)
            .field("region", &self.region)
            .field("resource", &self.resource)
            .field("engine", &self.engine)
            .field("node_group", &self.node_group)
            .field("failover", &self.failover)
            .field("event_window", &self.event_window)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("scope_revision", &self.scope_revision)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

impl Serialize for AwsElastiCacheScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsElastiCacheScope", 12)?;
        state.serialize_field("accountDigest", &self.account_id.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("resource", &self.resource)?;
        state.serialize_field("engine", &self.engine)?;
        state.serialize_field("nodeGroup", &self.node_group)?;
        state.serialize_field("failover", &self.failover)?;
        state.serialize_field("eventWindow", &self.event_window)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("scopeRevision", &self.scope_revision)?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    handle: String,
    scope_digest: Digest,
}

impl SecretReference {
    pub fn new(handle: impl Into<String>, scope: &AwsElastiCacheScope) -> Result<Self> {
        let handle = handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsElastiCacheError::InvalidSecretReference);
        }
        Ok(Self {
            handle,
            scope_digest: scope.digest(),
        })
    }

    pub fn for_scope(handle: impl Into<String>, scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new(handle, scope)
    }

    pub fn for_elasticache(handle: impl Into<String>, scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new(handle, scope)
    }

    pub fn sigv4(handle: impl Into<String>, scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new(handle, scope)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-secret-reference/v1",
            &[
                ("handle", self.handle.clone()),
                ("scope", self.scope_digest.to_string()),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub(crate) fn validate_against(&self, scope: &AwsElastiCacheScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || !valid_text(&self.handle, MAX_IDENTIFIER_BYTES, true)
        {
            Err(AwsElastiCacheError::InvalidSecretReference)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque", &true)
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.handle.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSnapshot {
    pub revision: Revision,
    permissions: Vec<String>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        revision: Revision,
        permissions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let permissions = permissions.into_iter().map(Into::into).collect::<Vec<_>>();
        if permissions.is_empty()
            || permissions.iter().any(|permission| {
                !valid_identifier(permission, MAX_IDENTIFIER_BYTES) || permission.contains(' ')
            })
        {
            return Err(AwsElastiCacheError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "aws-elasticache-permission-snapshot/v1",
            &[
                ("revision", revision.value().to_string()),
                ("permissions", permissions.join("\n")),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(Revision::new(revision)?, LAYER1_PERMISSIONS.iter().copied())
    }

    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.digest != Self::new(self.revision, self.permissions.clone())?.digest {
            Err(AwsElastiCacheError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

impl Serialize for PermissionSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PermissionSnapshot", 2)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("permissionDigest", &self.digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentScope {
    scope_digest: Digest,
    expires_at: DateTime<Utc>,
    revoked: bool,
    digest: Digest,
}

impl ConsentScope {
    pub fn for_scope(scope: &AwsElastiCacheScope, expires_at: DateTime<Utc>) -> Result<Self> {
        let consent = Self {
            scope_digest: scope.digest(),
            expires_at,
            revoked: false,
            digest: Digest::zero(),
        };
        let digest = consent.calculate_digest();
        Ok(Self { digest, ..consent })
    }

    pub fn valid_for(scope: &AwsElastiCacheScope, now: DateTime<Utc>) -> Result<Self> {
        Self::for_scope(scope, now + Duration::minutes(15))
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate_for(&self, scope: &AwsElastiCacheScope, now: DateTime<Utc>) -> Result<()> {
        if self.scope_digest != scope.digest() || self.digest != self.calculate_digest() {
            return Err(AwsElastiCacheError::InvalidConsent);
        }
        if self.revoked {
            return Err(AwsElastiCacheError::ConsentRevoked);
        }
        if self.expires_at <= now {
            return Err(AwsElastiCacheError::ConsentExpired);
        }
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.digest = self.calculate_digest();
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-consent/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("expires", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }
}

impl Serialize for ConsentScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConsentScope", 3)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("consentDigest", &self.digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueMarker {
    operation: String,
    scope_digest: Digest,
    filter_digest: Digest,
    token_digest: Digest,
    page_number: u16,
    expires_at: DateTime<Utc>,
}

impl OpaqueMarker {
    pub fn new(
        raw_marker: impl Into<String>,
        operation: impl Into<String>,
        scope: &AwsElastiCacheScope,
        filter_digest: Digest,
        page_number: u16,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let raw_marker = raw_marker.into();
        let operation = operation.into();
        if !valid_text(&raw_marker, MAX_IDENTIFIER_BYTES, true)
            || !valid_identifier(&operation, 128)
            || !matches!(
                operation.as_str(),
                "DescribeCacheClusters"
                    | "DescribeReplicationGroups"
                    | "DescribeEvents"
                    | "DescribeServiceUpdates"
            )
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        filter_digest.validate()?;
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            filter_digest,
            token_digest: Digest::from_parts(
                "aws-elasticache-marker/v1",
                &[("marker", raw_marker)],
            ),
            page_number,
            expires_at,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn validate_for(
        &self,
        operation: &str,
        scope: &AwsElastiCacheScope,
        filter_digest: &Digest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.operation != operation
            || self.scope_digest != scope.digest()
            || self.filter_digest != *filter_digest
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            return Err(AwsElastiCacheError::MarkerMismatch);
        }
        if self.expires_at <= now {
            return Err(AwsElastiCacheError::MarkerExpired);
        }
        Ok(())
    }
}

impl fmt::Debug for OpaqueMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueMarker")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for OpaqueMarker {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaqueMarker", 6)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Available,
    Degraded,
    Unavailable,
    Creating,
    Modifying,
    Failing,
    Replication,
    Rebooting,
    Deleting,
    AccessLoss,
    Unknown,
}

impl HealthState {
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy | Self::Available)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverPosture {
    Enabled,
    Disabled,
    InProgress,
    Failover,
    Completed,
    NotApplicable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePosture {
    Current,
    Pending,
    InProgress,
    Required,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceUpdateStatus {
    Available,
    InProgress,
    Complete,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Healthy,
    Creating,
    Modifying,
    Failing,
    Replication,
    Degraded,
    Unavailable,
    FailoverInProgress,
    UpdateRequired,
    Stale,
    Partial,
    Expired,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Unavailable)
    }

    pub const fn is_non_adoptable(self) -> bool {
        !self.is_review_complete()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheClusterMetadata {
    pub cluster_id: CacheClusterId,
    pub resource_revision: Revision,
    pub engine: CacheEngine,
    pub node_group: Option<NodeGroupBinding>,
    pub health: HealthState,
    pub failover: FailoverPosture,
    pub update: UpdatePosture,
    pub node_count: u16,
    pub observed_at: DateTime<Utc>,
    pub status_digest: Option<Digest>,
}

impl CacheClusterMetadata {
    pub fn new(
        cluster_id: CacheClusterId,
        resource_revision: Revision,
        health: HealthState,
        failover: FailoverPosture,
        update: UpdatePosture,
        node_count: u16,
        observed_at: DateTime<Utc>,
        status_message: Option<String>,
    ) -> Result<Self> {
        if node_count > 512 {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        let status_digest = status_message.map(|message| {
            Digest::from_parts("aws-elasticache-status-message/v1", &[("message", message)])
        });
        Ok(Self {
            cluster_id,
            resource_revision,
            engine: CacheEngine::Unknown,
            node_group: None,
            health,
            failover,
            update,
            node_count,
            observed_at,
            status_digest,
        })
    }

    pub fn for_scope(
        scope: &AwsElastiCacheScope,
        health: HealthState,
        failover: FailoverPosture,
        update: UpdatePosture,
        node_count: u16,
        observed_at: DateTime<Utc>,
        status_message: Option<String>,
    ) -> Result<Self> {
        let (cluster_id, revision) = match &scope.resource {
            ElastiCacheResource::CacheCluster { id, revision } => (id.clone(), *revision),
            ElastiCacheResource::ReplicationGroup { .. } => {
                return Err(AwsElastiCacheError::ScopeMismatch);
            }
        };
        let mut metadata = Self::new(
            cluster_id,
            revision,
            health,
            failover,
            update,
            node_count,
            observed_at,
            status_message,
        )?;
        metadata.engine = scope.engine;
        metadata.node_group = scope.node_group.clone();
        Ok(metadata)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-cache-cluster-metadata/v1",
            &[
                ("id", self.cluster_id.digest().to_string()),
                ("revision", self.resource_revision.value().to_string()),
                ("engine", self.engine.digest().to_string()),
                (
                    "node_group",
                    self.node_group
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                ("health", format!("{:?}", self.health)),
                ("failover", format!("{:?}", self.failover)),
                ("update", format!("{:?}", self.update)),
                ("nodes", self.node_count.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
                (
                    "status",
                    self.status_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &AwsElastiCacheScope) -> Result<()> {
        match &scope.resource {
            ElastiCacheResource::CacheCluster { id, revision }
                if id == &self.cluster_id
                    && revision == &self.resource_revision
                    && self.engine == scope.engine
                    && self.node_group == scope.node_group =>
            {
                Ok(())
            }
            _ => Err(AwsElastiCacheError::RevisionMismatch),
        }
    }
}

impl Serialize for CacheClusterMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CacheClusterMetadata", 10)?;
        state.serialize_field("clusterIdDigest", &self.cluster_id.digest())?;
        state.serialize_field("resourceRevision", &self.resource_revision)?;
        state.serialize_field("engine", &self.engine)?;
        state.serialize_field("nodeGroup", &self.node_group)?;
        state.serialize_field("health", &self.health)?;
        state.serialize_field("failover", &self.failover)?;
        state.serialize_field("update", &self.update)?;
        state.serialize_field("nodeCount", &self.node_count)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationGroupMetadata {
    pub replication_group_id: ReplicationGroupId,
    pub resource_revision: Revision,
    pub engine: CacheEngine,
    pub node_group: Option<NodeGroupBinding>,
    pub health: HealthState,
    pub failover: FailoverPosture,
    pub update: UpdatePosture,
    pub member_count: u16,
    pub observed_at: DateTime<Utc>,
    pub status_digest: Option<Digest>,
}

impl ReplicationGroupMetadata {
    pub fn new(
        replication_group_id: ReplicationGroupId,
        resource_revision: Revision,
        health: HealthState,
        failover: FailoverPosture,
        update: UpdatePosture,
        member_count: u16,
        observed_at: DateTime<Utc>,
        status_message: Option<String>,
    ) -> Result<Self> {
        if member_count > 512 {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        let status_digest = status_message.map(|message| {
            Digest::from_parts("aws-elasticache-status-message/v1", &[("message", message)])
        });
        Ok(Self {
            replication_group_id,
            resource_revision,
            engine: CacheEngine::Unknown,
            node_group: None,
            health,
            failover,
            update,
            member_count,
            observed_at,
            status_digest,
        })
    }

    pub fn for_scope(
        scope: &AwsElastiCacheScope,
        health: HealthState,
        failover: FailoverPosture,
        update: UpdatePosture,
        member_count: u16,
        observed_at: DateTime<Utc>,
        status_message: Option<String>,
    ) -> Result<Self> {
        let (group_id, revision) = match &scope.resource {
            ElastiCacheResource::ReplicationGroup { id, revision } => (id.clone(), *revision),
            ElastiCacheResource::CacheCluster { .. } => {
                return Err(AwsElastiCacheError::ScopeMismatch);
            }
        };
        let mut metadata = Self::new(
            group_id,
            revision,
            health,
            failover,
            update,
            member_count,
            observed_at,
            status_message,
        )?;
        metadata.engine = scope.engine;
        metadata.node_group = scope.node_group.clone();
        Ok(metadata)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-replication-group-metadata/v1",
            &[
                ("id", self.replication_group_id.digest().to_string()),
                ("revision", self.resource_revision.value().to_string()),
                ("engine", self.engine.digest().to_string()),
                (
                    "node_group",
                    self.node_group
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().to_string()),
                ),
                ("health", format!("{:?}", self.health)),
                ("failover", format!("{:?}", self.failover)),
                ("update", format!("{:?}", self.update)),
                ("members", self.member_count.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
                (
                    "status",
                    self.status_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &AwsElastiCacheScope) -> Result<()> {
        match &scope.resource {
            ElastiCacheResource::ReplicationGroup { id, revision }
                if id == &self.replication_group_id
                    && revision == &self.resource_revision
                    && self.engine == scope.engine
                    && self.node_group == scope.node_group =>
            {
                Ok(())
            }
            _ => Err(AwsElastiCacheError::RevisionMismatch),
        }
    }
}

impl Serialize for ReplicationGroupMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ReplicationGroupMetadata", 10)?;
        state.serialize_field(
            "replicationGroupIdDigest",
            &self.replication_group_id.digest(),
        )?;
        state.serialize_field("resourceRevision", &self.resource_revision)?;
        state.serialize_field("engine", &self.engine)?;
        state.serialize_field("nodeGroup", &self.node_group)?;
        state.serialize_field("health", &self.health)?;
        state.serialize_field("failover", &self.failover)?;
        state.serialize_field("update", &self.update)?;
        state.serialize_field("memberCount", &self.member_count)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventProjection {
    pub event_id_digest: Digest,
    pub resource_digest: Digest,
    pub event_code_digest: Digest,
    pub severity: EventSeverity,
    pub occurred_at: DateTime<Utc>,
    pub message_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEvent {
    pub event_id_digest: Digest,
    pub resource_digest: Digest,
    pub event_code_digest: Digest,
    pub severity: EventSeverity,
    pub occurred_at: DateTime<Utc>,
    pub message_digest: Option<Digest>,
}

impl CacheEvent {
    pub fn new(
        resource: &ElastiCacheResource,
        event_id: impl Into<String>,
        event_code: impl Into<String>,
        severity: EventSeverity,
        occurred_at: DateTime<Utc>,
        raw_message: Option<String>,
    ) -> Result<Self> {
        let event_id = event_id.into();
        let event_code = event_code.into();
        if !valid_text(&event_id, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&event_code, MAX_IDENTIFIER_BYTES, true)
        {
            return Err(AwsElastiCacheError::InvalidIdentifier { field: "event" });
        }
        Ok(Self {
            event_id_digest: Digest::from_parts("aws-elasticache-event-id/v1", &[("id", event_id)]),
            resource_digest: resource.digest(),
            event_code_digest: Digest::from_parts(
                "aws-elasticache-event-code/v1",
                &[("code", event_code)],
            ),
            severity,
            occurred_at,
            message_digest: raw_message.map(|message| {
                Digest::from_parts("aws-elasticache-event-message/v1", &[("message", message)])
            }),
        })
    }

    pub fn projection(&self) -> EventProjection {
        EventProjection {
            event_id_digest: self.event_id_digest.clone(),
            resource_digest: self.resource_digest.clone(),
            event_code_digest: self.event_code_digest.clone(),
            severity: self.severity,
            occurred_at: self.occurred_at,
            message_digest: self.message_digest.clone(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-event/v1",
            &[
                ("id", self.event_id_digest.to_string()),
                ("resource", self.resource_digest.to_string()),
                ("code", self.event_code_digest.to_string()),
                ("severity", format!("{:?}", self.severity)),
                ("occurred_at", self.occurred_at.to_rfc3339()),
                (
                    "message",
                    self.message_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &AwsElastiCacheScope) -> Result<()> {
        if self.resource_digest != scope.resource.digest() {
            Err(AwsElastiCacheError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceUpdateProjection {
    pub update_id_digest: Digest,
    pub resource_digest: Digest,
    pub status: ServiceUpdateStatus,
    pub severity: EventSeverity,
    pub update_posture: UpdatePosture,
    pub available_at: Option<DateTime<Utc>>,
    pub required_apply_by: Option<DateTime<Utc>>,
    pub description_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceUpdateMetadata {
    pub update_id_digest: Digest,
    pub resource_digest: Digest,
    pub status: ServiceUpdateStatus,
    pub severity: EventSeverity,
    pub update_posture: UpdatePosture,
    pub available_at: Option<DateTime<Utc>>,
    pub required_apply_by: Option<DateTime<Utc>>,
    pub description_digest: Option<Digest>,
}

impl ServiceUpdateMetadata {
    pub fn new(
        resource: &ElastiCacheResource,
        update_id: impl Into<String>,
        status: ServiceUpdateStatus,
        severity: EventSeverity,
        update_posture: UpdatePosture,
        available_at: Option<DateTime<Utc>>,
        required_apply_by: Option<DateTime<Utc>>,
        raw_description: Option<String>,
    ) -> Result<Self> {
        let update_id = update_id.into();
        if !valid_text(&update_id, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsElastiCacheError::InvalidIdentifier {
                field: "service-update",
            });
        }
        if let (Some(available), Some(deadline)) = (available_at, required_apply_by)
            && deadline < available
        {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        Ok(Self {
            update_id_digest: Digest::from_parts(
                "aws-elasticache-service-update-id/v1",
                &[("id", update_id)],
            ),
            resource_digest: resource.digest(),
            status,
            severity,
            update_posture,
            available_at,
            required_apply_by,
            description_digest: raw_description.map(|description| {
                Digest::from_parts(
                    "aws-elasticache-service-update-description/v1",
                    &[("description", description)],
                )
            }),
        })
    }

    pub fn projection(&self) -> ServiceUpdateProjection {
        ServiceUpdateProjection {
            update_id_digest: self.update_id_digest.clone(),
            resource_digest: self.resource_digest.clone(),
            status: self.status,
            severity: self.severity,
            update_posture: self.update_posture,
            available_at: self.available_at,
            required_apply_by: self.required_apply_by,
            description_digest: self.description_digest.clone(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-service-update/v1",
            &[
                ("id", self.update_id_digest.to_string()),
                ("resource", self.resource_digest.to_string()),
                ("status", format!("{:?}", self.status)),
                ("severity", format!("{:?}", self.severity)),
                ("posture", format!("{:?}", self.update_posture)),
                (
                    "available",
                    self.available_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "deadline",
                    self.required_apply_by
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "description",
                    self.description_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &AwsElastiCacheScope) -> Result<()> {
        if self.resource_digest != scope.resource.digest() {
            Err(AwsElastiCacheError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheClusterProjection {
    pub resource_id_digest: Digest,
    pub resource_revision: Revision,
    pub engine: CacheEngine,
    pub node_group: Option<NodeGroupBinding>,
    pub health: HealthState,
    pub failover: FailoverPosture,
    pub update_posture: UpdatePosture,
    pub node_count: u16,
    pub observed_at: DateTime<Utc>,
    pub status_digest: Option<Digest>,
}

impl From<&CacheClusterMetadata> for CacheClusterProjection {
    fn from(value: &CacheClusterMetadata) -> Self {
        Self {
            resource_id_digest: value.cluster_id.digest(),
            resource_revision: value.resource_revision,
            engine: value.engine,
            node_group: value.node_group.clone(),
            health: value.health,
            failover: value.failover,
            update_posture: value.update,
            node_count: value.node_count,
            observed_at: value.observed_at,
            status_digest: value.status_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationGroupProjection {
    pub resource_id_digest: Digest,
    pub resource_revision: Revision,
    pub engine: CacheEngine,
    pub node_group: Option<NodeGroupBinding>,
    pub health: HealthState,
    pub failover: FailoverPosture,
    pub update_posture: UpdatePosture,
    pub member_count: u16,
    pub observed_at: DateTime<Utc>,
    pub status_digest: Option<Digest>,
}

impl From<&ReplicationGroupMetadata> for ReplicationGroupProjection {
    fn from(value: &ReplicationGroupMetadata) -> Self {
        Self {
            resource_id_digest: value.replication_group_id.digest(),
            resource_revision: value.resource_revision,
            engine: value.engine,
            node_group: value.node_group.clone(),
            health: value.health,
            failover: value.failover,
            update_posture: value.update,
            member_count: value.member_count,
            observed_at: value.observed_at,
            status_digest: value.status_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationStatus {
    pub pages: u16,
    pub complete: bool,
    pub truncated: bool,
    pub marker_digest: Option<Digest>,
    pub expired: bool,
}

impl PaginationStatus {
    pub fn complete(pages: u16) -> Self {
        Self {
            pages,
            complete: true,
            truncated: false,
            marker_digest: None,
            expired: false,
        }
    }

    pub fn bounded(pages: u16, marker_digest: Option<Digest>) -> Self {
        Self {
            pages,
            complete: false,
            truncated: true,
            marker_digest,
            expired: false,
        }
    }

    pub fn expired(pages: u16, marker_digest: Option<Digest>) -> Self {
        Self {
            pages,
            complete: false,
            truncated: true,
            marker_digest,
            expired: true,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-pagination/v1",
            &[
                ("pages", self.pages.to_string()),
                ("complete", self.complete.to_string()),
                ("truncated", self.truncated.to_string()),
                (
                    "marker",
                    self.marker_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("expired", self.expired.to_string()),
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
    pub scope_digest: Digest,
    pub cluster_digest: Option<Digest>,
    pub replication_group_digest: Option<Digest>,
    pub events_digest: Digest,
    pub service_updates_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn zero() -> Self {
        Self {
            plugin_version_digest: Digest::zero(),
            contract_digest: Digest::zero(),
            provider_digest: Digest::zero(),
            api_digest: Digest::zero(),
            permission_digest: Digest::zero(),
            scope_digest: Digest::zero(),
            cluster_digest: None,
            replication_group_digest: None,
            events_digest: Digest::zero(),
            service_updates_digest: Digest::zero(),
            evidence_digest: Digest::zero(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsElastiCacheError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(AwsElastiCacheError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_page_count(page_count: u16) -> Result<()> {
    if page_count == 0 || page_count > MAX_PAGES {
        Err(AwsElastiCacheError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_collection_bounds(events: usize, updates: usize) -> Result<()> {
    if events > MAX_EVENTS || updates > MAX_SERVICE_UPDATES {
        Err(AwsElastiCacheError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub(crate) fn default_evidence_expiry(observed_at: DateTime<Utc>) -> DateTime<Utc> {
    observed_at
        + Duration::from_std(StdDuration::from_secs(crate::MAX_REQUEST_AGE_SECONDS))
            .expect("bounded evidence age fits chrono")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> AwsElastiCacheScope {
        AwsElastiCacheScope::cache_cluster(
            AwsAccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            CacheClusterId::new("cache-a").expect("cluster"),
            Revision::new(2).expect("resource revision"),
            ProjectBinding::new(
                ProjectId::new("project-a").expect("project"),
                Revision::new(3).expect("project revision"),
            )
            .expect("project binding"),
            MissionBinding::new(
                MissionId::new("mission-a").expect("mission"),
                Revision::new(4).expect("mission revision"),
            )
            .expect("mission binding"),
            WorkProductBinding::new(
                WorkProductId::new("work-product-a").expect("work product"),
                Revision::new(5).expect("work product revision"),
            )
            .expect("work product binding"),
        )
        .expect("scope")
    }

    #[test]
    fn secret_reference_is_opaque_in_json_and_debug() {
        let scope = scope();
        let secret = SecretReference::new("real-sigv4-keyring-handle", &scope).expect("secret");
        assert_eq!(
            serde_json::to_string(&secret).expect("secret json"),
            r#"{"opaque":true}"#
        );
        assert!(!format!("{secret:?}").contains("real-sigv4-keyring-handle"));
    }

    #[test]
    fn marker_serialization_contains_only_digest_material() {
        let scope = scope();
        let marker = OpaqueMarker::new(
            "provider-secret-marker",
            "DescribeCacheClusters",
            &scope,
            Digest::from_text("filter"),
            1,
            Utc::now() + Duration::minutes(5),
        )
        .expect("marker");
        let encoded = serde_json::to_string(&marker).expect("marker json");
        assert!(!encoded.contains("provider-secret-marker"));
        assert!(encoded.contains("tokenDigest"));
    }
}
