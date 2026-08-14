//! Typed Confluent scope, opaque credentials, and bounded non-native
//! projections.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ConfluentStreamResultError, MAX_IDENTIFIER_BYTES, MAX_OBSERVATION_WINDOW_SECONDS,
    MAX_PARTITIONS, MAX_TIMESTAMP_COUNT, Result, digest_serialized, sha256_hex, validate_digest,
    validate_identifier, validate_text,
};

/// A lowercase SHA-256 digest. Digests are the only representation used for
/// provider payloads, API-key handles, metric values, and recorded evidence.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_hex(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 24);
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

define_identifier!(OrganizationId, "organizationId");
define_identifier!(EnvironmentId, "environmentId");
define_identifier!(ClusterId, "clusterId");
define_identifier!(ConnectorId, "connectorId");
define_identifier!(ConsumerGroupId, "consumerGroupId");
define_identifier!(ProjectId, "projectId");
define_identifier!(MissionId, "missionId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(RegistrationId, "registrationId");

/// Semantic version bound to a registration, independent of crate packaging.
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
            return Err(ConfluentStreamResultError::InvalidIdentifier {
                field: "pluginVersion",
            });
        }
        let mut numbers = [0_u16; 3];
        for (index, part) in parsed.into_iter().enumerate() {
            numbers[index] = part
                .expect("checked version part")
                .parse::<u16>()
                .map_err(|_| ConfluentStreamResultError::InvalidIdentifier {
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

/// The only credential kind accepted by this Layer-1 boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ResourceScopedApiKey,
}

/// A resource scope for an API key. The opaque key handle is never retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ApiKeyResourceScope {
    CloudResourceManagement,
    Organization(String),
}

impl ApiKeyResourceScope {
    fn validate(&self) -> Result<()> {
        if let Self::Organization(id) = self {
            validate_identifier(id, "apiKeyOrganizationScope")?;
        }
        Ok(())
    }

    fn as_label(&self) -> String {
        match self {
            Self::CloudResourceManagement => "cloud_resource_management".to_owned(),
            Self::Organization(id) => format!("organization:{id}"),
        }
    }
}

/// An opaque, resource-scoped API-key reference. It intentionally has no
/// `Serialize`, `Display`, or secret-bearing `Debug` implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    resource_scope_digest: Digest,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn resource_scoped_api_key(
        opaque_id: impl Into<String>,
        resource_scope: ApiKeyResourceScope,
        revision: u64,
    ) -> Result<Self> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secretReference", MAX_IDENTIFIER_BYTES)?;
        resource_scope.validate()?;
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidSecretReference);
        }
        let resource_scope_digest = Digest::from_parts(
            "confluent-api-key-resource-scope/v1",
            &[("scope", resource_scope.as_label())],
        );
        let reference_digest = Digest::from_parts(
            "confluent-opaque-api-key-reference/v1",
            &[
                ("kind", "resource_scoped_api_key".to_owned()),
                ("resource_scope", resource_scope_digest.as_str().to_owned()),
                ("opaque_id", opaque_id),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind: SecretKind::ResourceScopedApiKey,
            resource_scope_digest,
            reference_digest,
            revision,
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn resource_scope_digest(&self) -> &Digest {
        &self.resource_scope_digest
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
        if self.kind != SecretKind::ResourceScopedApiKey
            || self.revision == 0
            || self.revoked && self.reference_digest.as_str().is_empty()
        {
            return Err(ConfluentStreamResultError::InvalidSecretReference);
        }
        self.resource_scope_digest.validate()?;
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("resource_scope_digest", &self.resource_scope_digest)
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// A versioned Confluent resource identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceIdentity {
    pub id: String,
    pub revision: u64,
}

impl ResourceIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "resourceId")?;
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "resourceId")?;
        if self.revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TopicIdentity {
    pub name: String,
    pub revision: u64,
}

impl TopicIdentity {
    pub fn new(name: impl Into<String>, revision: u64) -> Result<Self> {
        let name = name.into();
        validate_identifier(&name, "topicName")?;
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(Self { name, revision })
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.name, "topicName")?;
        if self.revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionIdentity {
    pub id: u32,
    pub revision: u64,
}

impl PartitionIdentity {
    pub fn new(id: u32, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(())
    }
}

/// A closed, bounded Metrics API observation window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricWindow {
    pub start_epoch_seconds: i64,
    pub end_epoch_seconds: i64,
}

impl MetricWindow {
    pub fn new(start_epoch_seconds: i64, end_epoch_seconds: i64) -> Result<Self> {
        let window = Self {
            start_epoch_seconds,
            end_epoch_seconds,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<()> {
        if self.start_epoch_seconds <= 0
            || self.end_epoch_seconds <= self.start_epoch_seconds
            || self.end_epoch_seconds - self.start_epoch_seconds > MAX_OBSERVATION_WINDOW_SECONDS
        {
            return Err(ConfluentStreamResultError::InvalidMetricWindow);
        }
        Ok(())
    }

    pub fn contains(&self, timestamp: i64) -> bool {
        (self.start_epoch_seconds..=self.end_epoch_seconds).contains(&timestamp)
    }
}

/// Exact provider, Kafka, and Mission/Project/Work Product scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluentScope {
    pub organization: ResourceIdentity,
    pub environment: ResourceIdentity,
    pub cluster: ResourceIdentity,
    pub topic: TopicIdentity,
    pub connector: ResourceIdentity,
    pub consumer_group: ResourceIdentity,
    pub partition: PartitionIdentity,
    pub project: ResourceIdentity,
    pub mission: ResourceIdentity,
    pub work_product: ResourceIdentity,
    pub observation_window: MetricWindow,
    pub policy_revision: u64,
}

impl ConfluentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: ResourceIdentity,
        environment: ResourceIdentity,
        cluster: ResourceIdentity,
        topic: TopicIdentity,
        connector: ResourceIdentity,
        consumer_group: ResourceIdentity,
        partition: PartitionIdentity,
        project: ResourceIdentity,
        mission: ResourceIdentity,
        work_product: ResourceIdentity,
        observation_window: MetricWindow,
        policy_revision: u64,
    ) -> Result<Self> {
        let scope = Self {
            organization,
            environment,
            cluster,
            topic,
            connector,
            consumer_group,
            partition,
            project,
            mission,
            work_product,
            observation_window,
            policy_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        organization_id: impl Into<String>,
        environment_id: impl Into<String>,
        cluster_id: impl Into<String>,
        topic_name: impl Into<String>,
        connector_id: impl Into<String>,
        consumer_group_id: impl Into<String>,
        partition_id: u32,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        observation_window: MetricWindow,
        policy_revision: u64,
    ) -> Result<Self> {
        Self::new(
            ResourceIdentity::new(organization_id, 1)?,
            ResourceIdentity::new(environment_id, 1)?,
            ResourceIdentity::new(cluster_id, 1)?,
            TopicIdentity::new(topic_name, 1)?,
            ResourceIdentity::new(connector_id, 1)?,
            ResourceIdentity::new(consumer_group_id, 1)?,
            PartitionIdentity::new(partition_id, 1)?,
            ResourceIdentity::new(project_id, 1)?,
            ResourceIdentity::new(mission_id, 1)?,
            ResourceIdentity::new(work_product_id, 1)?,
            observation_window,
            policy_revision,
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.organization.validate()?;
        self.environment.validate()?;
        self.cluster.validate()?;
        self.topic.validate()?;
        self.connector.validate()?;
        self.consumer_group.validate()?;
        self.partition.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.observation_window.validate()?;
        if self.policy_revision == 0 {
            return Err(ConfluentStreamResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_parts(
            "confluent-scope-revisions/v1",
            &[
                ("organization", self.organization.revision.to_string()),
                ("environment", self.environment.revision.to_string()),
                ("cluster", self.cluster.revision.to_string()),
                ("topic", self.topic.revision.to_string()),
                ("connector", self.connector.revision.to_string()),
                ("consumer_group", self.consumer_group.revision.to_string()),
                ("partition", self.partition.revision.to_string()),
                ("project", self.project.revision.to_string()),
                ("mission", self.mission.revision.to_string()),
                ("work_product", self.work_product.revision.to_string()),
                ("policy", self.policy_revision.to_string()),
            ],
        )
    }
}

/// Alias spelling used by callers that prefer the more explicit name.
pub type ConfluentStreamScope = ConfluentScope;

/// Exact read-only permission set. No provider mutation permission can enter
/// a registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<String>,
    pub revision: u64,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only(revision: u64) -> Result<Self> {
        Self::new(
            Self::expected_permissions().into_iter().map(str::to_owned),
            revision,
        )
    }

    pub fn new(permissions: impl IntoIterator<Item = String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidPermissionSnapshot);
        }
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let expected = Self::expected_permissions()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if permissions != expected {
            return Err(ConfluentStreamResultError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_serialized(&(permissions.clone(), revision));
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    fn expected_permissions() -> [&'static str; 9] {
        [
            "organization.read",
            "environment.read",
            "cluster.read",
            "topic.read",
            "connector.read",
            "connector.status.read",
            "consumer_group.read",
            "consumer_group.lag.read",
            "metrics.read",
        ]
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::expected_permissions()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if self.revision == 0 || self.permissions != expected {
            return Err(ConfluentStreamResultError::InvalidPermissionSnapshot);
        }
        if self.digest != Digest::from_serialized(&(self.permissions.clone(), self.revision)) {
            return Err(ConfluentStreamResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
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
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStatus {
    Provisioning,
    Running,
    Failed,
    Degraded,
    Paused,
    Restarting,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Running,
    Stopped,
    Unassigned,
    Restarting,
    SystemError,
    UserActionableError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerGroupStatus {
    Stable,
    Empty,
    Dead,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Lag,
    Throughput,
    Latency,
}

impl MetricKind {
    pub const fn is_allowlisted(self) -> bool {
        matches!(self, Self::Lag | Self::Throughput | Self::Latency)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
    ProviderUnknown,
}

impl ProjectionCompleteness {
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::ProviderUnknown, _) | (_, Self::ProviderUnknown) => Self::ProviderUnknown,
            (Self::Partial, _) | (_, Self::Partial) => Self::Partial,
            _ => Self::Complete,
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// A digest and timestamp only; no metric value or provider payload is kept.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedMetricDigest {
    pub kind: MetricKind,
    pub value_digest: Digest,
    pub observed_at_epoch_seconds: i64,
}

impl BoundedMetricDigest {
    pub fn new(
        kind: MetricKind,
        value_digest: Digest,
        observed_at_epoch_seconds: i64,
    ) -> Result<Self> {
        if !kind.is_allowlisted() || observed_at_epoch_seconds <= 0 {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        value_digest.validate()?;
        Ok(Self {
            kind,
            value_digest,
            observed_at_epoch_seconds,
        })
    }
}

/// Connector task projection. Diagnostic text is represented only by a
/// digest, so malformed provider messages cannot cross the boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorTaskProjection {
    pub task_id: String,
    pub revision: u64,
    pub status: TaskStatus,
    pub diagnostic_digest: Option<Digest>,
}

impl ConnectorTaskProjection {
    pub fn new(
        task_id: impl Into<String>,
        revision: u64,
        status: TaskStatus,
        diagnostic_digest: Option<Digest>,
    ) -> Result<Self> {
        let task_id = task_id.into();
        validate_identifier(&task_id, "taskId")?;
        if revision == 0 {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        if let Some(digest) = &diagnostic_digest {
            digest.validate()?;
        }
        Ok(Self {
            task_id,
            revision,
            status,
            diagnostic_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.task_id.clone(),
            self.revision,
            self.status,
            self.diagnostic_digest.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorStatusProjection {
    pub scope_digest: Digest,
    pub connector: ResourceIdentity,
    pub observation_revision: u64,
    pub status: ConnectorStatus,
    pub tasks: Vec<ConnectorTaskProjection>,
    pub observed_at_epoch_seconds: i64,
    pub completeness: ProjectionCompleteness,
    pub projection_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
}

impl ConnectorStatusProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        connector: ResourceIdentity,
        observation_revision: u64,
        status: ConnectorStatus,
        tasks: Vec<ConnectorTaskProjection>,
        observed_at_epoch_seconds: i64,
        completeness: ProjectionCompleteness,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut projection = Self {
            scope_digest,
            connector,
            observation_revision,
            status,
            tasks,
            observed_at_epoch_seconds,
            completeness,
            projection_digest: Digest::from_text("unsealed-confluent-connector-projection"),
            provenance,
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        projection.validate_integrity()?;
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_digest(self.scope_digest.as_str(), "scopeDigest")?;
        self.connector.validate()?;
        if self.observation_revision == 0 || self.tasks.len() > MAX_PARTITIONS {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        let mut task_ids = BTreeSet::new();
        for task in &self.tasks {
            task.validate()?;
            if !task_ids.insert(task.task_id.clone()) {
                return Err(ConfluentStreamResultError::InvalidProjection);
            }
        }
        if self.observed_at_epoch_seconds <= 0
            || self.connected
            || self.native
            || self.projection_digest != self.calculate_digest()
        {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        Ok(())
    }

    pub fn validate_monotonic_against(&self, previous: &Self) -> Result<()> {
        if self.scope_digest != previous.scope_digest || self.connector.id != previous.connector.id
        {
            return Err(ConfluentStreamResultError::ScopeMismatch);
        }
        if self.observation_revision < previous.observation_revision {
            return Err(ConfluentStreamResultError::ConnectorTaskMonotonicity);
        }
        for task in &self.tasks {
            if let Some(old) = previous
                .tasks
                .iter()
                .find(|item| item.task_id == task.task_id)
                && task.revision < old.revision
            {
                return Err(ConfluentStreamResultError::ConnectorTaskMonotonicity);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.connector,
            self.observation_revision,
            self.status,
            &self.tasks,
            self.observed_at_epoch_seconds,
            self.completeness,
            self.provenance,
            false,
            false,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerGroupLagProjection {
    pub scope_digest: Digest,
    pub consumer_group: ResourceIdentity,
    pub observation_revision: u64,
    pub status: ConsumerGroupStatus,
    pub partition_count: usize,
    pub lag_digest: Digest,
    pub timestamps: Vec<i64>,
    pub pages_read: usize,
    pub completeness: ProjectionCompleteness,
    pub projection_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
}

impl ConsumerGroupLagProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        consumer_group: ResourceIdentity,
        observation_revision: u64,
        status: ConsumerGroupStatus,
        partition_count: usize,
        lag_digest: Digest,
        timestamps: Vec<i64>,
        pages_read: usize,
        completeness: ProjectionCompleteness,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut projection = Self {
            scope_digest,
            consumer_group,
            observation_revision,
            status,
            partition_count,
            lag_digest,
            timestamps,
            pages_read,
            completeness,
            projection_digest: Digest::from_text("unsealed-confluent-lag-projection"),
            provenance,
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        projection.validate_integrity()?;
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_digest(self.scope_digest.as_str(), "scopeDigest")?;
        self.consumer_group.validate()?;
        validate_digest(self.lag_digest.as_str(), "lagDigest")?;
        if self.observation_revision == 0
            || self.partition_count > MAX_PARTITIONS
            || self.timestamps.len() > MAX_TIMESTAMP_COUNT
            || self.pages_read == 0
            || self.pages_read > crate::MAX_PAGES
            || self.timestamps.iter().any(|timestamp| *timestamp <= 0)
            || self.connected
            || self.native
            || self.projection_digest != self.calculate_digest()
        {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        Ok(())
    }

    pub fn validate_monotonic_against(&self, previous: &Self) -> Result<()> {
        if self.scope_digest != previous.scope_digest
            || self.consumer_group != previous.consumer_group
            || self.observation_revision < previous.observation_revision
        {
            return Err(ConfluentStreamResultError::ConsumerGroupMonotonicity);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.consumer_group,
            self.observation_revision,
            self.status,
            self.partition_count,
            &self.lag_digest,
            &self.timestamps,
            self.pages_read,
            self.completeness,
            self.provenance,
            false,
            false,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricProjection {
    pub scope_digest: Digest,
    pub window: MetricWindow,
    pub lag_digest: Option<Digest>,
    pub throughput_digest: Option<Digest>,
    pub latency_digest: Option<Digest>,
    pub timestamps: Vec<i64>,
    pub completeness: ProjectionCompleteness,
    pub projection_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
}

impl MetricProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        window: MetricWindow,
        lag_digest: Option<Digest>,
        throughput_digest: Option<Digest>,
        latency_digest: Option<Digest>,
        timestamps: Vec<i64>,
        completeness: ProjectionCompleteness,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut projection = Self {
            scope_digest,
            window,
            lag_digest,
            throughput_digest,
            latency_digest,
            timestamps,
            completeness,
            projection_digest: Digest::from_text("unsealed-confluent-metric-projection"),
            provenance,
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        projection.validate_integrity()?;
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_digest(self.scope_digest.as_str(), "scopeDigest")?;
        self.window.validate()?;
        for digest in [
            &self.lag_digest,
            &self.throughput_digest,
            &self.latency_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        if self.timestamps.len() > MAX_TIMESTAMP_COUNT
            || self
                .timestamps
                .iter()
                .any(|timestamp| !self.window.contains(*timestamp))
            || self.connected
            || self.native
            || self.projection_digest != self.calculate_digest()
        {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        Ok(())
    }

    pub fn digest_for(&self, kind: MetricKind) -> Option<&Digest> {
        match kind {
            MetricKind::Lag => self.lag_digest.as_ref(),
            MetricKind::Throughput => self.throughput_digest.as_ref(),
            MetricKind::Latency => self.latency_digest.as_ref(),
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.window,
            &self.lag_digest,
            &self.throughput_digest,
            &self.latency_digest,
            &self.timestamps,
            self.completeness,
            self.provenance,
            false,
            false,
        ))
    }
}
