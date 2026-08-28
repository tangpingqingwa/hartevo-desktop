//! Safe Layer-1 Airbyte identifiers, exact scope, and non-native projections.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AirbyteSyncResultError, MAX_CATALOG_ENTRIES, MAX_EVIDENCE_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_RECORD_COUNT, Result, digest_serialized, sha256_hex, validate_digest, validate_identifier,
    validate_text,
};

/// A SHA-256 digest used as a public binding, never as a container for a raw
/// provider payload or secret.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub(crate) fn from_hex(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub(crate) fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub(crate) fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub(crate) fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
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

define_identifier!(MissionId, "missionId");
define_identifier!(ProjectId, "projectId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(RegistrationId, "registrationId");
define_identifier!(WorkspaceId, "workspaceId");

/// Semantic version bound to a registration, independent of the crate's
/// packaging version.
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
            return Err(AirbyteSyncResultError::InvalidIdentifier {
                field: "pluginVersion",
            });
        }
        let mut numbers = [0_u16; 3];
        for (index, part) in parsed.into_iter().enumerate() {
            numbers[index] = part
                .expect("checked version part")
                .parse::<u16>()
                .map_err(|_| AirbyteSyncResultError::InvalidIdentifier {
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

/// OAuth or service-token kind without accepting token bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ServiceToken,
}

/// An opaque host-owned credential reference.
///
/// Only a digest of the host handle is retained. The reference has no
/// `Serialize`, `Display`, or secret-bearing `Debug` implementation. Layer 1
/// can bind kind and rotation revision, but cannot resolve credential bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn oauth(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::OAuth, opaque_id, revision)
    }

    pub fn service_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::ServiceToken, opaque_id, revision)
    }

    pub fn new(kind: SecretKind, opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secretReference", MAX_IDENTIFIER_BYTES)?;
        if revision == 0 {
            return Err(AirbyteSyncResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "airbyte-opaque-secret-reference/v1",
            &[
                ("kind", format!("{kind:?}")),
                ("opaque_id", opaque_id),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind,
            reference_digest,
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
            return Err(AirbyteSyncResultError::InvalidSecretReference);
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

/// An Airbyte Cloud workspace origin and provider revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceIdentity {
    pub id: WorkspaceId,
    pub https_host: String,
    pub revision: u64,
}

impl WorkspaceIdentity {
    pub fn new(
        id: impl Into<String>,
        https_host: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let id = WorkspaceId::new(id)?;
        let https_host = normalize_https_host(&https_host.into())?;
        if revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(Self {
            id,
            https_host,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.id.as_str(), &self.https_host, self.revision)?;
        if expected == *self {
            Ok(())
        } else {
            Err(AirbyteSyncResultError::InvalidScope)
        }
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn host(&self) -> &str {
        &self.https_host
    }
}

/// Shared source, destination, and connection identity shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "resourceId")?;
        if self.revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

pub type SourceIdentity = ResourceIdentity;
pub type DestinationIdentity = ResourceIdentity;
pub type ConnectionIdentity = ResourceIdentity;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

/// Exact stream identity and the schema fingerprint expected by the
/// registration. Namespace and name remain typed separately.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamIdentity {
    pub namespace: String,
    pub name: String,
    pub revision: u64,
    pub schema_digest: SchemaFingerprint,
}

impl StreamIdentity {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        revision: u64,
        schema_digest: impl Into<String>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        let name = name.into();
        validate_identifier(&namespace, "streamNamespace")?;
        validate_identifier(&name, "streamName")?;
        if revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(Self {
            namespace,
            name,
            revision,
            schema_digest: SchemaFingerprint::new(schema_digest)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.namespace, "streamNamespace")?;
        validate_identifier(&self.name, "streamName")?;
        self.schema_digest.validate()?;
        if self.revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.namespace, self.name)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobIdentity {
    pub id: String,
    pub revision: u64,
}

impl JobIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "jobId")?;
        if revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "jobId")?;
        if self.revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptIdentity {
    pub id: String,
    pub revision: u64,
}

impl AttemptIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        validate_identifier(&id, "attemptId")?;
        if revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.id, "attemptId")?;
        if self.revision == 0 {
            return Err(AirbyteSyncResultError::InvalidScope);
        }
        Ok(())
    }
}

/// Exact workspace/source/destination/connection/stream/job/attempt and
/// Mission/Project/Work Product fence.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirbyteScope {
    workspace: WorkspaceIdentity,
    source: SourceIdentity,
    destination: DestinationIdentity,
    connection: ConnectionIdentity,
    stream: StreamIdentity,
    job: JobIdentity,
    attempt: AttemptIdentity,
    mission_id: MissionId,
    project_id: ProjectId,
    work_product_id: WorkProductId,
}

impl AirbyteScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: WorkspaceIdentity,
        source: SourceIdentity,
        destination: DestinationIdentity,
        connection: ConnectionIdentity,
        stream: StreamIdentity,
        job: JobIdentity,
        attempt: AttemptIdentity,
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
    ) -> Result<Self> {
        let scope = Self {
            workspace,
            source,
            destination,
            connection,
            stream,
            job,
            attempt,
            mission_id,
            project_id,
            work_product_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        workspace_id: impl Into<String>,
        workspace_host: impl Into<String>,
        workspace_revision: u64,
        source_id: impl Into<String>,
        source_revision: u64,
        destination_id: impl Into<String>,
        destination_revision: u64,
        connection_id: impl Into<String>,
        connection_revision: u64,
        stream_namespace: impl Into<String>,
        stream_name: impl Into<String>,
        stream_revision: u64,
        stream_schema_digest: impl Into<String>,
        job_id: impl Into<String>,
        job_revision: u64,
        attempt_id: impl Into<String>,
        attempt_revision: u64,
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        work_product_id: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            WorkspaceIdentity::new(workspace_id, workspace_host, workspace_revision)?,
            ResourceIdentity::new(source_id, source_revision)?,
            ResourceIdentity::new(destination_id, destination_revision)?,
            ResourceIdentity::new(connection_id, connection_revision)?,
            StreamIdentity::new(
                stream_namespace,
                stream_name,
                stream_revision,
                stream_schema_digest,
            )?,
            JobIdentity::new(job_id, job_revision)?,
            AttemptIdentity::new(attempt_id, attempt_revision)?,
            MissionId::new(mission_id)?,
            ProjectId::new(project_id)?,
            WorkProductId::new(work_product_id)?,
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.workspace.validate()?;
        self.source.validate()?;
        self.destination.validate()?;
        self.connection.validate()?;
        self.stream.validate()?;
        self.job.validate()?;
        self.attempt.validate()?;
        self.mission_id.validate()?;
        self.project_id.validate()?;
        self.work_product_id.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn workspace(&self) -> &WorkspaceIdentity {
        &self.workspace
    }

    pub fn source(&self) -> &SourceIdentity {
        &self.source
    }

    pub fn destination(&self) -> &DestinationIdentity {
        &self.destination
    }

    pub fn connection(&self) -> &ConnectionIdentity {
        &self.connection
    }

    pub fn stream(&self) -> &StreamIdentity {
        &self.stream
    }

    pub fn job(&self) -> &JobIdentity {
        &self.job
    }

    pub fn attempt(&self) -> &AttemptIdentity {
        &self.attempt
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }
}

impl fmt::Debug for AirbyteScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AirbyteScope")
            .field("scope_digest", &self.digest())
            .field("mission_id", &self.mission_id)
            .field("project_id", &self.project_id)
            .field("work_product_id", &self.work_product_id)
            .finish_non_exhaustive()
    }
}

/// A normalized, bounded schema fingerprint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SchemaFingerprint(String);

impl SchemaFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "schemaDigest")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest(&self.0, "schemaDigest")
    }
}

/// Read-only permission snapshot bound into a registration. The exact set is
/// intentionally closed so write permissions cannot be smuggled into Layer 1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<String>,
    revision: u64,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only(revision: u64) -> Result<Self> {
        Self::new(
            [
                "workspace.read",
                "source.read",
                "destination.read",
                "connection.read",
                "stream.read",
                "job.read",
                "attempt.read",
                "schema.read",
            ]
            .into_iter()
            .map(str::to_owned),
            revision,
        )
    }

    pub fn new(permissions: impl IntoIterator<Item = String>, revision: u64) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if revision == 0
            || permissions.iter().any(|permission| {
                permission.is_empty()
                    || permission.len() > 128
                    || permission.chars().any(char::is_control)
            })
            || permissions
                != Self::expected_permissions()
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
        {
            return Err(AirbyteSyncResultError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "airbyte-permission-snapshot/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    fn expected_permissions() -> [&'static str; 8] {
        [
            "workspace.read",
            "source.read",
            "destination.read",
            "connection.read",
            "stream.read",
            "job.read",
            "attempt.read",
            "schema.read",
        ]
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.permissions.iter().cloned(), self.revision)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(AirbyteSyncResultError::InvalidPermissionSnapshot)
        }
    }
}

/// Closed provenance vocabulary for Layer-1 evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncAttemptStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Incomplete,
    ProviderUnknown,
}

impl SyncAttemptStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Incomplete
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
    Truncated,
    Unavailable,
}

/// A connection/stream catalog item contains identities and schema metadata,
/// never provider records or arbitrary response JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntry {
    pub workspace: WorkspaceIdentity,
    pub source: SourceIdentity,
    pub destination: DestinationIdentity,
    pub connection: ConnectionIdentity,
    pub stream: StreamIdentity,
    pub schema_digest: SchemaFingerprint,
    pub entry_digest: Digest,
}

impl CatalogEntry {
    pub fn for_scope(scope: &AirbyteScope) -> Self {
        let mut entry = Self {
            workspace: scope.workspace.clone(),
            source: scope.source.clone(),
            destination: scope.destination.clone(),
            connection: scope.connection.clone(),
            stream: scope.stream.clone(),
            schema_digest: scope.stream.schema_digest.clone(),
            entry_digest: Digest::from_text("unsealed-airbyte-catalog-entry"),
        };
        entry.entry_digest = entry.computed_digest();
        entry
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.workspace.validate()?;
        self.source.validate()?;
        self.destination.validate()?;
        self.connection.validate()?;
        self.stream.validate()?;
        self.schema_digest.validate()?;
        if self.entry_digest != self.computed_digest() {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &AirbyteScope) -> bool {
        self.workspace == scope.workspace
            && self.source == scope.source
            && self.destination == scope.destination
            && self.connection == scope.connection
            && self.stream == scope.stream
            && self.schema_digest == scope.stream.schema_digest
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_parts(
            "airbyte-catalog-entry/v1",
            &[
                (
                    "workspace",
                    serde_json::to_string(&self.workspace).expect("identity"),
                ),
                (
                    "source",
                    serde_json::to_string(&self.source).expect("identity"),
                ),
                (
                    "destination",
                    serde_json::to_string(&self.destination).expect("identity"),
                ),
                (
                    "connection",
                    serde_json::to_string(&self.connection).expect("identity"),
                ),
                (
                    "stream",
                    serde_json::to_string(&self.stream).expect("identity"),
                ),
                ("schema", self.schema_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogProjection {
    pub scope_digest: Digest,
    pub entries: Vec<CatalogEntry>,
    pub pages_read: usize,
    pub completeness: ProjectionCompleteness,
    pub provenance: TransportProvenance,
    pub catalog_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl CatalogProjection {
    pub(crate) fn new(
        scope: &AirbyteScope,
        entries: Vec<CatalogEntry>,
        pages_read: usize,
        completeness: ProjectionCompleteness,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if entries.is_empty() || entries.len() > MAX_CATALOG_ENTRIES || pages_read == 0 {
            return Err(AirbyteSyncResultError::OutOfScope);
        }
        let mut digests = BTreeSet::new();
        for entry in &entries {
            entry.validate_integrity()?;
            if !entry.matches_scope(scope) || !digests.insert(entry.entry_digest.clone()) {
                return Err(AirbyteSyncResultError::OutOfScope);
            }
        }
        let mut projection = Self {
            scope_digest: scope.digest(),
            entries,
            pages_read,
            completeness,
            provenance,
            catalog_digest: Digest::from_text("unsealed-airbyte-catalog"),
            connected: false,
            native: false,
        };
        projection.catalog_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        if self.entries.is_empty()
            || self.entries.len() > MAX_CATALOG_ENTRIES
            || self.pages_read == 0
            || self.connected
            || self.native
            || self.catalog_digest != self.calculate_digest()
        {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        for entry in &self.entries {
            entry.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "airbyte-catalog-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "entries",
                    self.entries
                        .iter()
                        .map(|entry| entry.entry_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

/// The only Layer-1 sync-attempt state projection. Counts and fingerprints are
/// bounded; raw records are not represented in this crate.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncAttemptProjection {
    pub scope_digest: Digest,
    pub job: JobIdentity,
    pub attempt: AttemptIdentity,
    pub status: SyncAttemptStatus,
    pub records_read: Option<u64>,
    pub records_written: Option<u64>,
    pub bytes_read: Option<u64>,
    pub bytes_written: Option<u64>,
    pub source_schema_digest: Option<SchemaFingerprint>,
    pub destination_schema_digest: Option<SchemaFingerprint>,
    pub schema_mismatch: bool,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub provider_request_id_digest: Option<Digest>,
    pub observed_at_epoch_seconds: u64,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl SyncAttemptProjection {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        scope: &AirbyteScope,
        status: SyncAttemptStatus,
        records_read: Option<u64>,
        records_written: Option<u64>,
        bytes_read: Option<u64>,
        bytes_written: Option<u64>,
        source_schema_digest: Option<SchemaFingerprint>,
        destination_schema_digest: Option<SchemaFingerprint>,
        completeness: ProjectionCompleteness,
        response_truncated: bool,
        provider_request_id_digest: Option<Digest>,
        observed_at_epoch_seconds: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        for value in [records_read, records_written] {
            if value.is_some_and(|value| value > MAX_RECORD_COUNT) {
                return Err(AirbyteSyncResultError::InvalidText {
                    field: "recordCount",
                });
            }
        }
        for value in [bytes_read, bytes_written] {
            if value.is_some_and(|value| value > MAX_EVIDENCE_BYTES) {
                return Err(AirbyteSyncResultError::ResponseTooLarge);
            }
        }
        if observed_at_epoch_seconds == 0 {
            return Err(AirbyteSyncResultError::InvalidText {
                field: "observedAt",
            });
        }
        if let Some(digest) = &source_schema_digest {
            digest.validate()?;
        }
        if let Some(digest) = &destination_schema_digest {
            digest.validate()?;
        }
        if let Some(digest) = &provider_request_id_digest {
            digest.validate()?;
        }
        let schema_mismatch = source_schema_digest.is_some()
            && destination_schema_digest.is_some()
            && source_schema_digest != destination_schema_digest;
        if schema_mismatch && completeness == ProjectionCompleteness::Complete {
            return Err(AirbyteSyncResultError::SchemaMismatch);
        }
        let mut projection = Self {
            scope_digest: scope.digest(),
            job: scope.job.clone(),
            attempt: scope.attempt.clone(),
            status,
            records_read,
            records_written,
            bytes_read,
            bytes_written,
            source_schema_digest,
            destination_schema_digest,
            schema_mismatch,
            completeness,
            response_truncated,
            provider_request_id_digest,
            observed_at_epoch_seconds,
            provenance,
            replayed: false,
            evidence_digest: Digest::from_text("unsealed-airbyte-attempt"),
            connected: false,
            native: false,
        };
        projection.evidence_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.job.validate()?;
        self.attempt.validate()?;
        for value in [self.records_read, self.records_written] {
            if value.is_some_and(|value| value > MAX_RECORD_COUNT) {
                return Err(AirbyteSyncResultError::TamperedEvidence);
            }
        }
        for value in [self.bytes_read, self.bytes_written] {
            if value.is_some_and(|value| value > MAX_EVIDENCE_BYTES) {
                return Err(AirbyteSyncResultError::TamperedEvidence);
            }
        }
        if self.observed_at_epoch_seconds == 0
            || self.connected
            || self.native
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        if let Some(digest) = &self.source_schema_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.destination_schema_digest {
            digest.validate()?;
        }
        if self.schema_mismatch
            != (self.source_schema_digest.is_some()
                && self.destination_schema_digest.is_some()
                && self.source_schema_digest != self.destination_schema_digest)
        {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete && !self.response_truncated
    }

    pub fn is_schema_match(&self) -> bool {
        !self.schema_mismatch
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "airbyte-sync-attempt-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("job", serde_json::to_string(&self.job).expect("identity")),
                (
                    "attempt",
                    serde_json::to_string(&self.attempt).expect("identity"),
                ),
                ("status", format!("{:?}", self.status)),
                ("records_read", format!("{:?}", self.records_read)),
                ("records_written", format!("{:?}", self.records_written)),
                ("bytes_read", format!("{:?}", self.bytes_read)),
                ("bytes_written", format!("{:?}", self.bytes_written)),
                (
                    "source_schema",
                    self.source_schema_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "destination_schema",
                    self.destination_schema_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("schema_mismatch", self.schema_mismatch.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                ("truncated", self.response_truncated.to_string()),
                (
                    "provider_request",
                    self.provider_request_id_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("observed_at", self.observed_at_epoch_seconds.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn normalize_https_host(value: &str) -> Result<String> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(AirbyteSyncResultError::InvalidWorkspaceHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains('@')
        || remainder.contains(':')
        || remainder.chars().any(char::is_whitespace)
    {
        return Err(AirbyteSyncResultError::InvalidWorkspaceHost);
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
        return Err(AirbyteSyncResultError::InvalidWorkspaceHost);
    }
    Ok(format!("https://{host}"))
}
