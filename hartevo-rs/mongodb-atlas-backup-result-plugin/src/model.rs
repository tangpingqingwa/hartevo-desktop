use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION, MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION,
    MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_SNAPSHOT_PAGE_SIZE: u16 = 100;
pub(crate) const MAX_SNAPSHOT_PAGES: u16 = 8;
pub(crate) const MAX_MEASUREMENT_WINDOW: Duration = Duration::days(7);
pub(crate) const MAX_MEASUREMENT_POINTS: u32 = 10_080;
pub(crate) const MAX_MEASUREMENT_SERIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("Atlas project or organization id must be 24 lowercase hexadecimal characters")]
    InvalidAtlasId,
    #[error("cluster name is empty, malformed, or too long")]
    InvalidClusterName,
    #[error("process id must be a non-empty host and port")]
    InvalidProcessId,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("measurement window is empty or exceeds the Layer-1 bound")]
    InvalidMeasurementWindow,
    #[error("measurement granularity would exceed the Layer-1 point bound")]
    TooManyMeasurementPoints,
    #[error("consent must grant at least one capability")]
    EmptyConsent,
    #[error("consent expiration must be after its start")]
    InvalidConsentExpiry,
    #[error("scope consent does not grant every required capability")]
    ConsentScopeMismatch,
    #[error("secret reference is empty or revoked")]
    InvalidSecretReference,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("snapshot page bound is empty or exceeds the Layer-1 ceiling")]
    InvalidSnapshotBounds,
    #[error("snapshot page size is empty or exceeds the Layer-1 ceiling")]
    InvalidSnapshotPageSize,
    #[error("measurement value must be finite")]
    InvalidMeasurementValue,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_parts(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_atlas_id(value: &str) -> bool {
    value.len() == 24 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_cluster_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

macro_rules! string_id {
    ($name:ident, $validator:ident, $error:expr) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err($error)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

string_id!(OrganizationId, valid_atlas_id, ModelError::InvalidAtlasId);
string_id!(ProjectId, valid_atlas_id, ModelError::InvalidAtlasId);
string_id!(MissionId, valid_identifier, ModelError::InvalidIdentifier);
string_id!(ConsentId, valid_identifier, ModelError::InvalidIdentifier);
string_id!(ProviderId, valid_identifier, ModelError::InvalidIdentifier);
string_id!(ServiceId, valid_identifier, ModelError::InvalidIdentifier);
string_id!(ConsumerId, valid_identifier, ModelError::InvalidIdentifier);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ClusterName(String);

impl ClusterName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_cluster_name(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidClusterName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClusterName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ClusterName").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProcessId(String);

impl ProcessId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some((host, port)) = value.rsplit_once(':') else {
            return Err(ModelError::InvalidProcessId);
        };
        let valid_host = !host.is_empty()
            && host.len() <= MAX_IDENTIFIER_BYTES
            && host.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'-' | b'_' | b'[' | b']' | b':')
            });
        let valid_port = !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit());
        if valid_host && valid_port {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidProcessId)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("mongodb-atlas-process", std::slice::from_ref(&self.0))
    }

    pub fn redacted(&self) -> String {
        format!("process:{}", &self.digest().as_str()[..16])
    }
}

impl fmt::Debug for ProcessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProcessId")
            .field(&self.redacted())
            .finish()
    }
}

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtlasCapability {
    BackupSnapshotRead,
    ProcessMeasurementRead,
    ClusterMetadataRead,
}

impl AtlasCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackupSnapshotRead => "mongodb.atlas.backup-snapshot.read",
            Self::ProcessMeasurementRead => "mongodb.atlas.process-measurement.read",
            Self::ClusterMetadataRead => "mongodb.atlas.cluster-metadata.read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySet(BTreeSet<AtlasCapability>);

impl CapabilitySet {
    pub fn read_only() -> Self {
        Self(BTreeSet::from([
            AtlasCapability::BackupSnapshotRead,
            AtlasCapability::ProcessMeasurementRead,
            AtlasCapability::ClusterMetadataRead,
        ]))
    }

    pub fn new(
        capabilities: impl IntoIterator<Item = AtlasCapability>,
    ) -> Result<Self, ModelError> {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() {
            Err(ModelError::EmptyConsent)
        } else {
            Ok(Self(capabilities))
        }
    }

    pub fn contains(&self, capability: AtlasCapability) -> bool {
        self.0.contains(&capability)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AtlasCapability> {
        self.0.iter()
    }

    pub fn digest(&self) -> Digest {
        let values = self
            .0
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect::<Vec<_>>();
        Digest::from_parts("mongodb-atlas-capabilities", &values)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentScope {
    consent_id: ConsentId,
    revision: Revision,
    capabilities: CapabilitySet,
    expires_at: DateTime<Utc>,
    revoked: bool,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(
        consent_id: ConsentId,
        revision: Revision,
        capabilities: CapabilitySet,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if expires_at <= DateTime::<Utc>::MIN_UTC + Duration::seconds(1) {
            return Err(ModelError::InvalidConsentExpiry);
        }
        let digest = Digest::from_parts(
            "mongodb-atlas-consent",
            &[
                consent_id.as_str().to_owned(),
                revision.get().to_string(),
                capabilities.digest().as_str().to_owned(),
                expires_at.to_rfc3339(),
            ],
        );
        Ok(Self {
            consent_id,
            revision,
            capabilities,
            expires_at,
            revoked: false,
            digest,
        })
    }

    pub fn consent_id(&self) -> &ConsentId {
        &self.consent_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        !self.revoked && now < self.expires_at
    }

    pub fn allows(&self, capability: AtlasCapability) -> bool {
        !self.revoked && self.capabilities.contains(capability)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mission {
    id: MissionId,
    revision: Revision,
}

impl Mission {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Project {
    organization_id: OrganizationId,
    project_id: ProjectId,
    revision: Revision,
}

impl Project {
    pub fn new(organization_id: OrganizationId, project_id: ProjectId, revision: Revision) -> Self {
        Self {
            organization_id,
            project_id,
            revision,
        }
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cluster {
    project_id: ProjectId,
    name: ClusterName,
}

impl Cluster {
    pub fn new(project_id: ProjectId, name: ClusterName) -> Self {
        Self { project_id, name }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn name(&self) -> &ClusterName {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Process {
    project_id: ProjectId,
    cluster_name: ClusterName,
    id: ProcessId,
}

impl Process {
    pub fn new(project_id: ProjectId, cluster_name: ClusterName, id: ProcessId) -> Self {
        Self {
            project_id,
            cluster_name,
            id,
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn cluster_name(&self) -> &ClusterName {
        &self.cluster_name
    }

    pub fn id(&self) -> &ProcessId {
        &self.id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MongoDbAtlasScope {
    organization: OrganizationId,
    project: Project,
    cluster: Cluster,
    process: Process,
    mission: Mission,
    consent: ConsentScope,
    digest: Digest,
}

impl MongoDbAtlasScope {
    pub fn new(
        organization_id: OrganizationId,
        project_id: ProjectId,
        cluster_name: ClusterName,
        process_id: ProcessId,
        mission: Mission,
        project_revision: Revision,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let project = Project::new(
            organization_id.clone(),
            project_id.clone(),
            project_revision,
        );
        let cluster = Cluster::new(project_id.clone(), cluster_name.clone());
        let process = Process::new(project_id.clone(), cluster_name.clone(), process_id.clone());
        let required = [
            AtlasCapability::BackupSnapshotRead,
            AtlasCapability::ProcessMeasurementRead,
            AtlasCapability::ClusterMetadataRead,
        ];
        if required
            .iter()
            .any(|capability| !consent.allows(*capability))
        {
            return Err(ModelError::ConsentScopeMismatch);
        }
        let digest = Digest::from_parts(
            "mongodb-atlas-scope",
            &[
                organization_id.as_str().to_owned(),
                project_id.as_str().to_owned(),
                cluster_name.as_str().to_owned(),
                process_id.digest().as_str().to_owned(),
                mission.id().as_str().to_owned(),
                mission.revision().get().to_string(),
                project_revision.get().to_string(),
                consent.digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            organization: organization_id,
            project,
            cluster,
            process,
            mission,
            consent,
            digest,
        })
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn project_id(&self) -> &ProjectId {
        self.project.project_id()
    }

    pub const fn project_revision(&self) -> Revision {
        self.project.revision()
    }

    pub fn cluster(&self) -> &Cluster {
        &self.cluster
    }

    pub fn cluster_name(&self) -> &ClusterName {
        self.cluster.name()
    }

    pub fn process(&self) -> &Process {
        &self.process
    }

    pub fn process_id(&self) -> &ProcessId {
        self.process.id()
    }

    pub fn mission(&self) -> &Mission {
        &self.mission
    }

    pub fn mission_id(&self) -> &MissionId {
        self.mission.id()
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission.revision()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn capability_digest(&self) -> Digest {
        self.consent.capabilities().digest()
    }
}

impl fmt::Debug for MongoDbAtlasScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MongoDbAtlasScope")
            .field("organization", &self.organization)
            .field("project", &self.project)
            .field("cluster", &self.cluster)
            .field("process", &self.process)
            .field("mission", &self.mission)
            .field("consent_digest", self.consent.digest())
            .field("digest", &self.digest)
            .finish()
    }
}

pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

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

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &MongoDbAtlasScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        if reference_id.as_ref().trim().is_empty() {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: Digest::from_parts(
                "mongodb-atlas-secret-reference",
                &[reference_id.as_ref().to_owned()],
            ),
            scope_digest: scope.digest().clone(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialOrd, Ord, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementGranularity {
    Pt1m,
    Pt5m,
    Pt1h,
    P1d,
}

impl MeasurementGranularity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pt1m => "PT1M",
            Self::Pt5m => "PT5M",
            Self::Pt1h => "PT1H",
            Self::P1d => "P1D",
        }
    }

    pub const fn seconds(self) -> i64 {
        match self {
            Self::Pt1m => 60,
            Self::Pt5m => 300,
            Self::Pt1h => 3_600,
            Self::P1d => 86_400,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeasurementWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    granularity: MeasurementGranularity,
}

impl MeasurementWindow {
    pub fn new(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        granularity: MeasurementGranularity,
    ) -> Result<Self, ModelError> {
        let duration = end - start;
        if duration <= Duration::zero() || duration > MAX_MEASUREMENT_WINDOW {
            return Err(ModelError::InvalidMeasurementWindow);
        }
        let point_count =
            (duration.num_seconds() + granularity.seconds() - 1) / granularity.seconds();
        if point_count <= 0 || point_count > i64::from(MAX_MEASUREMENT_POINTS) {
            return Err(ModelError::TooManyMeasurementPoints);
        }
        Ok(Self {
            start,
            end,
            granularity,
        })
    }

    pub const fn start(&self) -> DateTime<Utc> {
        self.start
    }

    pub const fn end(&self) -> DateTime<Utc> {
        self.end
    }

    pub const fn granularity(&self) -> MeasurementGranularity {
        self.granularity
    }

    pub fn max_points(&self) -> u32 {
        let seconds = (self.end - self.start).num_seconds();
        ((seconds + self.granularity.seconds() - 1) / self.granularity.seconds()) as u32
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "mongodb-atlas-measurement-window",
            &[
                self.start.to_rfc3339(),
                self.end.to_rfc3339(),
                self.granularity.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Queued,
    InProgress,
    Completed,
    Expired,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Snapshot {
    pub id: String,
    pub status: SnapshotStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub snapshot_type: String,
    pub storage_size_bytes: Option<u64>,
}

impl Snapshot {
    pub fn new(
        id: impl Into<String>,
        status: SnapshotStatus,
        created_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        snapshot_type: impl Into<String>,
        storage_size_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        let id = id.into();
        let snapshot_type = snapshot_type.into();
        if !valid_identifier(&id) || snapshot_type.trim().is_empty() {
            return Err(ModelError::InvalidIdentifier);
        }
        Ok(Self {
            id,
            status,
            created_at,
            expires_at,
            snapshot_type,
            storage_size_bytes,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "mongodb-atlas-snapshot",
            &[
                self.id.clone(),
                format!("{:?}", self.status),
                self.created_at.to_rfc3339(),
                self.expires_at
                    .map_or_else(|| "none".to_owned(), |value| value.to_rfc3339()),
                self.snapshot_type.clone(),
                self.storage_size_bytes
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MeasurementPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

impl MeasurementPoint {
    pub fn new(timestamp: DateTime<Utc>, value: f64) -> Result<Self, ModelError> {
        if value.is_finite() {
            Ok(Self { timestamp, value })
        } else {
            Err(ModelError::InvalidMeasurementValue)
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MeasurementSeries {
    pub name: String,
    pub units: String,
    pub points: Vec<MeasurementPoint>,
}

impl MeasurementSeries {
    pub fn new(
        name: impl Into<String>,
        units: impl Into<String>,
        points: Vec<MeasurementPoint>,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        let units = units.into();
        if name.trim().is_empty() || units.trim().is_empty() || points.is_empty() {
            return Err(ModelError::InvalidIdentifier);
        }
        if points.len() > MAX_MEASUREMENT_POINTS as usize {
            return Err(ModelError::TooManyMeasurementPoints);
        }
        Ok(Self {
            name,
            units,
            points,
        })
    }

    pub fn digest(&self) -> Digest {
        let mut fields = vec![self.name.clone(), self.units.clone()];
        fields.extend(
            self.points
                .iter()
                .flat_map(|point| [point.timestamp.to_rfc3339(), point.value.to_string()]),
        );
        Digest::from_parts("mongodb-atlas-measurement-series", &fields)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterHealth {
    Observed,
    Paused,
    BackupDisabled,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMetadata {
    pub project_id: ProjectId,
    pub cluster_name: ClusterName,
    pub backup_enabled: bool,
    pub point_in_time_enabled: bool,
    pub paused: bool,
    pub mongo_db_version: Option<String>,
    pub cluster_type: Option<String>,
    pub health: ClusterHealth,
}

impl ClusterMetadata {
    pub fn new(
        project_id: ProjectId,
        cluster_name: ClusterName,
        backup_enabled: bool,
        point_in_time_enabled: bool,
        paused: bool,
        mongo_db_version: Option<String>,
        cluster_type: Option<String>,
    ) -> Self {
        let health = if paused {
            ClusterHealth::Paused
        } else if !backup_enabled {
            ClusterHealth::BackupDisabled
        } else {
            ClusterHealth::Observed
        };
        Self {
            project_id,
            cluster_name,
            backup_enabled,
            point_in_time_enabled,
            paused,
            mongo_db_version,
            cluster_type,
            health,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "mongodb-atlas-cluster-metadata",
            &[
                self.project_id.as_str().to_owned(),
                self.cluster_name.as_str().to_owned(),
                self.backup_enabled.to_string(),
                self.point_in_time_enabled.to_string(),
                self.paused.to_string(),
                self.mongo_db_version.clone().unwrap_or_default(),
                self.cluster_type.clone().unwrap_or_default(),
                format!("{:?}", self.health),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MongoDbAtlasRegistration {
    pub registration_digest: Digest,
    pub service_id: ServiceId,
    pub service_version: String,
    pub contract_version: String,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub capability_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub registration_revision: Revision,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub state: RegistrationState,
}

impl MongoDbAtlasRegistration {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        service_version: impl Into<String>,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        provider_digest: Digest,
        capability_digest: Digest,
        scope: &MongoDbAtlasScope,
        registration_revision: Revision,
    ) -> Result<Self, ModelError> {
        let service_id = ServiceId::new(MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID)?;
        let service_version = service_version.into();
        let provider_version = provider_version.into();
        if service_version.trim().is_empty() || provider_version.trim().is_empty() {
            return Err(ModelError::InvalidRegistration);
        }
        let fields = vec![
            MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION.to_owned(),
            MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION.to_owned(),
            service_id.as_str().to_owned(),
            service_version.clone(),
            provider_id.as_str().to_owned(),
            provider_version.clone(),
            provider_digest.as_str().to_owned(),
            capability_digest.as_str().to_owned(),
            scope.organization_id().as_str().to_owned(),
            scope.project_id().as_str().to_owned(),
            scope.cluster_name().as_str().to_owned(),
            scope.process_id().digest().as_str().to_owned(),
            scope.digest().as_str().to_owned(),
            scope.consent().digest().as_str().to_owned(),
            scope.mission_revision().get().to_string(),
            scope.project_revision().get().to_string(),
            registration_revision.get().to_string(),
        ];
        Ok(Self {
            registration_digest: Digest::from_parts("mongodb-atlas-registration", &fields),
            service_id,
            service_version,
            contract_version: MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION.to_owned(),
            provider_id,
            provider_version,
            provider_digest,
            capability_digest,
            scope_digest: scope.digest().clone(),
            consent_digest: scope.consent().digest().clone(),
            registration_revision,
            mission_revision: scope.mission_revision(),
            project_revision: scope.project_revision(),
            state: RegistrationState::Active,
        })
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Queued,
    InProgress,
    Completed,
    Expired,
    Failed,
    Partial,
    RetentionGap,
    AccessLoss,
    ProviderUnknown,
}

impl ReadinessState {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::InProgress)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreVerification {
    NotPerformedLayer1,
    Layer2Required,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer1,
    Layer2Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessEvidenceState {
    Observed,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderMode {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

impl fmt::Display for ProviderMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityKind {
    ReadOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceDigests {
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub capability_digest: Digest,
    pub consent_digest: Digest,
    pub snapshot_digest: Digest,
    pub measurement_digest: Digest,
    pub cluster_metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFence {
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_digest: Digest,
}

pub(crate) fn all_read_capabilities() -> CapabilitySet {
    CapabilitySet::read_only()
}
