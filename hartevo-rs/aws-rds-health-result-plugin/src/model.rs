//! Typed, bounded and redacted RDS models.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_DB_IDENTIFIER_BYTES: usize = 63;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_EVENTS: usize = 64;
pub const MAX_MAINTENANCE_ACTIONS: usize = 16;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_TEXT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} contains too many values")]
    TooMany { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("RDS scope is invalid")]
    InvalidScope,
    #[error("scope mismatch: {field}")]
    ScopeMismatch { field: &'static str },
    #[error("revision mismatch: {field}")]
    RevisionMismatch { field: &'static str },
    #[error("opaque cursor is invalid: {field}")]
    InvalidCursor { field: &'static str },
    #[error("response exceeded the bounded byte budget")]
    ResponseTooLarge,
    #[error("bounded evidence is partial")]
    PartialEvidence,
}

pub type ModelResult<T> = std::result::Result<T, ModelError>;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(tag.len() + parts.len() * 40);
        canonical.push_str(tag);
        canonical.push('\n');
        for (key, value) in parts {
            canonical.push_str(key);
            canonical.push('=');
            canonical.push_str(value);
            canonical.push('\n');
        }
        Self::from_text(canonical)
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self(value))
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> ModelResult<Self> {
        (value > 0)
            .then_some(Self(value))
            .ok_or(ModelError::Invalid { field: "revision" })
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! bounded_text_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ModelResult<Self> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!(stringify!($name), "/v1"),
                    &[("value", self.0.clone())],
                )
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
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
    };
}

bounded_text_id!(ProjectId, "project id");
bounded_text_id!(MissionId, "mission id");
bounded_text_id!(WorkProductId, "work product id");
bounded_text_id!(DeploymentId, "deployment id");
bounded_text_id!(PermissionId, "permission id");
bounded_text_id!(AccountId, "AWS account id");
bounded_text_id!(AwsRegion, "AWS region");
bounded_text_id!(DbIdentifier, "RDS database identifier");
bounded_text_id!(RdsArn, "RDS ARN");
bounded_text_id!(EngineFamily, "RDS engine family");
bounded_text_id!(EngineVersionFamily, "RDS engine version family");

impl AccountId {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::InvalidIdentifier {
                field: "AWS account id",
            });
        }
        Self::new(value)
    }
}

impl AwsRegion {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !value.contains('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ModelError::InvalidIdentifier {
                field: "AWS region",
            });
        }
        Self::new(value)
    }
}

impl DbIdentifier {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() > MAX_DB_IDENTIFIER_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ModelError::InvalidIdentifier {
                field: "RDS database identifier",
            });
        }
        Self::new(value)
    }
}

impl RdsArn {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !value.starts_with("arn:") || !value.contains(":rds:") {
            return Err(ModelError::InvalidIdentifier { field: "RDS ARN" });
        }
        Self::new(value)
    }
}

impl EngineFamily {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ModelError::InvalidIdentifier {
                field: "RDS engine family",
            });
        }
        Self::new(value)
    }
}

impl EngineVersionFamily {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ModelError::InvalidIdentifier {
                field: "RDS engine version family",
            });
        }
        Self::new(value)
    }
}

fn validate_text(value: &str, field: &'static str, max_bytes: usize) -> ModelResult<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-deployment-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-mission-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-project-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-work-product-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    #[serde(rename = "rds:DescribeDBInstances")]
    DescribeDbInstances,
    #[serde(rename = "rds:DescribeDBClusters")]
    DescribeDbClusters,
    #[serde(rename = "rds:DescribeEvents")]
    DescribeEvents,
    #[serde(rename = "rds:DescribePendingMaintenanceActions")]
    DescribePendingMaintenanceActions,
    #[serde(rename = "mission.scope")]
    MissionScope,
}

impl PermissionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeDbInstances => "rds:DescribeDBInstances",
            Self::DescribeDbClusters => "rds:DescribeDBClusters",
            Self::DescribeEvents => "rds:DescribeEvents",
            Self::DescribePendingMaintenanceActions => "rds:DescribePendingMaintenanceActions",
            Self::MissionScope => "mission.scope",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> ModelResult<Self> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::DescribeDbInstances,
                PermissionAction::DescribeDbClusters,
                PermissionAction::DescribeEvents,
                PermissionAction::DescribePendingMaintenanceActions,
                PermissionAction::MissionScope,
            ],
        )
    }

    pub fn read_only(id: PermissionId, revision: Revision) -> ModelResult<Self> {
        Self::readonly(id, revision)
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> ModelResult<Self> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(Self {
            id,
            revision,
            allowed_actions,
        })
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        let actions = self
            .allowed_actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts(
            "aws-rds-permission-fence/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
                ("actions", actions),
            ],
        )
    }

    pub fn is_layer_one_complete(&self) -> bool {
        [
            PermissionAction::DescribeDbInstances,
            PermissionAction::DescribeDbClusters,
            PermissionAction::DescribeEvents,
            PermissionAction::DescribePendingMaintenanceActions,
            PermissionAction::MissionScope,
        ]
        .into_iter()
        .all(|action| self.allows(action))
    }
}

pub type PermissionSnapshot = PermissionFence;

/// A SigV4 handle is reduced to a digest immediately. No raw reference or
/// credential material is retained, serialized, or included in debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
}

impl SecretReference {
    pub fn for_rds(reference: impl AsRef<str>, region: AwsRegion) -> ModelResult<Self> {
        let reference = reference.as_ref();
        validate_text(reference, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            digest: Digest::from_parts(
                "aws-rds-sigv4-secret-reference/v1",
                &[
                    ("service", "rds".to_owned()),
                    ("region", region.as_str().to_owned()),
                    ("reference", reference.to_owned()),
                ],
            ),
            region,
        })
    }

    pub fn sigv4(reference: impl AsRef<str>, region: AwsRegion) -> ModelResult<Self> {
        Self::for_rds(reference, region)
    }

    pub fn aws_sigv4(reference: impl AsRef<str>, region: AwsRegion) -> ModelResult<Self> {
        Self::for_rds(reference, region)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn signing_service(&self) -> &'static str {
        "rds"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &"rds")
            .field("signing_region", &self.region)
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsEngineScope {
    pub family: EngineFamily,
    pub version_family: EngineVersionFamily,
}

impl RdsEngineScope {
    pub fn new(family: EngineFamily, version_family: EngineVersionFamily) -> ModelResult<Self> {
        let value = Self {
            family,
            version_family,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.family.as_str().is_empty() || self.version_family.as_str().is_empty() {
            return Err(ModelError::Invalid {
                field: "RDS engine scope",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-engine-scope/v1",
            &[
                ("family", self.family.digest().to_string()),
                ("version_family", self.version_family.digest().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsTimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl RdsTimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> ModelResult<Self> {
        let value = Self { start, end };
        value.validate()?;
        Ok(value)
    }

    pub fn recent(end: DateTime<Utc>, duration: Duration) -> ModelResult<Self> {
        Self::new(end - duration, end)
    }

    pub fn validate(&self) -> ModelResult<()> {
        let seconds = self.end.signed_duration_since(self.start).num_seconds();
        if self.start > self.end || seconds <= 0 || seconds > MAX_WINDOW_SECONDS {
            return Err(ModelError::Invalid {
                field: "RDS recent time window",
            });
        }
        Ok(())
    }

    pub fn contains(&self, value: DateTime<Utc>) -> bool {
        value >= self.start && value <= self.end
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-time-window/v1",
            &[
                ("start", self.start.to_rfc3339()),
                ("end", self.end.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum AwsRdsTarget {
    Instance {
        identifier: DbIdentifier,
        arn: RdsArn,
    },
    Cluster {
        identifier: DbIdentifier,
        arn: RdsArn,
    },
}

impl AwsRdsTarget {
    pub fn instance(identifier: DbIdentifier, arn: RdsArn) -> ModelResult<Self> {
        let target = Self::Instance { identifier, arn };
        target.validate()?;
        Ok(target)
    }

    pub fn cluster(identifier: DbIdentifier, arn: RdsArn) -> ModelResult<Self> {
        let target = Self::Cluster { identifier, arn };
        target.validate()?;
        Ok(target)
    }

    pub fn kind(&self) -> RdsTargetKind {
        match self {
            Self::Instance { .. } => RdsTargetKind::Instance,
            Self::Cluster { .. } => RdsTargetKind::Cluster,
        }
    }

    pub fn identifier(&self) -> &DbIdentifier {
        match self {
            Self::Instance { identifier, .. } | Self::Cluster { identifier, .. } => identifier,
        }
    }

    pub fn arn(&self) -> &RdsArn {
        match self {
            Self::Instance { arn, .. } | Self::Cluster { arn, .. } => arn,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-target/v1",
            &[
                ("kind", self.kind().as_str().to_owned()),
                ("identifier", self.identifier().digest().to_string()),
                ("arn", self.arn().digest().to_string()),
            ],
        )
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.identifier().as_str().is_empty() || self.arn().as_str().is_empty() {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for AwsRdsTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRdsTarget")
            .field("kind", &self.kind())
            .field("identifier_digest", &self.identifier().digest())
            .field("arn_digest", &self.arn().digest())
            .finish()
    }
}

impl Serialize for AwsRdsTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AwsRdsTarget", 3)?;
        value.serialize_field("kind", &self.kind())?;
        value.serialize_field("identifierDigest", &self.identifier().digest())?;
        value.serialize_field("arnDigest", &self.arn().digest())?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdsTargetKind {
    Instance,
    Cluster,
}

impl RdsTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Cluster => "cluster",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRdsHealthScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub target: AwsRdsTarget,
    pub engine: RdsEngineScope,
    pub db_revision: Revision,
    pub time_window: RdsTimeWindow,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsRdsHealthScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AccountId,
        region: AwsRegion,
        target: AwsRdsTarget,
        engine: RdsEngineScope,
        db_revision: Revision,
        time_window: RdsTimeWindow,
        permission_digest: Digest,
    ) -> ModelResult<Self> {
        let mut scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            target,
            engine,
            db_revision,
            time_window,
            permission_digest,
            scope_digest: Digest::zero(),
        };
        scope.validate_fields()?;
        scope.scope_digest = scope.recomputed_digest();
        Ok(scope)
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.validate_fields()?;
        if self.scope_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        Ok(())
    }

    fn validate_fields(&self) -> ModelResult<()> {
        self.target.validate()?;
        self.engine.validate()?;
        self.time_window.validate()?;
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-health-scope/v1",
            &[
                ("deployment", self.deployment.digest().to_string()),
                ("mission", self.mission.digest().to_string()),
                ("project", self.project.digest().to_string()),
                ("work_product", self.work_product.digest().to_string()),
                ("account", self.account_id.digest().to_string()),
                ("region", self.region.digest().to_string()),
                ("target", self.target.digest().to_string()),
                ("engine", self.engine.digest().to_string()),
                ("db_revision", self.db_revision.get().to_string()),
                ("time_window", self.time_window.digest().to_string()),
                ("permission", self.permission_digest.to_string()),
            ],
        )
    }

    pub fn deployment(&self) -> &DeploymentBinding {
        &self.deployment
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn target(&self) -> &AwsRdsTarget {
        &self.target
    }

    pub fn engine(&self) -> &RdsEngineScope {
        &self.engine
    }

    pub const fn db_revision(&self) -> Revision {
        self.db_revision
    }

    pub fn time_window(&self) -> &RdsTimeWindow {
        &self.time_window
    }
}

impl Serialize for AwsRdsHealthScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AwsRdsHealthScope", 12)?;
        value.serialize_field("deployment", &self.deployment.digest())?;
        value.serialize_field("mission", &self.mission.digest())?;
        value.serialize_field("project", &self.project.digest())?;
        value.serialize_field("workProduct", &self.work_product.digest())?;
        value.serialize_field("accountDigest", &self.account_id.digest())?;
        value.serialize_field("regionDigest", &self.region.digest())?;
        value.serialize_field("target", &self.target)?;
        value.serialize_field("engine", &self.engine)?;
        value.serialize_field("dbRevision", &self.db_revision)?;
        value.serialize_field("timeWindow", &self.time_window)?;
        value.serialize_field("permissionDigest", &self.permission_digest)?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    page_number: u16,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> ModelResult<Self> {
        let value = value.as_ref();
        validate_text(value, "RDS next token", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-rds-next-token/v1",
                &[("token", value.to_owned())],
            ),
            binding_digest: None,
            page_number: 1,
        })
    }

    pub fn bind(&self, binding_digest: &Digest, page_number: u16) -> ModelResult<Self> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(ModelError::InvalidCursor {
                field: "page number",
            });
        }
        Ok(Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 3)?;
        value.serialize_field("tokenDigest", &self.token_digest)?;
        value.serialize_field("bindingDigest", &self.binding_digest)?;
        value.serialize_field("pageNumber", &self.page_number)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsRdsReadOperation {
    #[serde(rename = "DescribeDBInstances")]
    DescribeDbInstances,
    #[serde(rename = "DescribeDBClusters")]
    DescribeDbClusters,
    #[serde(rename = "DescribeEvents")]
    DescribeEvents,
    #[serde(rename = "DescribePendingMaintenanceActions")]
    DescribePendingMaintenanceActions,
}

impl AwsRdsReadOperation {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::DescribeDbInstances => "DescribeDBInstances",
            Self::DescribeDbClusters => "DescribeDBClusters",
            Self::DescribeEvents => "DescribeEvents",
            Self::DescribePendingMaintenanceActions => "DescribePendingMaintenanceActions",
        }
    }

    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::DescribeDbInstances => PermissionAction::DescribeDbInstances,
            Self::DescribeDbClusters => PermissionAction::DescribeDbClusters,
            Self::DescribeEvents => PermissionAction::DescribeEvents,
            Self::DescribePendingMaintenanceActions => {
                PermissionAction::DescribePendingMaintenanceActions
            }
        }
    }

    pub const fn is_database(self) -> bool {
        matches!(self, Self::DescribeDbInstances | Self::DescribeDbClusters)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsReadRequest {
    pub operation: AwsRdsReadOperation,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub target: AwsRdsTarget,
    pub engine: RdsEngineScope,
    pub time_window: RdsTimeWindow,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_events: u16,
    pub max_maintenance_actions: u16,
    pub max_response_bytes: u64,
    pub db_revision: Revision,
    pub cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl AwsRdsReadRequest {
    pub fn for_scope(
        scope: &AwsRdsHealthScope,
        operation: AwsRdsReadOperation,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> ModelResult<Self> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        if operation == AwsRdsReadOperation::DescribeDbInstances
            && scope.target.kind() != RdsTargetKind::Instance
        {
            return Err(ModelError::ScopeMismatch {
                field: "instance operation target kind",
            });
        }
        if operation == AwsRdsReadOperation::DescribeDbClusters
            && scope.target.kind() != RdsTargetKind::Cluster
        {
            return Err(ModelError::ScopeMismatch {
                field: "cluster operation target kind",
            });
        }
        let mut request = Self {
            operation,
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            target: scope.target.clone(),
            engine: scope.engine.clone(),
            time_window: scope.time_window.clone(),
            page_size,
            max_pages,
            max_events: u16::try_from(MAX_EVENTS).expect("RDS event bound fits u16"),
            max_maintenance_actions: u16::try_from(MAX_MAINTENANCE_ACTIONS)
                .expect("RDS maintenance bound fits u16"),
            max_response_bytes: MAX_RESPONSE_BYTES,
            db_revision: scope.db_revision,
            cursor: None,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
        };
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> ModelResult<Self> {
        let mut request = self.clone();
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    pub fn with_bounds(
        &self,
        max_events: u16,
        max_maintenance_actions: u16,
        max_response_bytes: u64,
    ) -> ModelResult<Self> {
        if self.cursor.is_some()
            || max_events == 0
            || usize::from(max_events) > MAX_EVENTS
            || max_maintenance_actions == 0
            || usize::from(max_maintenance_actions) > MAX_MAINTENANCE_ACTIONS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        let mut request = self.clone();
        request.max_events = max_events;
        request.max_maintenance_actions = max_maintenance_actions;
        request.max_response_bytes = max_response_bytes;
        Ok(request)
    }

    fn bind_cursor(&self, cursor: Option<OpaqueCursor>) -> ModelResult<Option<OpaqueCursor>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let page_number = cursor.page_number();
        if page_number == 0 || page_number > self.max_pages {
            return Err(ModelError::InvalidCursor {
                field: "page budget",
            });
        }
        let query_digest = self.query_digest();
        if let Some(binding) = cursor.binding_digest()
            && binding != &query_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        cursor.bind(&query_digest, page_number).map(Some)
    }

    pub fn query_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-read-query/v1",
            &[
                ("operation", self.operation.api_name().to_owned()),
                ("account", self.account_id.digest().to_string()),
                ("region", self.region.digest().to_string()),
                ("target", self.target.digest().to_string()),
                ("engine", self.engine.digest().to_string()),
                ("time_window", self.time_window.digest().to_string()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("max_events", self.max_events.to_string()),
                (
                    "max_maintenance_actions",
                    self.max_maintenance_actions.to_string(),
                ),
                ("max_response_bytes", self.max_response_bytes.to_string()),
                ("db_revision", self.db_revision.get().to_string()),
                ("scope", self.scope_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
            ],
        )
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-read-request/v1",
            &[
                ("query", self.query_digest().to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                (
                    "page",
                    self.cursor
                        .as_ref()
                        .map_or(1, OpaqueCursor::page_number)
                        .to_string(),
                ),
            ],
        )
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaqueCursor::page_number)
    }

    pub fn validate_against(
        &self,
        scope: &AwsRdsHealthScope,
        permission: &PermissionFence,
    ) -> ModelResult<()> {
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.account_id != scope.account_id
            || self.region != scope.region
            || self.target != scope.target
            || self.engine != scope.engine
            || self.time_window != scope.time_window
            || self.db_revision != scope.db_revision
        {
            return Err(ModelError::ScopeMismatch {
                field: "RDS read scope",
            });
        }
        if self.permission_digest != permission.digest()
            || self.permission_digest != scope.permission_digest
            || !permission.allows(self.operation.permission())
        {
            return Err(ModelError::ScopeMismatch {
                field: "RDS read permission",
            });
        }
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_events == 0
            || usize::from(self.max_events) > MAX_EVENTS
            || self.max_maintenance_actions == 0
            || usize::from(self.max_maintenance_actions) > MAX_MAINTENANCE_ACTIONS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        if let Some(cursor) = &self.cursor
            && (cursor.binding_digest() != Some(&self.query_digest())
                || cursor.page_number() > self.max_pages)
        {
            return Err(ModelError::ScopeMismatch {
                field: "RDS cursor binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RdsDbStatus {
    Available,
    BackingUp,
    Creating,
    Deleting,
    Failed,
    FailingOver,
    Maintenance,
    Rebooting,
    Starting,
    Stopped,
    Stopping,
    StorageFull,
    StorageOptimization,
    Upgrading,
    Unknown,
}

impl RdsDbStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "available" => Self::Available,
            "backing-up" => Self::BackingUp,
            "creating" => Self::Creating,
            "deleting" => Self::Deleting,
            "failed" => Self::Failed,
            "failing-over" => Self::FailingOver,
            "maintenance" => Self::Maintenance,
            "rebooting" => Self::Rebooting,
            "starting" => Self::Starting,
            "stopped" => Self::Stopped,
            "stopping" => Self::Stopping,
            "storage-full" => Self::StorageFull,
            "storage-optimization" => Self::StorageOptimization,
            "upgrading" => Self::Upgrading,
            _ => Self::Unknown,
        }
    }

    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    pub const fn is_terminal_failure(self) -> bool {
        matches!(self, Self::Failed | Self::StorageFull)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPresence {
    Present,
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdsEventCategory {
    Availability,
    ConfigurationChange,
    Creation,
    Deletion,
    Failover,
    Failure,
    Maintenance,
    Notification,
    Recovery,
    Security,
    Unknown,
}

impl RdsEventCategory {
    pub fn parse_api(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "availability" => Self::Availability,
            "configuration change" | "configuration_change" => Self::ConfigurationChange,
            "creation" => Self::Creation,
            "deletion" => Self::Deletion,
            "failover" => Self::Failover,
            "failure" => Self::Failure,
            "maintenance" => Self::Maintenance,
            "notification" => Self::Notification,
            "recovery" => Self::Recovery,
            "security" => Self::Security,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdsEventSeverity {
    Informational,
    Warning,
    Critical,
    Unknown,
}

impl RdsEventSeverity {
    pub fn parse_api(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "informational" | "info" => Self::Informational,
            "warning" | "warn" => Self::Warning,
            "critical" | "error" => Self::Critical,
            _ => Self::Unknown,
        }
    }

    pub const fn is_critical(self) -> bool {
        matches!(self, Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdsMaintenanceCategory {
    SystemUpdate,
    DatabaseEngine,
    Security,
    Hardware,
    Other,
    Unknown,
}

impl RdsMaintenanceCategory {
    pub fn parse_api(value: &str) -> Self {
        let value = value.to_ascii_lowercase();
        if value.contains("system") {
            Self::SystemUpdate
        } else if value.contains("engine") || value.contains("db") {
            Self::DatabaseEngine
        } else if value.contains("security") {
            Self::Security
        } else if value.contains("hardware") {
            Self::Hardware
        } else if value.is_empty() {
            Self::Unknown
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdsMaintenanceStatus {
    Pending,
    Available,
    Scheduled,
    InProgress,
    Complete,
    Failed,
    Unknown,
}

impl RdsMaintenanceStatus {
    pub fn parse_api(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" => Self::Pending,
            "available" => Self::Available,
            "scheduled" => Self::Scheduled,
            "in-progress" | "in_progress" => Self::InProgress,
            "complete" | "completed" => Self::Complete,
            "failed" => Self::Failed,
            _ => Self::Unknown,
        }
    }

    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending | Self::Available | Self::Scheduled)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsDatabaseObservation {
    pub target_digest: Digest,
    pub target_kind: RdsTargetKind,
    pub status: RdsDbStatus,
    pub engine: EngineFamily,
    pub version_family: EngineVersionFamily,
    pub endpoint_presence: EndpointPresence,
    pub resource_revision: Revision,
    pub observation_digest: Digest,
}

impl RdsDatabaseObservation {
    pub fn for_scope(
        scope: &AwsRdsHealthScope,
        status: RdsDbStatus,
        endpoint_presence: EndpointPresence,
        resource_revision: Revision,
    ) -> Self {
        let mut value = Self {
            target_digest: scope.target.digest(),
            target_kind: scope.target.kind(),
            status,
            engine: scope.engine.family.clone(),
            version_family: scope.engine.version_family.clone(),
            endpoint_presence,
            resource_revision,
            observation_digest: Digest::zero(),
        };
        value.observation_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-database-observation/v1",
            &[
                ("target", self.target_digest.to_string()),
                ("kind", self.target_kind.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("engine", self.engine.digest().to_string()),
                ("version", self.version_family.digest().to_string()),
                ("endpoint", format!("{:?}", self.endpoint_presence)),
                ("revision", self.resource_revision.get().to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsRdsHealthScope) -> ModelResult<()> {
        if self.target_digest != scope.target.digest()
            || self.target_kind != scope.target.kind()
            || self.engine != scope.engine.family
            || self.version_family != scope.engine.version_family
        {
            return Err(ModelError::ScopeMismatch {
                field: "RDS database target or engine",
            });
        }
        if self.resource_revision != scope.db_revision {
            return Err(ModelError::RevisionMismatch {
                field: "RDS database revision",
            });
        }
        if self.observation_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "RDS database observation digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsEventSummary {
    pub event_digest: Digest,
    pub source_digest: Digest,
    pub category: RdsEventCategory,
    pub severity: RdsEventSeverity,
    pub occurred_at: DateTime<Utc>,
    pub message_digest: Digest,
}

impl RdsEventSummary {
    pub fn new(
        event_id: impl AsRef<str>,
        source: impl AsRef<str>,
        category: RdsEventCategory,
        severity: RdsEventSeverity,
        occurred_at: DateTime<Utc>,
        message: impl AsRef<str>,
    ) -> ModelResult<Self> {
        validate_text(event_id.as_ref(), "RDS event id", MAX_IDENTIFIER_BYTES)?;
        validate_text(source.as_ref(), "RDS event source", MAX_IDENTIFIER_BYTES)?;
        validate_text(message.as_ref(), "RDS event message", MAX_TEXT_BYTES)?;
        let event_digest = Digest::from_parts(
            "aws-rds-event/v1",
            &[
                ("id", Digest::from_text(event_id.as_ref()).to_string()),
                ("source", Digest::from_text(source.as_ref()).to_string()),
                ("time", occurred_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            event_digest,
            source_digest: Digest::from_text(source.as_ref()),
            category,
            severity,
            occurred_at,
            message_digest: Digest::from_text(message.as_ref()),
        })
    }

    pub fn validate_against(&self, window: &RdsTimeWindow) -> ModelResult<()> {
        if !window.contains(self.occurred_at) {
            return Err(ModelError::ScopeMismatch {
                field: "RDS event time window",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsMaintenanceSummary {
    pub action_digest: Digest,
    pub category: RdsMaintenanceCategory,
    pub status: RdsMaintenanceStatus,
    pub apply_at: Option<DateTime<Utc>>,
    pub detail_digest: Digest,
}

impl RdsMaintenanceSummary {
    pub fn new(
        action: impl AsRef<str>,
        category: RdsMaintenanceCategory,
        status: RdsMaintenanceStatus,
        apply_at: Option<DateTime<Utc>>,
        detail: impl AsRef<str>,
    ) -> ModelResult<Self> {
        validate_text(
            action.as_ref(),
            "RDS maintenance action",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(detail.as_ref(), "RDS maintenance detail", MAX_TEXT_BYTES)?;
        Ok(Self {
            action_digest: Digest::from_text(action.as_ref()),
            category,
            status,
            apply_at,
            detail_digest: Digest::from_text(detail.as_ref()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AwsRdsReadPageBody {
    Database(RdsDatabaseObservation),
    Events(Vec<RdsEventSummary>),
    Maintenance(Vec<RdsMaintenanceSummary>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsReadPage {
    pub request_digest: Digest,
    pub operation: AwsRdsReadOperation,
    pub target_digest: Digest,
    pub page_number: u16,
    pub complete: bool,
    pub next_cursor: Option<OpaqueCursor>,
    pub body: AwsRdsReadPageBody,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub page_digest: Digest,
    pub provenance: TransportProvenance,
}

impl AwsRdsReadPage {
    pub fn database(
        request: &AwsRdsReadRequest,
        observation: RdsDatabaseObservation,
        next_token: Option<impl AsRef<str>>,
        response_bytes: u64,
    ) -> ModelResult<Self> {
        Self::new(
            request,
            AwsRdsReadPageBody::Database(observation),
            next_token,
            response_bytes,
        )
    }

    pub fn events(
        request: &AwsRdsReadRequest,
        events: Vec<RdsEventSummary>,
        next_token: Option<impl AsRef<str>>,
        response_bytes: u64,
    ) -> ModelResult<Self> {
        Self::new(
            request,
            AwsRdsReadPageBody::Events(events),
            next_token,
            response_bytes,
        )
    }

    pub fn maintenance(
        request: &AwsRdsReadRequest,
        maintenance: Vec<RdsMaintenanceSummary>,
        next_token: Option<impl AsRef<str>>,
        response_bytes: u64,
    ) -> ModelResult<Self> {
        Self::new(
            request,
            AwsRdsReadPageBody::Maintenance(maintenance),
            next_token,
            response_bytes,
        )
    }

    fn new(
        request: &AwsRdsReadRequest,
        body: AwsRdsReadPageBody,
        next_token: Option<impl AsRef<str>>,
        response_bytes: u64,
    ) -> ModelResult<Self> {
        if response_bytes == 0 || response_bytes > request.max_response_bytes {
            return Err(if response_bytes > request.max_response_bytes {
                ModelError::ResponseTooLarge
            } else {
                ModelError::Invalid {
                    field: "response bytes",
                }
            });
        }
        let body_kind_matches = match (&request.operation, &body) {
            (operation, AwsRdsReadPageBody::Database(_)) => operation.is_database(),
            (AwsRdsReadOperation::DescribeEvents, AwsRdsReadPageBody::Events(_))
            | (
                AwsRdsReadOperation::DescribePendingMaintenanceActions,
                AwsRdsReadPageBody::Maintenance(_),
            ) => true,
            _ => false,
        };
        if !body_kind_matches {
            return Err(ModelError::ScopeMismatch {
                field: "RDS page operation body",
            });
        }
        let next_cursor = next_token
            .map(|token| {
                OpaqueCursor::new(token).and_then(|cursor| {
                    cursor.bind(
                        &request.query_digest(),
                        request.page_number().saturating_add(1),
                    )
                })
            })
            .transpose()?;
        let target_digest = request.target.digest();
        let body_digest =
            Digest::from_text(serde_json::to_vec(&body).map_err(|_| ModelError::Invalid {
                field: "RDS normalized page",
            })?);
        let response_digest = Digest::from_parts(
            "aws-rds-response/v1",
            &[
                ("request", request.request_digest().to_string()),
                ("body", body_digest.to_string()),
                ("bytes", response_bytes.to_string()),
            ],
        );
        let mut page = Self {
            request_digest: request.request_digest(),
            operation: request.operation,
            target_digest,
            page_number: request.page_number(),
            complete: next_cursor.is_none(),
            next_cursor,
            body,
            response_bytes,
            response_digest,
            page_digest: Digest::zero(),
            provenance: TransportProvenance::Recording,
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub(crate) fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-read-page/v1",
            &[
                ("request", self.request_digest.to_string()),
                ("operation", self.operation.api_name().to_owned()),
                ("target", self.target_digest.to_string()),
                ("page", self.page_number.to_string()),
                ("complete", self.complete.to_string()),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                ("response", self.response_digest.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, request: &AwsRdsReadRequest) -> ModelResult<()> {
        if self.request_digest != request.request_digest()
            || self.operation != request.operation
            || self.target_digest != request.target.digest()
            || self.page_number != request.page_number()
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
            || self.page_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "RDS page binding or digest",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && (cursor.binding_digest() != Some(&request.query_digest())
                || cursor.page_number() != self.page_number.saturating_add(1))
        {
            return Err(ModelError::InvalidCursor {
                field: "RDS next cursor binding",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    CursorReplay,
    CursorBindingMismatch,
    ResponseTooLarge,
    TargetMismatch,
    RevisionDrift,
    MissingDatabase,
    EventRetentionGap,
    ProviderConflict,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    Partial,
    Conflict,
    MalformedResponse,
    RequestMismatch,
    FixtureExhausted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: AwsRdsReadOperation,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub response_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsRdsHealthState {
    Healthy,
    Degraded,
    Unavailable,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    TimedOut,
    ProviderUnknown,
    RegistrationRevoked,
}

impl AwsRdsHealthState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Unavailable)
    }

    pub const fn is_non_adoptable(self) -> bool {
        !self.is_review_complete()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsDatabaseProjection {
    pub target_digest: Digest,
    pub target_kind: RdsTargetKind,
    pub status: RdsDbStatus,
    pub engine_family: EngineFamily,
    pub engine_version_family: EngineVersionFamily,
    pub endpoint_presence: EndpointPresence,
    pub resource_revision: Revision,
    pub observation_digest: Digest,
}

impl From<&RdsDatabaseObservation> for RdsDatabaseProjection {
    fn from(value: &RdsDatabaseObservation) -> Self {
        Self {
            target_digest: value.target_digest.clone(),
            target_kind: value.target_kind,
            status: value.status,
            engine_family: value.engine.clone(),
            engine_version_family: value.version_family.clone(),
            endpoint_presence: value.endpoint_presence,
            resource_revision: value.resource_revision,
            observation_digest: value.observation_digest.clone(),
        }
    }
}

impl RdsDatabaseProjection {
    pub fn recomputed_observation_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-database-observation/v1",
            &[
                ("target", self.target_digest.to_string()),
                ("kind", self.target_kind.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("engine", self.engine_family.digest().to_string()),
                ("version", self.engine_version_family.digest().to_string()),
                ("endpoint", format!("{:?}", self.endpoint_presence)),
                ("revision", self.resource_revision.get().to_string()),
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
    pub database_digest: Digest,
    pub events_digest: Digest,
    pub maintenance_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsHealthEvidence {
    pub state: AwsRdsHealthState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub target_kind: RdsTargetKind,
    pub database: Option<RdsDatabaseProjection>,
    pub maintenance: Vec<RdsMaintenanceSummary>,
    pub events: Vec<RdsEventSummary>,
    pub page_count: u16,
    pub request_count: u16,
    pub complete: bool,
    pub partial_reason: Option<PartialReason>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub page_digests: Vec<Digest>,
    pub cursor_digests: Vec<Digest>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digests: EvidenceDigests,
}

impl AwsRdsHealthEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: AwsRdsHealthState,
        scope: &AwsRdsHealthScope,
        registration_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        database: Option<RdsDatabaseProjection>,
        maintenance: Vec<RdsMaintenanceSummary>,
        events: Vec<RdsEventSummary>,
        page_count: u16,
        request_count: u16,
        complete: bool,
        partial_reason: Option<PartialReason>,
        provider_errors: Vec<ProviderErrorEvidence>,
        page_digests: Vec<Digest>,
        cursor_digests: Vec<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        let database_digest = database
            .as_ref()
            .map_or_else(Digest::zero, |value| value.observation_digest.clone());
        let events_digest = digest_serialized(&events, "aws-rds-events/v1");
        let maintenance_digest = digest_serialized(&maintenance, "aws-rds-maintenance/v1");
        let mut evidence = Self {
            state,
            scope_digest: scope.digest(),
            registration_digest,
            target_kind: scope.target.kind(),
            database,
            maintenance,
            events,
            page_count,
            request_count,
            complete,
            partial_reason,
            provider_errors,
            page_digests,
            cursor_digests,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            evidence_digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
                contract_digest: crate::contract_digest(),
                provider_digest,
                api_digest,
                permission_digest: scope.permission_digest.clone(),
                scope_digest: scope.digest(),
                database_digest,
                events_digest,
                maintenance_digest,
                evidence_digest: Digest::zero(),
            },
        };
        evidence.evidence_digests.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        let parts = vec![
            ("state", format!("{:?}", self.state)),
            ("scope", self.scope_digest.to_string()),
            ("registration", self.registration_digest.to_string()),
            ("target_kind", self.target_kind.as_str().to_owned()),
            (
                "database",
                serde_json::to_string(&self.database).expect("database projection serializes"),
            ),
            (
                "maintenance",
                serde_json::to_string(&self.maintenance)
                    .expect("maintenance projection serializes"),
            ),
            (
                "events",
                serde_json::to_string(&self.events).expect("event projection serializes"),
            ),
            ("page_count", self.page_count.to_string()),
            ("request_count", self.request_count.to_string()),
            ("complete", self.complete.to_string()),
            (
                "partial_reason",
                self.partial_reason
                    .map_or_else(String::new, |reason| format!("{reason:?}")),
            ),
            (
                "provider_errors",
                serde_json::to_string(&self.provider_errors)
                    .expect("provider error evidence serializes"),
            ),
            (
                "page_digests",
                serde_json::to_string(&self.page_digests).expect("page digests serialize"),
            ),
            (
                "cursor_digests",
                serde_json::to_string(&self.cursor_digests).expect("cursor digests serialize"),
            ),
            ("provenance", self.provenance.as_str().to_owned()),
            ("connected", self.connected.to_string()),
            ("native", self.native.to_string()),
            ("first_party", self.first_party.to_string()),
            (
                "plugin_version",
                self.evidence_digests.plugin_version_digest.to_string(),
            ),
            (
                "contract",
                self.evidence_digests.contract_digest.to_string(),
            ),
            (
                "provider",
                self.evidence_digests.provider_digest.to_string(),
            ),
            ("api", self.evidence_digests.api_digest.to_string()),
            (
                "permission",
                self.evidence_digests.permission_digest.to_string(),
            ),
            (
                "scope_digest",
                self.evidence_digests.scope_digest.to_string(),
            ),
            (
                "database_digest",
                self.evidence_digests.database_digest.to_string(),
            ),
            (
                "events_digest",
                self.evidence_digests.events_digest.to_string(),
            ),
            (
                "maintenance_digest",
                self.evidence_digests.maintenance_digest.to_string(),
            ),
        ];
        Digest::from_parts("aws-rds-health-evidence/v1", &parts)
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digests.evidence_digest
    }

    pub fn validate(&self, scope: &AwsRdsHealthScope) -> ModelResult<()> {
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.evidence_digests.scope_digest != scope.digest()
            || self.evidence_digests.permission_digest != scope.permission_digest
            || self.target_kind != scope.target.kind()
            || self.connected
            || self.native
            || self.first_party
            || self.page_count > MAX_PAGES
            || self.events.len() > MAX_EVENTS
            || self.maintenance.len() > MAX_MAINTENANCE_ACTIONS
            || self.evidence_digests.contract_digest != crate::contract_digest()
            || self.evidence_digests.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "RDS health evidence digest or scope",
            });
        }
        if self.complete && self.partial_reason.is_some() {
            return Err(ModelError::PartialEvidence);
        }
        if let Some(database) = &self.database
            && (database.target_kind != scope.target.kind()
                || database.target_digest != scope.target.digest()
                || database.resource_revision != scope.db_revision
                || database.engine_family != scope.engine.family
                || database.engine_version_family != scope.engine.version_family
                || database.observation_digest != database.recomputed_observation_digest())
        {
            return Err(ModelError::RevisionMismatch {
                field: "RDS evidence database",
            });
        }
        for event in &self.events {
            event.validate_against(&scope.time_window)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentProjection {
    pub id_digest: Digest,
    pub revision: Revision,
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

pub fn deployment_projection(binding: &DeploymentBinding) -> DeploymentProjection {
    DeploymentProjection {
        id_digest: binding.id.digest(),
        revision: binding.revision,
    }
}

pub fn mission_projection(binding: &MissionBinding) -> MissionProjection {
    MissionProjection {
        id_digest: binding.id.digest(),
        revision: binding.revision,
    }
}

pub fn project_projection(binding: &ProjectBinding) -> ProjectProjection {
    ProjectProjection {
        id_digest: binding.id.digest(),
        revision: binding.revision,
    }
}

pub fn work_product_projection(binding: &WorkProductBinding) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: binding.id.digest(),
        revision: binding.revision,
    }
}

pub fn digest_serialized<T: Serialize>(value: &T, tag: &str) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed RDS value is serializable");
    Digest::from_parts(tag, &[("value", hex::encode(bytes))])
}
