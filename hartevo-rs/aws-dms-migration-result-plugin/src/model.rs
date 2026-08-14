//! Typed, bounded AWS DMS scope, request, metadata, and evidence models.
//!
//! Raw DMS payloads are intentionally not modeled. Constructors accept the
//! few provider fields needed to calculate a digest and immediately discard
//! endpoint credentials, markers, stop-reason text, and assessment bodies.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsDmsMigrationError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 12;
pub const MAX_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_COUNTER: u64 = 1_000_000_000_000_000;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "dms:DescribeReplicationTasks",
    "dms:DescribeReplications",
    "dms:DescribeReplicationTaskAssessmentResults",
    "mission.scope",
];

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

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsDmsMigrationError::InvalidDigest { field: "digest" })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::InvalidDigest { field })
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
        self.0.fmt(formatter)
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

fn valid_text(value: &str, max_bytes: usize, internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/+=@*".contains(&byte))
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false) && value.starts_with("arn:")
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $validator:expr, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsDmsMigrationError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsDmsMigrationError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
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

impl From<TaskId> for String {
    fn from(value: TaskId) -> Self {
        value.0
    }
}

impl From<ServerlessReplicationId> for String {
    fn from(value: ServerlessReplicationId) -> Self {
        value.0
    }
}

impl From<ReplicationInstanceId> for String {
    fn from(value: ReplicationInstanceId) -> Self {
        value.0
    }
}

bounded_identifier!(
    AwsAccountId,
    "AWS account id",
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()),
    "aws-dms-account/v1"
);
bounded_identifier!(
    AwsRegion,
    "AWS region",
    |value: &str| valid_identifier(value, 63),
    "aws-dms-region/v1"
);
bounded_identifier!(
    ReplicationTaskArn,
    "replication task ARN",
    valid_arn,
    "aws-dms-replication-task-arn/v1"
);
bounded_identifier!(
    ServerlessReplicationArn,
    "serverless replication ARN",
    valid_arn,
    "aws-dms-serverless-replication-arn/v1"
);
bounded_identifier!(
    ReplicationInstanceArn,
    "replication instance ARN",
    valid_arn,
    "aws-dms-replication-instance-arn/v1"
);
bounded_identifier!(
    EndpointArn,
    "endpoint ARN",
    valid_arn,
    "aws-dms-endpoint-arn/v1"
);
bounded_identifier!(
    DatabaseEngine,
    "database engine",
    |value: &str| valid_identifier(value, 64),
    "aws-dms-database-engine/v1"
);
bounded_identifier!(
    TaskId,
    "replication task id",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-dms-task-id/v1"
);
bounded_identifier!(
    ServerlessReplicationId,
    "serverless replication id",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-dms-serverless-replication-id/v1"
);
bounded_identifier!(
    ReplicationInstanceId,
    "replication instance id",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-dms-replication-instance-id/v1"
);
bounded_identifier!(
    MigrationWindowId,
    "migration window id",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES),
    "aws-dms-window-id/v1"
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsDmsMigrationError::RevisionDrift)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    pub id: String,
    pub revision: Revision,
    pub id_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    pub id: String,
    pub revision: Revision,
    pub id_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    pub id: String,
    pub revision: Revision,
    pub id_digest: Digest,
}

macro_rules! exact_identity_impl {
    ($name:ident, $domain:literal, $label:literal) => {
        impl $name {
            pub fn new(id: impl Into<String>, revision: impl Into<Revision>) -> Result<Self> {
                let id = id.into();
                let revision = revision.into();
                if revision.get() == 0 {
                    return Err(AwsDmsMigrationError::RevisionDrift);
                }
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) {
                    return Err(AwsDmsMigrationError::InvalidIdentifier { field: $label });
                }
                Ok(Self {
                    id_digest: Digest::from_parts($domain, &[("id", id.clone())]),
                    id,
                    revision,
                })
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!($domain, "/binding"),
                    &[
                        ("id", self.id_digest.as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) {
                    return Err(AwsDmsMigrationError::InvalidIdentifier { field: $label });
                }
                if self.revision.get() == 0 {
                    return Err(AwsDmsMigrationError::RevisionDrift);
                }
                self.id_digest.validate($label)?;
                let expected = Digest::from_parts($domain, &[("id", self.id.clone())]);
                if self.id_digest == expected {
                    Ok(())
                } else {
                    Err(AwsDmsMigrationError::IdentityDrift)
                }
            }
        }
    };
}

exact_identity_impl!(MissionIdentity, "aws-dms-mission/v1", "Mission id");
exact_identity_impl!(ProjectIdentity, "aws-dms-project/v1", "Project id");
exact_identity_impl!(
    WorkProductIdentity,
    "aws-dms-work-product/v1",
    "Work Product id"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationWindow {
    pub id: MigrationWindowId,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

impl MigrationWindow {
    pub fn new(
        id: MigrationWindowId,
        starts_at: DateTime<Utc>,
        ends_at: DateTime<Utc>,
    ) -> Result<Self> {
        let window = Self {
            id,
            starts_at,
            ends_at,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn duration(&self) -> Duration {
        self.ends_at - self.starts_at
    }

    pub fn contains(&self, observed_at: DateTime<Utc>) -> bool {
        observed_at >= self.starts_at && observed_at <= self.ends_at
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-migration-window/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("starts_at", self.starts_at.to_rfc3339()),
                ("ends_at", self.ends_at.to_rfc3339()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        let seconds = self.duration().num_seconds();
        if seconds <= 0 || seconds > MAX_WINDOW_SECONDS {
            Err(AwsDmsMigrationError::InvalidWindow)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EndpointIdentity {
    arn: EndpointArn,
    engine: DatabaseEngine,
}

impl EndpointIdentity {
    pub fn new(arn: EndpointArn, engine: DatabaseEngine) -> Result<Self> {
        let identity = Self { arn, engine };
        identity.validate()?;
        Ok(identity)
    }

    pub fn arn(&self) -> &EndpointArn {
        &self.arn
    }

    pub fn engine(&self) -> &DatabaseEngine {
        &self.engine
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-endpoint-identity/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("engine", self.engine.digest().as_str().to_owned()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.engine.validate()
    }
}

impl fmt::Debug for EndpointIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointIdentity")
            .field("digest", &self.digest())
            .field("engine", &self.engine)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReplicationTaskIdentity {
    arn: ReplicationTaskArn,
    id_digest: Digest,
}

impl ReplicationTaskIdentity {
    pub fn new(arn: ReplicationTaskArn, id: impl Into<String>) -> Result<Self> {
        let id = TaskId::new(id.into())?;
        id.validate()?;
        let identity = Self {
            arn,
            id_digest: id.digest(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn arn(&self) -> &ReplicationTaskArn {
        &self.arn
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-replication-task/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("id", self.id_digest.as_str().to_owned()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.id_digest.validate("task id digest")
    }
}

impl fmt::Debug for ReplicationTaskIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicationTaskIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ServerlessReplicationIdentity {
    arn: ServerlessReplicationArn,
    id_digest: Digest,
}

impl ServerlessReplicationIdentity {
    pub fn new(arn: ServerlessReplicationArn, id: impl Into<String>) -> Result<Self> {
        let id = ServerlessReplicationId::new(id.into())?;
        id.validate()?;
        let identity = Self {
            arn,
            id_digest: id.digest(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn arn(&self) -> &ServerlessReplicationArn {
        &self.arn
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-serverless-replication/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("id", self.id_digest.as_str().to_owned()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.id_digest.validate("serverless replication id digest")
    }
}

impl fmt::Debug for ServerlessReplicationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerlessReplicationIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationIdentity {
    Task(ReplicationTaskIdentityProjection),
    Serverless(ServerlessReplicationIdentityProjection),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReplicationTaskIdentityProjection {
    pub arn_digest: Digest,
    pub id_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServerlessReplicationIdentityProjection {
    pub arn_digest: Digest,
    pub id_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ReplicationIdentityValue {
    Task(ReplicationTaskIdentity),
    Serverless(ServerlessReplicationIdentity),
}

impl ReplicationIdentityValue {
    pub fn task(identity: ReplicationTaskIdentity) -> Self {
        Self::Task(identity)
    }

    pub fn serverless(identity: ServerlessReplicationIdentity) -> Self {
        Self::Serverless(identity)
    }

    pub fn digest(&self) -> Digest {
        match self {
            Self::Task(value) => value.digest(),
            Self::Serverless(value) => value.digest(),
        }
    }

    pub fn kind(&self) -> ReplicationKind {
        match self {
            Self::Task(_) => ReplicationKind::Task,
            Self::Serverless(_) => ReplicationKind::Serverless,
        }
    }

    pub fn task_arn_digest(&self) -> Option<Digest> {
        match self {
            Self::Task(value) => Some(value.arn.digest()),
            Self::Serverless(_) => None,
        }
    }

    pub fn replication_arn_digest(&self) -> Digest {
        match self {
            Self::Task(value) => value.arn.digest(),
            Self::Serverless(value) => value.arn.digest(),
        }
    }
}

impl fmt::Debug for ReplicationIdentityValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicationIdentityValue")
            .field("kind", &self.kind())
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationKind {
    Task,
    Serverless,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReplicationInstanceIdentity {
    arn: ReplicationInstanceArn,
    id_digest: Digest,
}

impl ReplicationInstanceIdentity {
    pub fn new(arn: ReplicationInstanceArn, id: impl Into<String>) -> Result<Self> {
        let id = ReplicationInstanceId::new(id.into())?;
        id.validate()?;
        let identity = Self {
            arn,
            id_digest: id.digest(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn arn(&self) -> &ReplicationInstanceArn {
        &self.arn
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-replication-instance/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("id", self.id_digest.as_str().to_owned()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.id_digest.validate("replication instance id digest")
    }
}

impl fmt::Debug for ReplicationInstanceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicationInstanceIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsDmsScope {
    account: AwsAccountId,
    region: AwsRegion,
    replication: ReplicationIdentityValue,
    source_endpoint: EndpointIdentity,
    target_endpoint: EndpointIdentity,
    replication_instance: Option<ReplicationInstanceIdentity>,
    task_revision: Revision,
    migration_window: MigrationWindow,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsDmsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        replication: ReplicationIdentityValue,
        source_endpoint: EndpointIdentity,
        target_endpoint: EndpointIdentity,
        replication_instance: Option<ReplicationInstanceIdentity>,
        task_revision: impl Into<Revision>,
        migration_window: MigrationWindow,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let task_revision = task_revision.into();
        let scope = Self {
            account,
            region,
            replication,
            source_endpoint,
            target_endpoint,
            replication_instance,
            task_revision,
            migration_window,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn replication(&self) -> &ReplicationIdentityValue {
        &self.replication
    }

    pub fn source_endpoint(&self) -> &EndpointIdentity {
        &self.source_endpoint
    }

    pub fn target_endpoint(&self) -> &EndpointIdentity {
        &self.target_endpoint
    }

    pub fn replication_instance(&self) -> Option<&ReplicationInstanceIdentity> {
        self.replication_instance.as_ref()
    }

    pub const fn task_revision(&self) -> Revision {
        self.task_revision
    }

    pub fn migration_window(&self) -> &MigrationWindow {
        &self.migration_window
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("replication", self.replication.digest().as_str().to_owned()),
                ("source", self.source_endpoint.digest().as_str().to_owned()),
                ("target", self.target_endpoint.digest().as_str().to_owned()),
                (
                    "instance",
                    self.replication_instance
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("task_revision", self.task_revision.get().to_string()),
                ("window", self.migration_window.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        match &self.replication {
            ReplicationIdentityValue::Task(value) => value.validate()?,
            ReplicationIdentityValue::Serverless(value) => value.validate()?,
        }
        self.source_endpoint.validate()?;
        self.target_endpoint.validate()?;
        if self.source_endpoint.digest() == self.target_endpoint.digest() {
            return Err(AwsDmsMigrationError::InvalidScope);
        }
        if let Some(instance) = &self.replication_instance {
            instance.validate()?;
        }
        if self.task_revision.get() == 0 {
            return Err(AwsDmsMigrationError::RevisionDrift);
        }
        self.migration_window.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsDmsScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDmsScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("replication", &self.replication)
            .field("source_endpoint", &self.source_endpoint)
            .field("target_endpoint", &self.target_endpoint)
            .field("replication_instance", &self.replication_instance)
            .field("task_revision", &self.task_revision)
            .field("migration_window", &self.migration_window)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller handle is hashed and zeroized; this
/// type deliberately has no `Serialize` implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: impl Into<Revision>) -> Result<Self> {
        let revision = revision.into();
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision.get() == 0 {
            handle.zeroize();
            return Err(AwsDmsMigrationError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-dms-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.get().to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-dms-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsDmsScope,
        revision: impl Into<Revision>,
    ) -> Result<Self> {
        let revision = revision.into();
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-dms-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn for_scope(opaque_handle: impl Into<String>, scope: &AwsDmsScope) -> Result<Self> {
        Self::sigv4(opaque_handle, scope, Revision::new(1)?)
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.reference_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AwsDmsScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsDmsMigrationError::InvalidSecretReference);
        }
        self.reference_digest.validate("secret reference digest")
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S, R>(revision: R, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        R: Into<Revision>,
    {
        let snapshot = Self {
            revision: revision.into(),
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: impl Into<Revision>) -> Self {
        Self {
            revision: revision.into(),
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-permissions/v1",
            &[
                ("revision", self.revision.get().to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsDmsMigrationError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: Revision,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S, R>(
        id: impl Into<String>,
        revision: R,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        R: Into<Revision>,
    {
        let consent = Self {
            id: id.into(),
            revision: revision.into(),
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: impl Into<Revision>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.get().to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at >= DateTime::<Utc>::MIN_UTC && at <= self.expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision.get() == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsDmsMigrationError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplicationTaskState {
    Creating,
    Ready,
    Running,
    Starting,
    Stopping,
    Stopped,
    Failed,
    Modifying,
    Deleting,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplicationState {
    Creating,
    Ready,
    Running,
    Stopped,
    Failed,
    Deleting,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationType {
    FullLoad,
    Cdc,
    FullLoadAndCdc,
    Serverless,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentStatus {
    Passed,
    Failed,
    Warning,
    NotRun,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullLoadProgress {
    pub tables_loaded: u64,
    pub tables_loading: u64,
    pub tables_queued: u64,
    pub tables_errored: u64,
    pub bytes_loaded: u64,
}

impl FullLoadProgress {
    pub fn new(
        tables_loaded: u64,
        tables_loading: u64,
        tables_queued: u64,
        tables_errored: u64,
        bytes_loaded: u64,
    ) -> Result<Self> {
        let progress = Self {
            tables_loaded,
            tables_loading,
            tables_queued,
            tables_errored,
            bytes_loaded,
        };
        if [
            tables_loaded,
            tables_loading,
            tables_queued,
            tables_errored,
            bytes_loaded,
        ]
        .into_iter()
        .any(|value| value > MAX_COUNTER)
        {
            Err(AwsDmsMigrationError::InvalidRequest)
        } else {
            Ok(progress)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-full-load-progress/v1",
            &[
                ("tables_loaded", self.tables_loaded.to_string()),
                ("tables_loading", self.tables_loading.to_string()),
                ("tables_queued", self.tables_queued.to_string()),
                ("tables_errored", self.tables_errored.to_string()),
                ("bytes_loaded", self.bytes_loaded.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentResultMetadata {
    pub replication_digest: Digest,
    pub task_revision: Revision,
    pub status: AssessmentStatus,
    pub assessed_at: DateTime<Utc>,
    pub report_digest: Option<Digest>,
    pub result_digest: Digest,
}

impl AssessmentResultMetadata {
    pub fn new(
        scope: &AwsDmsScope,
        status: AssessmentStatus,
        assessed_at: DateTime<Utc>,
        report_body: Option<&[u8]>,
    ) -> Result<Self> {
        let report_digest = report_body.map(Digest::from_bytes);
        Self::from_digest(scope, status, assessed_at, report_digest)
    }

    pub fn from_digest(
        scope: &AwsDmsScope,
        status: AssessmentStatus,
        assessed_at: DateTime<Utc>,
        report_digest: Option<Digest>,
    ) -> Result<Self> {
        if !scope.migration_window().contains(assessed_at) {
            return Err(AwsDmsMigrationError::InvalidWindow);
        }
        if let Some(digest) = &report_digest {
            digest.validate("assessment report digest")?;
        }
        let result_digest = Digest::from_parts(
            "aws-dms-assessment-result/v1",
            &[
                (
                    "replication",
                    scope.replication().digest().as_str().to_owned(),
                ),
                ("revision", scope.task_revision().get().to_string()),
                ("status", format!("{status:?}")),
                ("assessed_at", assessed_at.to_rfc3339()),
                (
                    "report",
                    report_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            replication_digest: scope.replication().digest(),
            task_revision: scope.task_revision(),
            status,
            assessed_at,
            report_digest,
            result_digest,
        })
    }

    pub fn validate_against(&self, scope: &AwsDmsScope) -> Result<()> {
        if self.replication_digest != scope.replication().digest()
            || !scope.migration_window().contains(self.assessed_at)
        {
            return Err(AwsDmsMigrationError::IdentityDrift);
        }
        if self.task_revision != scope.task_revision() {
            return Err(AwsDmsMigrationError::RevisionDrift);
        }
        if let Some(digest) = &self.report_digest {
            digest.validate("assessment report digest")?;
        }
        let expected = Digest::from_parts(
            "aws-dms-assessment-result/v1",
            &[
                ("replication", self.replication_digest.as_str().to_owned()),
                ("revision", self.task_revision.get().to_string()),
                ("status", format!("{:?}", self.status)),
                ("assessed_at", self.assessed_at.to_rfc3339()),
                (
                    "report",
                    self.report_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        if expected == self.result_digest {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

#[derive(Clone)]
pub struct ReplicationTaskMetadataInput {
    pub state: ReplicationTaskState,
    pub migration_type: MigrationType,
    pub full_load_progress: FullLoadProgress,
    pub stop_reason: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub assessment: Option<AssessmentResultMetadata>,
}

impl fmt::Debug for ReplicationTaskMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicationTaskMetadataInput")
            .field("state", &self.state)
            .field("migration_type", &self.migration_type)
            .field("full_load_progress", &self.full_load_progress)
            .field(
                "stop_reason_digest",
                &self.stop_reason.as_ref().map(Digest::from_text),
            )
            .field("observed_at", &self.observed_at)
            .field("assessment", &self.assessment)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationTaskMetadata {
    pub replication_digest: Digest,
    pub task_revision: Revision,
    pub state: ReplicationTaskState,
    pub migration_type: MigrationType,
    pub source_endpoint_digest: Digest,
    pub target_endpoint_digest: Digest,
    pub replication_instance_digest: Option<Digest>,
    pub full_load_progress: FullLoadProgress,
    pub stop_reason_digest: Option<Digest>,
    pub assessment: Option<AssessmentResultMetadata>,
    pub observed_at: DateTime<Utc>,
    pub metadata_digest: Digest,
}

impl ReplicationTaskMetadata {
    pub fn new(
        scope: &AwsDmsScope,
        state: ReplicationTaskState,
        migration_type: MigrationType,
        full_load_progress: FullLoadProgress,
        stop_reason: Option<String>,
        observed_at: DateTime<Utc>,
        assessment: Option<AssessmentResultMetadata>,
    ) -> Result<Self> {
        let stop_reason_digest = stop_reason.map(|reason| Digest::from_text(reason.as_bytes()));
        let metadata = Self {
            replication_digest: scope.replication().digest(),
            task_revision: scope.task_revision(),
            state,
            migration_type,
            source_endpoint_digest: scope.source_endpoint().digest(),
            target_endpoint_digest: scope.target_endpoint().digest(),
            replication_instance_digest: scope
                .replication_instance()
                .map(ReplicationInstanceIdentity::digest),
            full_load_progress,
            stop_reason_digest,
            assessment,
            observed_at,
            metadata_digest: Digest::zero(),
        };
        let metadata = Self {
            metadata_digest: metadata.recomputed_digest(),
            ..metadata
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-replication-task-metadata/v1",
            &[
                ("replication", self.replication_digest.as_str().to_owned()),
                ("revision", self.task_revision.get().to_string()),
                ("state", format!("{:?}", self.state)),
                ("migration_type", format!("{:?}", self.migration_type)),
                ("source", self.source_endpoint_digest.as_str().to_owned()),
                ("target", self.target_endpoint_digest.as_str().to_owned()),
                (
                    "instance",
                    self.replication_instance_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "progress",
                    self.full_load_progress.digest().as_str().to_owned(),
                ),
                (
                    "stop_reason",
                    self.stop_reason_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "assessment",
                    self.assessment
                        .as_ref()
                        .map_or_else(String::new, |value| value.result_digest.as_str().to_owned()),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsDmsScope) -> Result<()> {
        if self.replication_digest != scope.replication().digest()
            || self.source_endpoint_digest != scope.source_endpoint().digest()
            || self.target_endpoint_digest != scope.target_endpoint().digest()
            || self.replication_instance_digest
                != scope
                    .replication_instance()
                    .map(ReplicationInstanceIdentity::digest)
            || !scope.migration_window().contains(self.observed_at)
        {
            return Err(AwsDmsMigrationError::IdentityDrift);
        }
        if self.task_revision != scope.task_revision() {
            return Err(AwsDmsMigrationError::RevisionDrift);
        }
        if let Some(assessment) = &self.assessment {
            assessment.validate_against(scope)?;
        }
        if self.metadata_digest == self.recomputed_digest() {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationMetadata {
    pub replication_digest: Digest,
    pub state: ReplicationState,
    pub migration_type: MigrationType,
    pub source_endpoint_digest: Digest,
    pub target_endpoint_digest: Digest,
    pub replication_instance_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub metadata_digest: Digest,
}

impl ReplicationMetadata {
    pub fn new(
        scope: &AwsDmsScope,
        state: ReplicationState,
        migration_type: MigrationType,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let metadata = Self {
            replication_digest: scope.replication().digest(),
            state,
            migration_type,
            source_endpoint_digest: scope.source_endpoint().digest(),
            target_endpoint_digest: scope.target_endpoint().digest(),
            replication_instance_digest: scope
                .replication_instance()
                .map(ReplicationInstanceIdentity::digest),
            observed_at,
            metadata_digest: Digest::zero(),
        };
        let metadata = Self {
            metadata_digest: metadata.recomputed_digest(),
            ..metadata
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-replication-metadata/v1",
            &[
                ("replication", self.replication_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("migration_type", format!("{:?}", self.migration_type)),
                ("source", self.source_endpoint_digest.as_str().to_owned()),
                ("target", self.target_endpoint_digest.as_str().to_owned()),
                (
                    "instance",
                    self.replication_instance_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsDmsScope) -> Result<()> {
        if self.replication_digest != scope.replication().digest()
            || self.source_endpoint_digest != scope.source_endpoint().digest()
            || self.target_endpoint_digest != scope.target_endpoint().digest()
            || self.replication_instance_digest
                != scope
                    .replication_instance()
                    .map(ReplicationInstanceIdentity::digest)
            || !scope.migration_window().contains(self.observed_at)
        {
            return Err(AwsDmsMigrationError::IdentityDrift);
        }
        if self.metadata_digest == self.recomputed_digest() {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: DmsOperation,
    pub category: String,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl FailureEvidence {
    pub fn new(
        operation: DmsOperation,
        category: impl Into<String>,
        status_code: Option<u16>,
    ) -> Self {
        let category = category.into();
        let error_digest = Digest::from_parts(
            "aws-dms-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.clone()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            operation,
            category,
            status_code,
            error_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DmsOperation {
    DescribeReplicationTasks,
    DescribeReplications,
    DescribeReplicationTaskAssessmentResults,
}

impl DmsOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeReplicationTasks => "DescribeReplicationTasks",
            Self::DescribeReplications => "DescribeReplications",
            Self::DescribeReplicationTaskAssessmentResults => {
                "DescribeReplicationTaskAssessmentResults"
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueMarker {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl OpaqueMarker {
    pub fn new(
        raw_token: impl Into<String>,
        scope: &AwsDmsScope,
        operation: DmsOperation,
        max_records: u16,
        page_number: u16,
    ) -> Result<Self> {
        let mut token = raw_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || max_records == 0
            || max_records > MAX_PAGE_SIZE
            || page_number == 0
        {
            token.zeroize();
            return Err(AwsDmsMigrationError::InvalidRequest);
        }
        let token_digest = Digest::from_text(token.as_bytes());
        token.zeroize();
        let binding_digest = Self::binding(scope, operation, max_records, page_number);
        Ok(Self {
            token_digest,
            binding_digest,
            page_number,
        })
    }

    fn binding(
        scope: &AwsDmsScope,
        operation: DmsOperation,
        max_records: u16,
        page_number: u16,
    ) -> Digest {
        Self::binding_from_scope_digest(&scope.digest(), operation, max_records, page_number)
    }

    fn binding_from_scope_digest(
        scope_digest: &Digest,
        operation: DmsOperation,
        max_records: u16,
        page_number: u16,
    ) -> Digest {
        Digest::from_parts(
            "aws-dms-marker-binding/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("operation", operation.as_str().to_owned()),
                ("max_records", max_records.to_string()),
                ("page", page_number.to_string()),
            ],
        )
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(
        &self,
        scope: &AwsDmsScope,
        operation: DmsOperation,
        max_records: u16,
    ) -> Result<()> {
        if self.binding_digest == Self::binding(scope, operation, max_records, self.page_number)
            && self.page_number <= MAX_PAGES
        {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::MarkerMismatch)
        }
    }

    fn validate_against_request(
        &self,
        scope_digest: &Digest,
        operation: DmsOperation,
        max_records: u16,
        page_number: u16,
    ) -> Result<()> {
        self.token_digest.validate("marker token digest")?;
        self.binding_digest.validate("marker binding digest")?;
        if self.page_number == page_number
            && self.binding_digest
                == Self::binding_from_scope_digest(
                    scope_digest,
                    operation,
                    max_records,
                    page_number,
                )
            && page_number <= MAX_PAGES
        {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::MarkerMismatch)
        }
    }
}

impl fmt::Debug for OpaqueMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueMarker")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDmsMigrationReadRequest {
    pub scope_digest: Digest,
    pub replication_arn_digest: Digest,
    pub source_endpoint_digest: Digest,
    pub target_endpoint_digest: Digest,
    pub task_revision: Revision,
    pub migration_window: MigrationWindow,
    pub max_records: u16,
    pub max_pages: u16,
    pub request_digest: Digest,
}

impl AwsDmsMigrationReadRequest {
    pub fn new(
        scope: &AwsDmsScope,
        max_records: u16,
        max_pages: u16,
        migration_window: MigrationWindow,
    ) -> Result<Self> {
        if max_records == 0
            || max_records > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || migration_window != *scope.migration_window()
        {
            return Err(AwsDmsMigrationError::InvalidRequest);
        }
        let request = Self {
            scope_digest: scope.digest(),
            replication_arn_digest: scope.replication().replication_arn_digest(),
            source_endpoint_digest: scope.source_endpoint().digest(),
            target_endpoint_digest: scope.target_endpoint().digest(),
            task_revision: scope.task_revision(),
            migration_window,
            max_records,
            max_pages,
            request_digest: Digest::zero(),
        };
        Ok(Self {
            request_digest: request.recomputed_digest(),
            ..request
        })
    }

    pub fn for_scope(scope: &AwsDmsScope, max_records: u16, max_pages: u16) -> Result<Self> {
        Self::new(
            scope,
            max_records,
            max_pages,
            scope.migration_window().clone(),
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-read-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "replication",
                    self.replication_arn_digest.as_str().to_owned(),
                ),
                ("source", self.source_endpoint_digest.as_str().to_owned()),
                ("target", self.target_endpoint_digest.as_str().to_owned()),
                ("revision", self.task_revision.get().to_string()),
                ("window", self.migration_window.digest().as_str().to_owned()),
                ("max_records", self.max_records.to_string()),
                ("max_pages", self.max_pages.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsDmsScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.replication_arn_digest != scope.replication().replication_arn_digest()
            || self.source_endpoint_digest != scope.source_endpoint().digest()
            || self.target_endpoint_digest != scope.target_endpoint().digest()
            || self.migration_window != *scope.migration_window()
            || self.max_records == 0
            || self.max_records > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            return Err(AwsDmsMigrationError::ScopeMismatch);
        }
        if self.task_revision != scope.task_revision() {
            return Err(AwsDmsMigrationError::RevisionDrift);
        }
        if self.request_digest == self.recomputed_digest() {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }

    pub fn tasks_request(
        &self,
        scope: &AwsDmsScope,
        marker: Option<OpaqueMarker>,
        page_number: u16,
    ) -> Result<DescribeReplicationTasksRequest> {
        DescribeReplicationTasksRequest::new(self, scope, marker, page_number)
    }

    pub fn replications_request(
        &self,
        scope: &AwsDmsScope,
        marker: Option<OpaqueMarker>,
        page_number: u16,
    ) -> Result<DescribeReplicationsRequest> {
        DescribeReplicationsRequest::new(self, scope, marker, page_number)
    }

    pub fn assessment_request(
        &self,
        scope: &AwsDmsScope,
        marker: Option<OpaqueMarker>,
        page_number: u16,
    ) -> Result<DescribeReplicationTaskAssessmentResultsRequest> {
        DescribeReplicationTaskAssessmentResultsRequest::new(self, scope, marker, page_number)
    }
}

macro_rules! page_request {
    ($name:ident, $operation:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub base_request_digest: Digest,
            pub scope_digest: Digest,
            pub replication_arn_digest: Digest,
            pub task_revision: Revision,
            pub migration_window: MigrationWindow,
            pub max_records: u16,
            pub page_number: u16,
            pub marker: Option<OpaqueMarker>,
            pub request_digest: Digest,
        }

        impl $name {
            pub(crate) fn new(
                base: &AwsDmsMigrationReadRequest,
                scope: &AwsDmsScope,
                marker: Option<OpaqueMarker>,
                page_number: u16,
            ) -> Result<Self> {
                base.validate_against(scope)?;
                if page_number == 0 || page_number > base.max_pages {
                    return Err(AwsDmsMigrationError::InvalidRequest);
                }
                if let Some(value) = &marker {
                    value.validate_against(scope, $operation, base.max_records)?;
                    if value.page_number() != page_number.saturating_sub(1) {
                        return Err(AwsDmsMigrationError::MarkerMismatch);
                    }
                }
                let request = Self {
                    base_request_digest: base.request_digest.clone(),
                    scope_digest: base.scope_digest.clone(),
                    replication_arn_digest: base.replication_arn_digest.clone(),
                    task_revision: base.task_revision,
                    migration_window: base.migration_window.clone(),
                    max_records: base.max_records,
                    page_number,
                    marker,
                    request_digest: Digest::zero(),
                };
                Ok(Self {
                    request_digest: request.recomputed_digest(),
                    ..request
                })
            }

            pub const fn operation(&self) -> DmsOperation {
                $operation
            }

            pub fn recomputed_digest(&self) -> Digest {
                Digest::from_parts(
                    "aws-dms-page-request/v1",
                    &[
                        ("operation", self.operation().as_str().to_owned()),
                        ("base", self.base_request_digest.as_str().to_owned()),
                        ("scope", self.scope_digest.as_str().to_owned()),
                        (
                            "replication",
                            self.replication_arn_digest.as_str().to_owned(),
                        ),
                        ("revision", self.task_revision.get().to_string()),
                        ("window", self.migration_window.digest().as_str().to_owned()),
                        ("max_records", self.max_records.to_string()),
                        ("page", self.page_number.to_string()),
                        (
                            "marker",
                            self.marker.as_ref().map_or_else(String::new, |value| {
                                value.token_digest().as_str().to_owned()
                            }),
                        ),
                        (
                            "marker_binding",
                            self.marker.as_ref().map_or_else(String::new, |value| {
                                value.binding_digest().as_str().to_owned()
                            }),
                        ),
                    ],
                )
            }

            pub fn validate_against(&self, scope: &AwsDmsScope) -> Result<()> {
                if self.scope_digest != scope.digest()
                    || self.replication_arn_digest != scope.replication().replication_arn_digest()
                    || self.migration_window != *scope.migration_window()
                    || self.page_number == 0
                    || self.page_number > MAX_PAGES
                {
                    return Err(AwsDmsMigrationError::ScopeMismatch);
                }
                if self.task_revision != scope.task_revision() {
                    return Err(AwsDmsMigrationError::RevisionDrift);
                }
                if let Some(value) = &self.marker {
                    value.validate_against(scope, self.operation(), self.max_records)?;
                }
                if self.request_digest == self.recomputed_digest() {
                    Ok(())
                } else {
                    Err(AwsDmsMigrationError::TamperedEvidence)
                }
            }
        }
    };
}

page_request!(
    DescribeReplicationTasksRequest,
    DmsOperation::DescribeReplicationTasks
);
page_request!(
    DescribeReplicationsRequest,
    DmsOperation::DescribeReplications
);
page_request!(
    DescribeReplicationTaskAssessmentResultsRequest,
    DmsOperation::DescribeReplicationTaskAssessmentResults
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeReplicationTasksResponse {
    pub request_digest: Digest,
    pub tasks: Vec<ReplicationTaskMetadata>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
}

impl DescribeReplicationTasksResponse {
    pub fn new(
        request: &DescribeReplicationTasksRequest,
        scope: &AwsDmsScope,
        tasks: Vec<ReplicationTaskMetadata>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate_against(scope)?;
        if tasks.len() > usize::from(request.max_records) || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsDmsMigrationError::PartialEvidence);
        }
        for task in &tasks {
            task.validate_against(scope)?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            scope,
            DmsOperation::DescribeReplicationTasks,
            request.max_records,
            request.page_number,
        )?;
        let page_digest = page_digest(
            request.request_digest.clone(),
            tasks.iter().map(|value| value.metadata_digest.clone()),
            next_marker.as_ref(),
            response_bytes,
            &provenance,
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            tasks,
            next_marker,
            response_bytes,
            provenance,
            page_digest,
        })
    }

    pub const fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub(crate) fn validate_integrity(
        &self,
        request: &DescribeReplicationTasksRequest,
    ) -> Result<()> {
        if self.request_digest != request.request_digest || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsDmsMigrationError::TamperedEvidence);
        }
        for task in &self.tasks {
            if task.metadata_digest != task.recomputed_digest() {
                return Err(AwsDmsMigrationError::TamperedEvidence);
            }
            if let Some(assessment) = &task.assessment {
                assessment.validate_against_replication_only()?;
            }
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_against_request(
                &request.scope_digest,
                DmsOperation::DescribeReplicationTasks,
                request.max_records,
                request.page_number,
            )?;
        }
        let expected = page_digest(
            self.request_digest.clone(),
            self.tasks.iter().map(|value| value.metadata_digest.clone()),
            self.next_marker.as_ref(),
            self.response_bytes,
            &self.provenance,
        );
        if self.page_digest == expected {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeReplicationsResponse {
    pub request_digest: Digest,
    pub replications: Vec<ReplicationMetadata>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
}

impl DescribeReplicationsResponse {
    pub fn new(
        request: &DescribeReplicationsRequest,
        scope: &AwsDmsScope,
        replications: Vec<ReplicationMetadata>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate_against(scope)?;
        if replications.len() > usize::from(request.max_records)
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsDmsMigrationError::PartialEvidence);
        }
        for replication in &replications {
            replication.validate_against(scope)?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            scope,
            DmsOperation::DescribeReplications,
            request.max_records,
            request.page_number,
        )?;
        let page_digest = page_digest(
            request.request_digest.clone(),
            replications
                .iter()
                .map(|value| value.metadata_digest.clone()),
            next_marker.as_ref(),
            response_bytes,
            &provenance,
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            replications,
            next_marker,
            response_bytes,
            provenance,
            page_digest,
        })
    }

    pub const fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub(crate) fn validate_integrity(&self, request: &DescribeReplicationsRequest) -> Result<()> {
        if self.request_digest != request.request_digest || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsDmsMigrationError::TamperedEvidence);
        }
        for replication in &self.replications {
            if replication.metadata_digest != replication.recomputed_digest() {
                return Err(AwsDmsMigrationError::TamperedEvidence);
            }
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_against_request(
                &request.scope_digest,
                DmsOperation::DescribeReplications,
                request.max_records,
                request.page_number,
            )?;
        }
        let expected = page_digest(
            self.request_digest.clone(),
            self.replications
                .iter()
                .map(|value| value.metadata_digest.clone()),
            self.next_marker.as_ref(),
            self.response_bytes,
            &self.provenance,
        );
        if self.page_digest == expected {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeReplicationTaskAssessmentResultsResponse {
    pub request_digest: Digest,
    pub assessments: Vec<AssessmentResultMetadata>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
}

impl DescribeReplicationTaskAssessmentResultsResponse {
    pub fn new(
        request: &DescribeReplicationTaskAssessmentResultsRequest,
        scope: &AwsDmsScope,
        assessments: Vec<AssessmentResultMetadata>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate_against(scope)?;
        if assessments.len() > usize::from(request.max_records)
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsDmsMigrationError::PartialEvidence);
        }
        for assessment in &assessments {
            assessment.validate_against(scope)?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            scope,
            DmsOperation::DescribeReplicationTaskAssessmentResults,
            request.max_records,
            request.page_number,
        )?;
        let page_digest = page_digest(
            request.request_digest.clone(),
            assessments.iter().map(|value| value.result_digest.clone()),
            next_marker.as_ref(),
            response_bytes,
            &provenance,
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            assessments,
            next_marker,
            response_bytes,
            provenance,
            page_digest,
        })
    }

    pub const fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub(crate) fn validate_integrity(
        &self,
        request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> Result<()> {
        if self.request_digest != request.request_digest || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsDmsMigrationError::TamperedEvidence);
        }
        for assessment in &self.assessments {
            assessment.validate_against_replication_only()?;
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_against_request(
                &request.scope_digest,
                DmsOperation::DescribeReplicationTaskAssessmentResults,
                request.max_records,
                request.page_number,
            )?;
        }
        let expected = page_digest(
            self.request_digest.clone(),
            self.assessments
                .iter()
                .map(|value| value.result_digest.clone()),
            self.next_marker.as_ref(),
            self.response_bytes,
            &self.provenance,
        );
        if self.page_digest == expected {
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

fn validate_next_marker(
    marker: Option<&OpaqueMarker>,
    scope: &AwsDmsScope,
    operation: DmsOperation,
    max_records: u16,
    page_number: u16,
) -> Result<()> {
    if let Some(value) = marker {
        value.validate_against(scope, operation, max_records)?;
        if value.page_number() != page_number {
            return Err(AwsDmsMigrationError::MarkerMismatch);
        }
    }
    Ok(())
}

fn page_digest<I>(
    request_digest: Digest,
    item_digests: I,
    next_marker: Option<&OpaqueMarker>,
    response_bytes: usize,
    provenance: &TransportProvenance,
) -> Digest
where
    I: IntoIterator<Item = Digest>,
{
    let items = item_digests
        .into_iter()
        .map(|digest| digest.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    Digest::from_parts(
        "aws-dms-provider-page/v1",
        &[
            ("request", request_digest.as_str().to_owned()),
            ("items", items),
            (
                "marker",
                next_marker.map_or_else(String::new, |marker| {
                    marker.token_digest().as_str().to_owned()
                }),
            ),
            ("bytes", response_bytes.to_string()),
            ("provenance", provenance.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Completed,
    InProgress,
    Stopped,
    Failed,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Completed | Self::InProgress)
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Completed | Self::InProgress)
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
    pub task_request_digest: Digest,
    pub replication_request_digest: Digest,
    pub assessment_request_digest: Digest,
    pub task_pages_digest: Option<Digest>,
    pub replication_pages_digest: Option<Digest>,
    pub assessment_pages_digest: Option<Digest>,
    pub task_marker_digest: Option<Digest>,
    pub replication_marker_digest: Option<Digest>,
    pub assessment_marker_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.id_digest.clone(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.id_digest.clone(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: value.id_digest.clone(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDmsMigrationEvidence {
    pub state: EvidenceState,
    pub task: Option<ReplicationTaskMetadata>,
    pub replication: Option<ReplicationMetadata>,
    pub assessment: Option<AssessmentResultMetadata>,
    pub task_pages: u16,
    pub replication_pages: u16,
    pub assessment_pages: u16,
    pub task_complete: bool,
    pub replication_complete: bool,
    pub assessment_complete: bool,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub digests: EvidenceDigests,
}

impl AwsDmsMigrationEvidence {
    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("task", digest_json(&self.task)),
                ("replication", digest_json(&self.replication)),
                ("assessment", digest_json(&self.assessment)),
                ("task_pages", self.task_pages.to_string()),
                ("replication_pages", self.replication_pages.to_string()),
                ("assessment_pages", self.assessment_pages.to_string()),
                ("task_complete", self.task_complete.to_string()),
                (
                    "replication_complete",
                    self.replication_complete.to_string(),
                ),
                ("assessment_complete", self.assessment_complete.to_string()),
                ("failure", digest_json(&self.failure)),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "plugin_version",
                    self.digests.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.digests.contract_digest.as_str().to_owned()),
                ("provider", self.digests.provider_digest.as_str().to_owned()),
                ("api", self.digests.api_digest.as_str().to_owned()),
                (
                    "permission",
                    self.digests.permission_digest.as_str().to_owned(),
                ),
                ("consent", self.digests.consent_digest.as_str().to_owned()),
                ("scope", self.digests.scope_digest.as_str().to_owned()),
                (
                    "task_request",
                    self.digests.task_request_digest.as_str().to_owned(),
                ),
                (
                    "replication_request",
                    self.digests.replication_request_digest.as_str().to_owned(),
                ),
                (
                    "assessment_request",
                    self.digests.assessment_request_digest.as_str().to_owned(),
                ),
                (
                    "task_pages_digest",
                    self.digests
                        .task_pages_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "replication_pages_digest",
                    self.digests
                        .replication_pages_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "assessment_pages_digest",
                    self.digests
                        .assessment_pages_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "task_marker",
                    self.digests
                        .task_marker_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "replication_marker",
                    self.digests
                        .replication_marker_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "assessment_marker",
                    self.digests
                        .assessment_marker_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for (field, digest) in [
            ("plugin version digest", &self.digests.plugin_version_digest),
            ("contract digest", &self.digests.contract_digest),
            ("provider digest", &self.digests.provider_digest),
            ("API digest", &self.digests.api_digest),
            ("permission digest", &self.digests.permission_digest),
            ("consent digest", &self.digests.consent_digest),
            ("scope digest", &self.digests.scope_digest),
            ("task request digest", &self.digests.task_request_digest),
            (
                "replication request digest",
                &self.digests.replication_request_digest,
            ),
            (
                "assessment request digest",
                &self.digests.assessment_request_digest,
            ),
        ] {
            digest.validate(field)?;
        }
        for (field, digest) in [
            ("task pages digest", self.digests.task_pages_digest.as_ref()),
            (
                "replication pages digest",
                self.digests.replication_pages_digest.as_ref(),
            ),
            (
                "assessment pages digest",
                self.digests.assessment_pages_digest.as_ref(),
            ),
            (
                "task marker digest",
                self.digests.task_marker_digest.as_ref(),
            ),
            (
                "replication marker digest",
                self.digests.replication_marker_digest.as_ref(),
            ),
            (
                "assessment marker digest",
                self.digests.assessment_marker_digest.as_ref(),
            ),
        ] {
            if let Some(digest) = digest {
                digest.validate(field)?;
            }
        }
        self.digests.evidence_digest.validate("evidence digest")?;
        if self.digests.evidence_digest == self.recomputed_digest()
            && !self.provenance.connected()
            && !self.provenance.native()
            && !self.provenance.first_party()
        {
            if let Some(task) = &self.task {
                if task.metadata_digest != task.recomputed_digest() {
                    return Err(AwsDmsMigrationError::TamperedEvidence);
                }
            }
            if let Some(replication) = &self.replication {
                if replication.metadata_digest != replication.recomputed_digest() {
                    return Err(AwsDmsMigrationError::TamperedEvidence);
                }
            }
            if let Some(assessment) = &self.assessment {
                assessment.validate_against_replication_only()?;
            }
            Ok(())
        } else {
            Err(AwsDmsMigrationError::TamperedEvidence)
        }
    }
}

impl AssessmentResultMetadata {
    fn validate_against_replication_only(&self) -> Result<()> {
        if let Some(digest) = &self.report_digest {
            digest.validate("assessment report digest")?;
        }
        let expected = Digest::from_parts(
            "aws-dms-assessment-result/v1",
            &[
                ("replication", self.replication_digest.as_str().to_owned()),
                ("revision", self.task_revision.get().to_string()),
                ("status", format!("{:?}", self.status)),
                ("assessed_at", self.assessed_at.to_rfc3339()),
                (
                    "report",
                    self.report_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        (expected == self.result_digest)
            .then_some(())
            .ok_or(AwsDmsMigrationError::TamperedEvidence)
    }
}

fn digest_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("bounded DMS projection serializes")
}
