//! Typed, bounded, and redacted AWS Elastic Beanstalk deployment evidence.
//!
//! The public model deliberately has no representation for credentials, raw
//! AWS responses, source bundles, logs, CNAMEs, or environment variables.
//! Provider adapters may inspect those values transiently while parsing a
//! bounded fixture, but only digests and small projections can cross this
//! Layer-1 boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_ENVIRONMENTS: usize = 64;
pub const MAX_RESOURCES: usize = 256;
pub const MAX_EVENTS: usize = 256;
pub const MAX_PAGES: u16 = 4;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 12;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} exceeds its bound")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} is not a valid bounded page token")]
    InvalidPageToken { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is not permitted by the read-only fence")]
    Unsupported { field: &'static str },
    #[error("registration or secret reference is revoked")]
    Revoked,
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_payload(value: &str, field: &'static str, maximum: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_digest(digest: &Digest, field: &'static str) -> Result<(), ModelError> {
    if digest == &Digest::zero() {
        Err(ModelError::Invalid { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(EnvironmentId, "environment id");
bounded_identifier!(EnvironmentName, "environment name");
bounded_identifier!(ApplicationName, "application name");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(RevisionId, "revision id");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            return Err(ModelError::MustBePositive { field: "revision" });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

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

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut material = Vec::new();
        material.extend_from_slice(tag.as_bytes());
        for part in parts {
            material.push(0);
            material.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&material)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsElasticBeanstalkReadOperation {
    DescribeEnvironments,
    DescribeEnvironmentResources,
    DescribeEvents,
}

impl AwsElasticBeanstalkReadOperation {
    pub const ALL: [Self; 3] = [
        Self::DescribeEnvironments,
        Self::DescribeEnvironmentResources,
        Self::DescribeEvents,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeEnvironments => "DescribeEnvironments",
            Self::DescribeEnvironmentResources => "DescribeEnvironmentResources",
            Self::DescribeEvents => "DescribeEvents",
        }
    }
}

pub type ReadOperation = AwsElasticBeanstalkReadOperation;
pub type PermissionAction = AwsElasticBeanstalkReadOperation;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentVersionBinding {
    pub revision: Revision,
    pub version_digest: Digest,
}

impl DeploymentVersionBinding {
    pub fn new(revision: Revision, version_digest: Digest) -> Result<Self, ModelError> {
        validate_digest(&version_digest, "deployment version digest")?;
        Ok(Self {
            revision,
            version_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PermissionDigestMaterial<'a> {
    id: &'a PermissionId,
    revision: Revision,
    allowed_actions: &'a BTreeSet<AwsElasticBeanstalkReadOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<AwsElasticBeanstalkReadOperation>,
    pub permission_digest: Digest,
}

impl PermissionFence {
    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = AwsElasticBeanstalkReadOperation>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "Elastic Beanstalk permission allowlist",
            });
        }
        let material = PermissionDigestMaterial {
            id: &id,
            revision,
            allowed_actions: &allowed_actions,
        };
        let permission_digest = digest_serializable(&material)?;
        Ok(Self {
            id,
            revision,
            allowed_actions,
            permission_digest,
        })
    }

    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(id, revision, AwsElasticBeanstalkReadOperation::ALL)
    }

    pub fn permits(&self, action: AwsElasticBeanstalkReadOperation) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.id.clone(),
            self.revision,
            self.allowed_actions.iter().copied(),
        )?;
        if rebuilt.permission_digest != self.permission_digest {
            return Err(ModelError::InvalidDigest {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeDigestMaterial<'a> {
    deployment: &'a DeploymentBinding,
    mission: &'a MissionBinding,
    project: &'a ProjectBinding,
    work_product: &'a WorkProductBinding,
    account_id: &'a AccountId,
    region: &'a AwsRegion,
    application_name: &'a ApplicationName,
    environment_allowlist: &'a [EnvironmentName],
    version: &'a DeploymentVersionBinding,
    permission_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsElasticBeanstalkDeploymentScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub application_name: ApplicationName,
    pub environment_allowlist: Vec<EnvironmentName>,
    pub version: DeploymentVersionBinding,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsElasticBeanstalkDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AccountId,
        region: AwsRegion,
        application_name: ApplicationName,
        mut environment_allowlist: Vec<EnvironmentName>,
        version: DeploymentVersionBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        if environment_allowlist.is_empty() {
            return Err(ModelError::Empty {
                field: "environment allowlist",
            });
        }
        if environment_allowlist.len() > MAX_ENVIRONMENTS {
            return Err(ModelError::TooMany {
                field: "environment allowlist",
            });
        }
        environment_allowlist.sort();
        if environment_allowlist
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ModelError::Duplicate {
                field: "environment allowlist",
            });
        }
        validate_digest(&permission_digest, "permission digest")?;
        let material = ScopeDigestMaterial {
            deployment: &deployment,
            mission: &mission,
            project: &project,
            work_product: &work_product,
            account_id: &account_id,
            region: &region,
            application_name: &application_name,
            environment_allowlist: &environment_allowlist,
            version: &version,
            permission_digest: &permission_digest,
        };
        let scope_digest = digest_serializable(&material)?;
        Ok(Self {
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            application_name,
            environment_allowlist,
            version,
            permission_digest,
            scope_digest,
        })
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version.version_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn allows_environment(&self, environment: &EnvironmentName) -> bool {
        self.environment_allowlist.contains(environment)
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.deployment.clone(),
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
            self.account_id.clone(),
            self.region.clone(),
            self.application_name.clone(),
            self.environment_allowlist.clone(),
            self.version.clone(),
            self.permission_digest.clone(),
        )?;
        if rebuilt.scope_digest != self.scope_digest {
            return Err(ModelError::InvalidDigest {
                field: "scope digest",
            });
        }
        Ok(())
    }
}

/// Opaque reference to a host-owned SigV4 secret.
///
/// This type intentionally does not implement `Serialize` or `Deserialize`.
/// It stores only an opaque host reference long enough to derive a digest; it
/// never stores an access key, secret key, session token, or signer.
#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    region: AwsRegion,
    scope_digest: Digest,
    revision: RevisionId,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_id", &"<opaque>")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        region: AwsRegion,
        scope_digest: Digest,
        revision: RevisionId,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "SigV4 secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_digest(&scope_digest, "secret reference scope digest")?;
        Ok(Self {
            reference_id,
            region,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &AwsElasticBeanstalkDeploymentScope,
        revision: RevisionId,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope.region.clone(),
            scope.scope_digest.clone(),
            revision,
        )
    }

    pub fn signing_service(&self) -> &'static str {
        "elasticbeanstalk"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-elastic-beanstalk-sigv4-reference/v1",
            &[
                self.reference_id.clone(),
                self.region.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.as_str().to_owned(),
            ],
        )
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::Revoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.reference_id.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaquePageToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidPageToken {
                field: "next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-elastic-beanstalk-next-token/v1",
                &[value.to_owned()],
            ),
            binding_digest: None,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnvironmentStatus {
    Launching,
    Updating,
    Ready,
    Terminating,
    Terminated,
    Unknown,
}

impl EnvironmentStatus {
    pub fn parse(value: &str) -> Self {
        match value {
            "Launching" => Self::Launching,
            "Updating" => Self::Updating,
            "Ready" => Self::Ready,
            "Terminating" => Self::Terminating,
            "Terminated" => Self::Terminated,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthStatus {
    Green,
    Yellow,
    Red,
    Grey,
    Unknown,
}

impl HealthStatus {
    pub fn parse(value: &str) -> Self {
        match value {
            "Green" => Self::Green,
            "Yellow" => Self::Yellow,
            "Red" => Self::Red,
            "Grey" => Self::Grey,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceKind {
    Instance,
    AutoScalingGroup,
    LaunchConfiguration,
    LoadBalancer,
    Queue,
    Trigger,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Unknown,
}

impl EventSeverity {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "info" => Self::Info,
            "warning" | "warn" => Self::Warning,
            "error" => Self::Error,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    Deployment,
    Health,
    Configuration,
    Scaling,
    Platform,
    Other,
}

impl EventKind {
    pub fn parse(value: &str) -> Self {
        let value = value.to_ascii_lowercase();
        if value.contains("deploy") {
            Self::Deployment
        } else if value.contains("health") {
            Self::Health
        } else if value.contains("config") {
            Self::Configuration
        } else if value.contains("scal") {
            Self::Scaling
        } else if value.contains("platform") {
            Self::Platform
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentRevisionProjection {
    pub environment_id: EnvironmentId,
    pub environment_name: EnvironmentName,
    pub revision: Revision,
    pub status: EnvironmentStatus,
    pub health: HealthStatus,
    pub version_digest: Digest,
    pub updated_at: DateTime<Utc>,
    pub projection_digest: Digest,
}

impl EnvironmentRevisionProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        environment_id: EnvironmentId,
        environment_name: EnvironmentName,
        revision: Revision,
        status: EnvironmentStatus,
        health: HealthStatus,
        version_digest: Digest,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        validate_digest(&version_digest, "environment version digest")?;
        let projection_digest = digest_serializable(&(
            &environment_id,
            &environment_name,
            revision,
            status,
            health,
            &version_digest,
            updated_at,
        ))?;
        Ok(Self {
            environment_id,
            environment_name,
            revision,
            status,
            health,
            version_digest,
            updated_at,
            projection_digest,
        })
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.environment_id.clone(),
            self.environment_name.clone(),
            self.revision,
            self.status,
            self.health,
            self.version_digest.clone(),
            self.updated_at,
        )?;
        if rebuilt.projection_digest != self.projection_digest {
            return Err(ModelError::InvalidDigest {
                field: "environment revision projection digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceProjection {
    pub environment_id: EnvironmentId,
    pub resource_kind: ResourceKind,
    pub resource_count: u32,
    pub resource_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub projection_digest: Digest,
}

impl ResourceProjection {
    pub fn new(
        environment_id: EnvironmentId,
        resource_kind: ResourceKind,
        resource_count: u32,
        resource_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if resource_count as usize > MAX_RESOURCES {
            return Err(ModelError::TooMany {
                field: "resource projection",
            });
        }
        validate_digest(&resource_digest, "resource projection digest")?;
        let projection_digest = digest_serializable(&(
            &environment_id,
            resource_kind,
            resource_count,
            &resource_digest,
            observed_at,
        ))?;
        Ok(Self {
            environment_id,
            resource_kind,
            resource_count,
            resource_digest,
            observed_at,
            projection_digest,
        })
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.environment_id.clone(),
            self.resource_kind,
            self.resource_count,
            self.resource_digest.clone(),
            self.observed_at,
        )?;
        if rebuilt.projection_digest != self.projection_digest {
            return Err(ModelError::InvalidDigest {
                field: "resource projection digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventProjection {
    pub environment_id: EnvironmentId,
    pub event_id_digest: Digest,
    pub revision: Revision,
    pub occurred_at: DateTime<Utc>,
    pub severity: EventSeverity,
    pub event_kind: EventKind,
    pub message_digest: Digest,
    pub projection_digest: Digest,
}

impl EventProjection {
    pub fn new(
        environment_id: EnvironmentId,
        event_id: impl AsRef<str>,
        revision: Revision,
        occurred_at: DateTime<Utc>,
        severity: EventSeverity,
        event_kind: EventKind,
        message: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        validate_text(event_id.as_ref(), "event id", MAX_IDENTIFIER_BYTES)?;
        validate_payload(message.as_ref(), "event message", MAX_RESPONSE_BYTES)?;
        let event_id_digest = Digest::from_parts(
            "hartevo-aws-elastic-beanstalk-event-id/v1",
            &[event_id.as_ref().to_owned()],
        );
        let message_digest = Digest::from_parts(
            "hartevo-aws-elastic-beanstalk-event-message/v1",
            &[message.as_ref().to_owned()],
        );
        let projection_digest = digest_serializable(&(
            &environment_id,
            &event_id_digest,
            revision,
            occurred_at,
            severity,
            event_kind,
            &message_digest,
        ))?;
        Ok(Self {
            environment_id,
            event_id_digest,
            revision,
            occurred_at,
            severity,
            event_kind,
            message_digest,
            projection_digest,
        })
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.event_id_digest == Digest::zero() || self.message_digest == Digest::zero() {
            return Err(ModelError::InvalidDigest {
                field: "event projection digest",
            });
        }
        let rebuilt = digest_serializable(&(
            &self.environment_id,
            &self.event_id_digest,
            self.revision,
            self.occurred_at,
            self.severity,
            self.event_kind,
            &self.message_digest,
        ))?;
        if rebuilt != self.projection_digest {
            return Err(ModelError::InvalidDigest {
                field: "event projection digest",
            });
        }
        Ok(())
    }
}

pub type RedactedEnvironmentRevision = EnvironmentRevisionProjection;
pub type RedactedResourceProjection = ResourceProjection;
pub type RedactedEventProjection = EventProjection;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub max_items: usize,
    pub page_size: u16,
    pub max_response_bytes: usize,
}

impl ReadBounds {
    pub fn new(
        max_pages: u16,
        max_items: usize,
        page_size: u16,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid { field: "max pages" });
        }
        if max_items == 0 || max_items > MAX_ENVIRONMENTS.max(MAX_RESOURCES).max(MAX_EVENTS) {
            return Err(ModelError::Invalid { field: "max items" });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "max response bytes",
            });
        }
        Ok(Self {
            max_pages,
            max_items,
            page_size,
            max_response_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.max_pages,
            self.max_items,
            self.page_size,
            self.max_response_bytes,
        )
        .map(|_| ())
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_items: MAX_EVENTS,
            page_size: MAX_PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub prior_registration_digest: Digest,
    pub revocation_revision: Revision,
    pub reason_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub mission: MissionBinding,
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub contract_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub revocation: Option<RegistrationRevocation>,
    pub registration_digest: Digest,
}

impl Registration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mission: MissionBinding,
        scope_digest: Digest,
        version_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
        secret_reference_digest: Digest,
        contract_digest: Digest,
        registration_revision: Revision,
    ) -> Result<Self, ModelError> {
        for (digest, field) in [
            (&scope_digest, "registration scope digest"),
            (&version_digest, "registration version digest"),
            (&provider_digest, "registration provider digest"),
            (&permission_digest, "registration permission digest"),
            (
                &secret_reference_digest,
                "registration secret reference digest",
            ),
            (&contract_digest, "registration contract digest"),
        ] {
            validate_digest(digest, field)?;
        }
        let mut registration = Self {
            mission,
            scope_digest,
            version_digest,
            provider_digest,
            permission_digest,
            secret_reference_digest,
            contract_digest,
            registration_revision,
            state: RegistrationState::Active,
            revocation: None,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.compute_digest()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.mission,
            &self.scope_digest,
            &self.version_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
            &self.contract_digest,
            self.registration_revision,
            self.state,
            &self.revocation,
        ))
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.compute_digest()? != self.registration_digest {
            return Err(ModelError::InvalidDigest {
                field: "registration digest",
            });
        }
        if matches!(self.state, RegistrationState::Active) && self.revocation.is_some()
            || matches!(self.state, RegistrationState::Revoked) && self.revocation.is_none()
        {
            return Err(ModelError::Invalid {
                field: "registration state",
            });
        }
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        self.verify()?;
        if matches!(self.state, RegistrationState::Active) {
            Ok(())
        } else {
            Err(ModelError::Revoked)
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.revoke_with_reason(Digest::from_text("operator-revocation"))
    }

    pub fn revoke_with_reason(
        &mut self,
        reason_digest: Digest,
    ) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        validate_digest(&reason_digest, "registration revocation reason digest")?;
        let revocation = RegistrationRevocation {
            prior_registration_digest: self.registration_digest.clone(),
            revocation_revision: Revision::new(self.registration_revision.get() + 1)?,
            reason_digest,
        };
        self.registration_revision = revocation.revocation_revision;
        self.state = RegistrationState::Revoked;
        self.revocation = Some(revocation.clone());
        self.registration_digest = self.compute_digest()?;
        Ok(revocation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: &str) -> Digest {
        Digest::from_text(value)
    }

    #[test]
    fn opaque_secret_reference_redacts_debug_and_has_no_credential_material() {
        let reference = SigV4SecretReference::new(
            "host-keychain-reference",
            AwsRegion::new("us-east-1").expect("region"),
            digest("scope"),
            RevisionId::new("secret-r1").expect("revision"),
        )
        .expect("reference");
        let debug = format!("{reference:?}");
        assert!(!debug.contains("host-keychain-reference"));
        assert!(debug.contains("<opaque>"));
        assert!(reference.is_opaque());
        assert_eq!(reference.signing_service(), "elasticbeanstalk");
    }

    #[test]
    fn scope_and_permission_digests_detect_tampering() {
        let permission = PermissionFence::readonly(
            PermissionId::new("perm").expect("id"),
            Revision::new(1).expect("rev"),
        )
        .expect("permission");
        permission.verify().expect("permission verifies");
        let version =
            DeploymentVersionBinding::new(Revision::new(1).expect("rev"), digest("version"))
                .expect("version");
        let scope = AwsElasticBeanstalkDeploymentScope::new(
            DeploymentBinding::new(
                DeploymentId::new("deployment").expect("id"),
                Revision::new(1).expect("rev"),
            ),
            MissionBinding::new(
                MissionId::new("mission").expect("id"),
                Revision::new(1).expect("rev"),
            ),
            ProjectBinding::new(
                ProjectId::new("project").expect("id"),
                Revision::new(1).expect("rev"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work").expect("id"),
                Revision::new(1).expect("rev"),
            ),
            AccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            ApplicationName::new("app").expect("application"),
            vec![EnvironmentName::new("prod").expect("environment")],
            version,
            permission.permission_digest.clone(),
        )
        .expect("scope");
        scope.verify().expect("scope verifies");
        assert_ne!(scope.digest(), &Digest::zero());
    }

    #[test]
    fn event_projection_does_not_retain_raw_message() {
        let projection = EventProjection::new(
            EnvironmentId::new("e-1").expect("environment"),
            "event-1",
            Revision::new(1).expect("revision"),
            DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            EventSeverity::Error,
            EventKind::Deployment,
            "AWS_SECRET_ACCESS_KEY=do-not-retain",
        )
        .expect("event");
        let json = serde_json::to_string(&projection).expect("projection serializes");
        assert!(!json.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!json.contains("do-not-retain"));
        projection.verify().expect("projection verifies");
    }
}
