//! Typed, bounded, and redacted models for the AWS ELB target-health seam.
//!
//! The model deliberately keeps provider identifiers and target identifiers as
//! host-owned values that serialize only as scoped SHA-256 digests.  Pagination
//! markers and SigV4 references are opaque handles; their source values never
//! appear in `Debug`, `Serialize`, evidence, requests, or receipts.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_MARKER_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_LOAD_BALANCERS: usize = 8;
pub const MAX_TARGET_GROUPS: usize = 8;
pub const MAX_TARGETS: usize = 256;
pub const MAX_AVAILABILITY_ZONES: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 12;
pub const MAX_RETRIES: u8 = 2;
pub const MAX_OBSERVATION_AGE_SECONDS: i64 = 300;
pub const MAX_HEALTH_DETAIL_BYTES: usize = 1_024;

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
    #[error("AWS ELB scope is invalid")]
    InvalidScope,
    #[error("scope mismatch: {field}")]
    ScopeMismatch { field: &'static str },
    #[error("target-group mismatch: {field}")]
    TargetGroupMismatch { field: &'static str },
    #[error("opaque marker is invalid: {field}")]
    InvalidMarker { field: &'static str },
    #[error("response exceeded the bounded byte budget")]
    ResponseTooLarge,
    #[error("health observation is stale")]
    StaleObservation,
}

pub type ModelResult<T> = std::result::Result<T, ModelError>;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    /// Hashes a domain and length-delimited fields to avoid ambiguous joins.
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut canonical = Vec::with_capacity(domain.len() + fields.len() * 48);
        append_bytes(&mut canonical, domain.as_bytes());
        for (name, value) in fields {
            append_bytes(&mut canonical, name.as_bytes());
            append_bytes(&mut canonical, value.as_bytes());
        }
        Self::from_bytes(&canonical)
    }

    pub fn parse(value: impl Into<String>) -> ModelResult<Self> {
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

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
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

pub fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    match serde_json::to_vec(value) {
        Ok(bytes) => Digest::from_bytes(&bytes),
        Err(error) => Digest::from_text(format!("serialization-error:{error}")),
    }
}

fn append_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}

fn valid_text(value: &str, field: &'static str, max_bytes: usize) -> ModelResult<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ModelError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn valid_identifier(value: &str, field: &'static str, max_bytes: usize) -> ModelResult<()> {
    valid_text(value, field, max_bytes)?;
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidIdentifier { field })
    }
}

macro_rules! opaque_identifier {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ModelResult<Self> {
                let value = value.into();
                valid_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .finish()
            }
        }
    };
}

opaque_identifier!(ProjectId, "project id", "aws-elb-project-id/v1");
opaque_identifier!(MissionId, "mission id", "aws-elb-mission-id/v1");
opaque_identifier!(
    WorkProductId,
    "work product id",
    "aws-elb-work-product-id/v1"
);
opaque_identifier!(DeploymentId, "deployment id", "aws-elb-deployment-id/v1");
opaque_identifier!(PermissionId, "permission id", "aws-elb-permission-id/v1");
opaque_identifier!(AwsAccountId, "AWS account id", "aws-elb-account-id/v1");
opaque_identifier!(AwsRegion, "AWS region", "aws-elb-region/v1");
opaque_identifier!(
    LoadBalancerArn,
    "load balancer ARN",
    "aws-elb-load-balancer-arn/v1"
);
opaque_identifier!(
    TargetGroupArn,
    "target group ARN",
    "aws-elb-target-group-arn/v1"
);
opaque_identifier!(
    LoadBalancerName,
    "load balancer name",
    "aws-elb-load-balancer-name/v1"
);
opaque_identifier!(
    TargetGroupName,
    "target group name",
    "aws-elb-target-group-name/v1"
);
opaque_identifier!(
    AvailabilityZone,
    "availability zone",
    "aws-elb-availability-zone/v1"
);

impl AwsAccountId {
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

impl LoadBalancerArn {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !value.starts_with("arn:")
            || !value.contains(":elasticloadbalancing:")
            || !value.contains(":loadbalancer/")
        {
            return Err(ModelError::InvalidIdentifier {
                field: "load balancer ARN",
            });
        }
        Self::new(value)
    }
}

impl TargetGroupArn {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if !value.starts_with("arn:")
            || !value.contains(":elasticloadbalancing:")
            || !value.contains(":targetgroup/")
        {
            return Err(ModelError::InvalidIdentifier {
                field: "target group ARN",
            });
        }
        Self::new(value)
    }
}

impl LoadBalancerName {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() > 32
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ModelError::InvalidIdentifier {
                field: "load balancer name",
            });
        }
        Self::new(value)
    }
}

impl TargetGroupName {
    pub fn aws(value: impl Into<String>) -> ModelResult<Self> {
        let value = value.into();
        if value.len() > 32
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ModelError::InvalidIdentifier {
                field: "target group name",
            });
        }
        Self::new(value)
    }
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
            "aws-elb-deployment-binding/v1",
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
            "aws-elb-mission-binding/v1",
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
            "aws-elb-project-binding/v1",
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
            "aws-elb-work-product-binding/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PermissionAction {
    #[serde(rename = "elasticloadbalancing:DescribeLoadBalancers")]
    DescribeLoadBalancers,
    #[serde(rename = "elasticloadbalancing:DescribeTargetGroups")]
    DescribeTargetGroups,
    #[serde(rename = "elasticloadbalancing:DescribeTargetHealth")]
    DescribeTargetHealth,
    #[serde(rename = "mission.scope")]
    MissionScope,
}

impl PermissionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeLoadBalancers => "elasticloadbalancing:DescribeLoadBalancers",
            Self::DescribeTargetGroups => "elasticloadbalancing:DescribeTargetGroups",
            Self::DescribeTargetHealth => "elasticloadbalancing:DescribeTargetHealth",
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
                PermissionAction::DescribeLoadBalancers,
                PermissionAction::DescribeTargetGroups,
                PermissionAction::DescribeTargetHealth,
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
            "aws-elb-permission-fence/v1",
            &[
                ("id", self.id.digest().to_string()),
                ("revision", self.revision.get().to_string()),
                ("actions", actions),
            ],
        )
    }

    pub fn is_layer_one_complete(&self) -> bool {
        [
            PermissionAction::DescribeLoadBalancers,
            PermissionAction::DescribeTargetGroups,
            PermissionAction::DescribeTargetHealth,
            PermissionAction::MissionScope,
        ]
        .into_iter()
        .all(|action| self.allows(action))
    }
}

pub type PermissionScope = PermissionFence;

#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference: Zeroizing<String>,
    service: String,
    region: AwsRegion,
    scope_binding_digest: Digest,
    revision: Revision,
}

impl SigV4SecretReference {
    pub fn new(
        reference: impl Into<String>,
        service: impl Into<String>,
        region: AwsRegion,
        scope_binding_digest: Digest,
        revision: Revision,
    ) -> ModelResult<Self> {
        let reference = reference.into();
        valid_text(
            &reference,
            "opaque SigV4 secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let service = service.into();
        valid_identifier(&service, "SigV4 service", 64)?;
        Ok(Self {
            reference: Zeroizing::new(reference),
            service,
            region,
            scope_binding_digest,
            revision,
        })
    }

    pub fn for_elb(reference: impl Into<String>, region: &AwsRegion) -> ModelResult<Self> {
        Self::new(
            reference,
            "elasticloadbalancing",
            region.clone(),
            Digest::zero(),
            Revision::new(1)?,
        )
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn signing_service(&self) -> &str {
        self.service()
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn signing_region(&self) -> &AwsRegion {
        self.region()
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn scope_binding_digest(&self) -> &Digest {
        &self.scope_binding_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-sigv4-secret-reference/v1",
            &[
                ("reference", self.reference.as_str().to_owned()),
                ("service", self.service.clone()),
                ("region", self.region.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl Serialize for SigV4SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SigV4SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("opaque", &true)
            .field("service", &self.service)
            .field("region_digest", &self.region.digest())
            .field("scope_binding_digest", &self.scope_binding_digest)
            .field("revision", &self.revision)
            .field("reference", &self.digest())
            .finish()
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.service.zeroize();
    }
}

pub type SecretReference = SigV4SecretReference;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LoadBalancerReference {
    pub arn: LoadBalancerArn,
    pub revision: Revision,
}

impl LoadBalancerReference {
    pub const fn new(arn: LoadBalancerArn, revision: Revision) -> Self {
        Self { arn, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-load-balancer-reference/v1",
            &[
                ("arn", self.arn.digest().to_string()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

impl Serialize for LoadBalancerReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("LoadBalancerReference", 2)?;
        value.serialize_field("arnDigest", &self.arn.digest())?;
        value.serialize_field("revision", &self.revision)?;
        value.end()
    }
}

pub type AwsElbLoadBalancer = LoadBalancerReference;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetGroupType {
    Instance,
    Ip,
    Lambda,
    Alb,
    Unknown,
}

impl TargetGroupType {
    pub fn from_aws(value: &str) -> Self {
        match value {
            "instance" => Self::Instance,
            "ip" => Self::Ip,
            "lambda" => Self::Lambda,
            "alb" => Self::Alb,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetGroupReference {
    pub arn: TargetGroupArn,
    pub revision: Revision,
    pub target_group_type: TargetGroupType,
}

impl TargetGroupReference {
    pub const fn new(
        arn: TargetGroupArn,
        revision: Revision,
        target_group_type: TargetGroupType,
    ) -> Self {
        Self {
            arn,
            revision,
            target_group_type,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-target-group-reference/v1",
            &[
                ("arn", self.arn.digest().to_string()),
                ("revision", self.revision.get().to_string()),
                ("type", format!("{:?}", self.target_group_type)),
            ],
        )
    }
}

impl Serialize for TargetGroupReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("TargetGroupReference", 3)?;
        value.serialize_field("arnDigest", &self.arn.digest())?;
        value.serialize_field("revision", &self.revision)?;
        value.serialize_field("targetGroupType", &self.target_group_type)?;
        value.end()
    }
}

pub type AwsElbTargetGroup = TargetGroupReference;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetIdDigest(Digest);

impl TargetIdDigest {
    pub fn from_target_id(value: impl AsRef<str>) -> ModelResult<Self> {
        let value = value.as_ref();
        valid_text(value, "target id", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(Digest::from_parts(
            "aws-elb-target-id/v1",
            &[("target", value.to_owned())],
        )))
    }

    pub fn from_digest(value: Digest) -> ModelResult<Self> {
        if value.is_zero() {
            Err(ModelError::InvalidDigest)
        } else {
            Ok(Self(value))
        }
    }

    pub fn digest(&self) -> Digest {
        self.0.clone()
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for TargetIdDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl fmt::Debug for TargetIdDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TargetIdDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for TargetIdDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerType {
    Application,
    Network,
    Gateway,
    Unknown,
}

impl LoadBalancerType {
    pub fn from_aws(value: &str) -> Self {
        match value {
            "application" => Self::Application,
            "network" => Self::Network,
            "gateway" => Self::Gateway,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerScheme {
    InternetFacing,
    Internal,
    Unknown,
}

impl LoadBalancerScheme {
    pub fn from_aws(value: &str) -> Self {
        match value {
            "internet-facing" => Self::InternetFacing,
            "internal" => Self::Internal,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerState {
    Provisioning,
    Active,
    ActiveImpaired,
    Failed,
    Unknown,
}

impl LoadBalancerState {
    pub fn from_aws(value: &str) -> Self {
        match value {
            "provisioning" => Self::Provisioning,
            "active" => Self::Active,
            "active_impaired" => Self::ActiveImpaired,
            "failed" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetGroupState {
    Active,
    Draining,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ElbProtocol {
    Http,
    Https,
    Tcp,
    Tls,
    Udp,
    TcpUdp,
    Geneve,
    Unknown,
}

impl ElbProtocol {
    pub fn from_aws(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "HTTP" => Self::Http,
            "HTTPS" => Self::Https,
            "TCP" => Self::Tcp,
            "TLS" => Self::Tls,
            "UDP" => Self::Udp,
            "TCP_UDP" => Self::TcpUdp,
            "GENEVE" => Self::Geneve,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckSummary {
    pub protocol: ElbProtocol,
    pub port: Option<u16>,
    pub path_digest: Option<Digest>,
    pub interval_seconds: u16,
    pub timeout_seconds: u16,
    pub healthy_threshold: u16,
    pub unhealthy_threshold: u16,
    pub matcher_digest: Option<Digest>,
    pub summary_digest: Digest,
}

impl HealthCheckSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: ElbProtocol,
        port: Option<u16>,
        path: Option<impl AsRef<str>>,
        interval_seconds: u16,
        timeout_seconds: u16,
        healthy_threshold: u16,
        unhealthy_threshold: u16,
        matcher: Option<impl AsRef<str>>,
    ) -> ModelResult<Self> {
        if interval_seconds == 0
            || timeout_seconds == 0
            || healthy_threshold == 0
            || unhealthy_threshold == 0
        {
            return Err(ModelError::Invalid {
                field: "health check bounds",
            });
        }
        let path_digest = path
            .map(|value| {
                valid_text(value.as_ref(), "health check path", MAX_HEALTH_DETAIL_BYTES)
                    .map(|()| Digest::from_text(value.as_ref()))
            })
            .transpose()?;
        let matcher_digest = matcher
            .map(|value| {
                valid_text(
                    value.as_ref(),
                    "health check matcher",
                    MAX_HEALTH_DETAIL_BYTES,
                )
                .map(|()| Digest::from_text(value.as_ref()))
            })
            .transpose()?;
        let mut value = Self {
            protocol,
            port,
            path_digest,
            interval_seconds,
            timeout_seconds,
            healthy_threshold,
            unhealthy_threshold,
            matcher_digest,
            summary_digest: Digest::zero(),
        };
        value.summary_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.protocol,
            self.port,
            &self.path_digest,
            self.interval_seconds,
            self.timeout_seconds,
            self.healthy_threshold,
            self.unhealthy_threshold,
            &self.matcher_digest,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancerSummary {
    pub arn_digest: Digest,
    pub name_digest: Digest,
    pub availability_zone_digests: Vec<Digest>,
    pub load_balancer_type: LoadBalancerType,
    pub scheme: LoadBalancerScheme,
    pub state: LoadBalancerState,
    pub revision: Revision,
    pub summary_digest: Digest,
}

impl LoadBalancerSummary {
    pub fn new(
        arn: &LoadBalancerArn,
        name: &LoadBalancerName,
        load_balancer_type: LoadBalancerType,
        scheme: LoadBalancerScheme,
        state: LoadBalancerState,
        revision: Revision,
    ) -> Self {
        let mut value = Self {
            arn_digest: arn.digest(),
            name_digest: name.digest(),
            availability_zone_digests: Vec::new(),
            load_balancer_type,
            scheme,
            state,
            revision,
            summary_digest: Digest::zero(),
        };
        value.summary_digest = value.recomputed_digest();
        value
    }

    pub fn with_availability_zones(
        mut self,
        availability_zones: impl IntoIterator<Item = AvailabilityZone>,
    ) -> Self {
        self.availability_zone_digests = availability_zones
            .into_iter()
            .map(|zone| zone.digest())
            .collect();
        self.availability_zone_digests.sort();
        self.summary_digest = self.recomputed_digest();
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.arn_digest,
            &self.name_digest,
            &self.availability_zone_digests,
            self.load_balancer_type,
            self.scheme,
            self.state,
            self.revision,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetGroupSummary {
    pub arn_digest: Digest,
    pub name_digest: Digest,
    pub target_group_type: TargetGroupType,
    pub protocol: ElbProtocol,
    pub port: Option<u16>,
    pub state: TargetGroupState,
    pub load_balancer_arn_digests: Vec<Digest>,
    pub health_check: HealthCheckSummary,
    pub revision: Revision,
    pub summary_digest: Digest,
}

impl TargetGroupSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        arn: &TargetGroupArn,
        name: &TargetGroupName,
        target_group_type: TargetGroupType,
        protocol: ElbProtocol,
        port: Option<u16>,
        state: TargetGroupState,
        load_balancer_arns: impl IntoIterator<Item = LoadBalancerArn>,
        health_check: HealthCheckSummary,
        revision: Revision,
    ) -> Self {
        let mut load_balancer_arn_digests = load_balancer_arns
            .into_iter()
            .map(|arn| arn.digest())
            .collect::<Vec<_>>();
        load_balancer_arn_digests.sort();
        let mut value = Self {
            arn_digest: arn.digest(),
            name_digest: name.digest(),
            target_group_type,
            protocol,
            port,
            state,
            load_balancer_arn_digests,
            health_check,
            revision,
            summary_digest: Digest::zero(),
        };
        value.summary_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.arn_digest,
            &self.name_digest,
            self.target_group_type,
            self.protocol,
            self.port,
            self.state,
            &self.load_balancer_arn_digests,
            &self.health_check.summary_digest,
            self.revision,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHealthState {
    Healthy,
    Unhealthy,
    Initial,
    Draining,
    Unavailable,
    Unused,
    Unknown,
}

impl TargetHealthState {
    pub fn from_aws(value: &str) -> Self {
        match value {
            "healthy" => Self::Healthy,
            "unhealthy" => Self::Unhealthy,
            "initial" => Self::Initial,
            "draining" => Self::Draining,
            "unavailable" => Self::Unavailable,
            "unused" => Self::Unused,
            _ => Self::Unknown,
        }
    }

    pub const fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::Initial | Self::Draining | Self::Unavailable | Self::Unused | Self::Unknown
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHealthReasonClass {
    Elb,
    Target,
    Registration,
    Administrative,
    Internal,
    None,
    Unknown,
}

impl TargetHealthReasonClass {
    pub fn from_aws(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::None,
            Some(value) if value.starts_with("Elb.") => Self::Elb,
            Some(value) if value.starts_with("Target.") => Self::Target,
            Some(value) if value.starts_with("Registration.") => Self::Registration,
            Some(value) if value.starts_with("Administrative.") => Self::Administrative,
            Some(value) if value.starts_with("Internal.") => Self::Internal,
            Some(_) => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetHealthObservation {
    pub target_id_digest: TargetIdDigest,
    pub availability_zone_digest: Option<Digest>,
    pub target_port: Option<u16>,
    pub state: TargetHealthState,
    pub reason_class: TargetHealthReasonClass,
    pub health_detail_digest: Option<Digest>,
    pub observed_at: DateTime<Utc>,
    pub observation_digest: Digest,
}

impl TargetHealthObservation {
    pub fn new(
        target_id: impl AsRef<str>,
        target_port: Option<u16>,
        state: TargetHealthState,
        reason_class: TargetHealthReasonClass,
        detail: Option<impl AsRef<str>>,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        let target_id_digest = TargetIdDigest::from_target_id(target_id)?;
        let health_detail_digest = detail
            .map(|value| {
                valid_text(
                    value.as_ref(),
                    "target health detail",
                    MAX_HEALTH_DETAIL_BYTES,
                )
                .map(|()| Digest::from_text(value.as_ref()))
            })
            .transpose()?;
        let mut value = Self {
            target_id_digest,
            availability_zone_digest: None,
            target_port,
            state,
            reason_class,
            health_detail_digest,
            observed_at,
            observation_digest: Digest::zero(),
        };
        value.observation_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn with_availability_zone(mut self, availability_zone: &AvailabilityZone) -> Self {
        self.availability_zone_digest = Some(availability_zone.digest());
        self.observation_digest = self.recomputed_digest();
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.target_id_digest,
            &self.availability_zone_digest,
            self.target_port,
            self.state,
            self.reason_class,
            &self.health_detail_digest,
            self.observed_at,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHealthCollectionState {
    Fresh,
    Stale,
    Initial,
    Unavailable,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    DescribeLoadBalancers,
    DescribeTargetGroups,
    DescribeTargetHealth,
}

impl ReadOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeLoadBalancers => "DescribeLoadBalancers",
            Self::DescribeTargetGroups => "DescribeTargetGroups",
            Self::DescribeTargetHealth => "DescribeTargetHealth",
        }
    }

    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::DescribeLoadBalancers => PermissionAction::DescribeLoadBalancers,
            Self::DescribeTargetGroups => PermissionAction::DescribeTargetGroups,
            Self::DescribeTargetHealth => PermissionAction::DescribeTargetHealth,
        }
    }

    pub const fn is_paginated(self) -> bool {
        !matches!(self, Self::DescribeTargetHealth)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueMarker {
    marker_digest: Digest,
    binding_digest: Option<Digest>,
    page_number: u16,
}

impl OpaqueMarker {
    pub fn new(value: impl AsRef<str>) -> ModelResult<Self> {
        valid_text(value.as_ref(), "ELB marker", MAX_MARKER_BYTES)?;
        Ok(Self {
            marker_digest: Digest::from_parts(
                "aws-elb-marker/v1",
                &[("marker", value.as_ref().to_owned())],
            ),
            binding_digest: None,
            page_number: 0,
        })
    }

    pub fn from_digest(value: Digest) -> ModelResult<Self> {
        if value.is_zero() {
            Err(ModelError::InvalidMarker {
                field: "marker digest",
            })
        } else {
            Ok(Self {
                marker_digest: value,
                binding_digest: None,
                page_number: 0,
            })
        }
    }

    pub fn bind(&self, request_digest: &Digest, page_number: u16) -> ModelResult<Self> {
        if page_number == 0 {
            return Err(ModelError::InvalidMarker {
                field: "marker page number",
            });
        }
        let mut value = self.clone();
        value.binding_digest = Some(request_digest.clone());
        value.page_number = page_number;
        Ok(value)
    }

    pub fn digest(&self) -> Digest {
        self.marker_digest.clone()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

impl Serialize for OpaqueMarker {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueMarker", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

impl fmt::Debug for OpaqueMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueMarker")
            .field("digest", &self.marker_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

pub type OpaquePageToken = OpaqueMarker;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_targets: usize,
    pub max_response_bytes: usize,
    pub max_requests: u16,
    pub max_observation_age_seconds: i64,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_targets: MAX_TARGETS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_requests: MAX_REQUESTS_PER_READ,
            max_observation_age_seconds: MAX_OBSERVATION_AGE_SECONDS,
        }
    }
}

impl ReadBounds {
    pub fn bounded(max_pages: u16, page_size: u16, max_targets: usize) -> ModelResult<Self> {
        let value = Self {
            max_pages,
            page_size,
            max_targets,
            ..Self::default()
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> ModelResult<()> {
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_targets == 0
            || self.max_targets > MAX_TARGETS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_requests == 0
            || self.max_requests > MAX_REQUESTS_PER_READ
            || self.max_observation_age_seconds <= 0
            || self.max_observation_age_seconds > MAX_OBSERVATION_AGE_SECONDS
        {
            Err(ModelError::Invalid {
                field: "read bounds",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsElbScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub load_balancer: LoadBalancerReference,
    pub target_group: TargetGroupReference,
    pub target_allowlist: Option<BTreeSet<TargetIdDigest>>,
    pub availability_zones: Option<BTreeSet<AvailabilityZone>>,
    pub target_port: Option<u16>,
    pub health_check_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub target_health_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsElbScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AwsAccountId,
        region: AwsRegion,
        load_balancer: LoadBalancerReference,
        target_group: TargetGroupReference,
        target_allowlist: Option<BTreeSet<TargetIdDigest>>,
        permission_digest: Digest,
        secret_reference_digest: Digest,
    ) -> ModelResult<Self> {
        let mut scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            load_balancer,
            target_group,
            target_allowlist,
            availability_zones: None,
            target_port: None,
            health_check_digest: Digest::zero(),
            permission_digest,
            secret_reference_digest,
            target_health_digest: Digest::zero(),
            scope_digest: Digest::zero(),
        };
        scope.validate_fields()?;
        scope.target_health_digest = scope.recomputed_target_health_digest();
        scope.scope_digest = scope.recomputed_digest();
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_health_scope(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AwsAccountId,
        region: AwsRegion,
        load_balancer: LoadBalancerReference,
        target_group: TargetGroupReference,
        target_allowlist: Option<BTreeSet<TargetIdDigest>>,
        availability_zones: Option<BTreeSet<AvailabilityZone>>,
        target_port: Option<u16>,
        health_check: &HealthCheckSummary,
        permission_digest: Digest,
        secret_reference_digest: Digest,
    ) -> ModelResult<Self> {
        let mut scope = Self::new(
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            load_balancer,
            target_group,
            target_allowlist,
            permission_digest,
            secret_reference_digest,
        )?;
        scope.availability_zones = availability_zones;
        scope.target_port = target_port;
        scope.health_check_digest = health_check.summary_digest.clone();
        scope.validate_fields()?;
        scope.target_health_digest = scope.recomputed_target_health_digest();
        scope.scope_digest = scope.recomputed_digest();
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_secret(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AwsAccountId,
        region: AwsRegion,
        load_balancer: LoadBalancerReference,
        target_group: TargetGroupReference,
        target_allowlist: Option<BTreeSet<TargetIdDigest>>,
        permission: &PermissionFence,
        secret_reference: &SigV4SecretReference,
    ) -> ModelResult<Self> {
        Self::new(
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            load_balancer,
            target_group,
            target_allowlist,
            permission.digest(),
            secret_reference.digest(),
        )
    }

    pub fn validate(&self) -> ModelResult<()> {
        self.validate_fields()?;
        if self.target_health_digest != self.recomputed_target_health_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "target health digest",
            });
        }
        if self.scope_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        Ok(())
    }

    fn validate_fields(&self) -> ModelResult<()> {
        if self.permission_digest.is_zero() || self.secret_reference_digest.is_zero() {
            return Err(ModelError::InvalidScope);
        }
        if self.target_group.target_group_type == TargetGroupType::Unknown {
            return Err(ModelError::InvalidScope);
        }
        if let Some(targets) = &self.target_allowlist {
            if targets.is_empty() || targets.len() > MAX_TARGETS {
                return Err(ModelError::TooMany {
                    field: "target allowlist",
                });
            }
        }
        if self.target_port == Some(0) {
            return Err(ModelError::Invalid {
                field: "target port",
            });
        }
        if self
            .availability_zones
            .as_ref()
            .is_some_and(|zones| zones.is_empty() || zones.len() > MAX_AVAILABILITY_ZONES)
        {
            return Err(ModelError::Invalid {
                field: "availability zone scope",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn target_health_digest(&self) -> Digest {
        self.target_health_digest.clone()
    }

    pub fn target_allowlist_digest(&self) -> Digest {
        let values = self.target_allowlist.as_ref().map_or_else(
            || "none".to_owned(),
            |targets| {
                targets
                    .iter()
                    .map(TargetIdDigest::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            },
        );
        Digest::from_parts("aws-elb-target-allowlist/v1", &[("targets", values)])
    }

    pub fn availability_zones_digest(&self) -> Digest {
        let values = self.availability_zones.as_ref().map_or_else(
            || "none".to_owned(),
            |zones| {
                zones
                    .iter()
                    .map(|zone| zone.digest().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            },
        );
        Digest::from_parts("aws-elb-availability-zones/v1", &[("zones", values)])
    }

    pub fn recomputed_target_health_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-target-health-scope/v1",
            &[
                ("target_group", self.target_group.digest().to_string()),
                ("allowlist", self.target_allowlist_digest().to_string()),
                (
                    "availability_zones",
                    self.availability_zones_digest().to_string(),
                ),
                (
                    "target_port",
                    self.target_port
                        .map_or_else(|| "none".to_owned(), |port| port.to_string()),
                ),
                ("health_check", self.health_check_digest.to_string()),
            ],
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-target-health-scope/v1",
            &[
                ("deployment", self.deployment.digest().to_string()),
                ("mission", self.mission.digest().to_string()),
                ("project", self.project.digest().to_string()),
                ("work_product", self.work_product.digest().to_string()),
                ("account", self.account_id.digest().to_string()),
                ("region", self.region.digest().to_string()),
                ("load_balancer", self.load_balancer.digest().to_string()),
                ("target_group", self.target_group.digest().to_string()),
                ("allowlist", self.target_allowlist_digest().to_string()),
                (
                    "availability_zones",
                    self.availability_zones_digest().to_string(),
                ),
                (
                    "target_port",
                    self.target_port
                        .map_or_else(|| "none".to_owned(), |port| port.to_string()),
                ),
                ("health_check", self.health_check_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
                ("secret_reference", self.secret_reference_digest.to_string()),
                ("target_health", self.target_health_digest.to_string()),
            ],
        )
    }

    pub fn account_id(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn load_balancer(&self) -> &LoadBalancerReference {
        &self.load_balancer
    }

    pub fn target_group(&self) -> &TargetGroupReference {
        &self.target_group
    }
}

impl Serialize for AwsElbScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AwsElbScope", 16)?;
        value.serialize_field("deployment", &self.deployment.digest())?;
        value.serialize_field("mission", &self.mission.digest())?;
        value.serialize_field("project", &self.project.digest())?;
        value.serialize_field("workProduct", &self.work_product.digest())?;
        value.serialize_field("accountDigest", &self.account_id.digest())?;
        value.serialize_field("regionDigest", &self.region.digest())?;
        value.serialize_field("loadBalancer", &self.load_balancer)?;
        value.serialize_field("targetGroup", &self.target_group)?;
        value.serialize_field("targetAllowlistDigest", &self.target_allowlist_digest())?;
        value.serialize_field("availabilityZonesDigest", &self.availability_zones_digest())?;
        value.serialize_field("targetPort", &self.target_port)?;
        value.serialize_field("healthCheckDigest", &self.health_check_digest)?;
        value.serialize_field("permissionDigest", &self.permission_digest)?;
        value.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        value.serialize_field("targetHealthDigest", &self.target_health_digest)?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsElbReadRequest {
    pub operation: ReadOperation,
    pub scope_digest: Digest,
    pub load_balancer_digest: Digest,
    pub target_group_digest: Digest,
    pub target_allowlist_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub max_pages: u16,
    pub marker: Option<OpaqueMarker>,
    pub request_digest: Digest,
}

impl AwsElbReadRequest {
    pub fn new(
        scope: &AwsElbScope,
        operation: ReadOperation,
        bounds: ReadBounds,
        marker: Option<OpaqueMarker>,
    ) -> ModelResult<Self> {
        bounds.validate()?;
        let page_number = marker.as_ref().map_or(1, |marker| marker.page_number() + 1);
        if page_number == 0 || page_number > bounds.max_pages.saturating_add(1) {
            return Err(ModelError::InvalidMarker {
                field: "page number",
            });
        }
        let mut value = Self {
            operation,
            scope_digest: scope.digest(),
            load_balancer_digest: scope.load_balancer.digest(),
            target_group_digest: scope.target_group.digest(),
            target_allowlist_digest: scope.target_allowlist_digest(),
            page_number,
            page_size: bounds.page_size,
            max_pages: bounds.max_pages,
            marker,
            request_digest: Digest::zero(),
        };
        value.request_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn for_scope(
        scope: &AwsElbScope,
        operation: ReadOperation,
        page_size: u16,
        max_pages: u16,
        marker: Option<OpaqueMarker>,
    ) -> ModelResult<Self> {
        let bounds = ReadBounds {
            max_pages,
            page_size,
            ..ReadBounds::default()
        };
        Self::new(scope, operation, bounds, marker)
    }

    pub fn describe_load_balancers(
        scope: &AwsElbScope,
        bounds: ReadBounds,
        marker: Option<OpaqueMarker>,
    ) -> ModelResult<Self> {
        Self::new(scope, ReadOperation::DescribeLoadBalancers, bounds, marker)
    }

    pub fn describe_target_groups(
        scope: &AwsElbScope,
        bounds: ReadBounds,
        marker: Option<OpaqueMarker>,
    ) -> ModelResult<Self> {
        Self::new(scope, ReadOperation::DescribeTargetGroups, bounds, marker)
    }

    pub fn describe_target_health(scope: &AwsElbScope, bounds: ReadBounds) -> ModelResult<Self> {
        Self::new(scope, ReadOperation::DescribeTargetHealth, bounds, None)
    }

    pub fn with_marker(&self, marker: Option<OpaqueMarker>) -> ModelResult<Self> {
        let page_number = marker.as_ref().map_or(1, |marker| marker.page_number() + 1);
        let mut value = self.clone();
        value.marker = marker;
        value.page_number = page_number;
        value.request_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-read-request/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("scope", self.scope_digest.to_string()),
                ("load_balancer", self.load_balancer_digest.to_string()),
                ("target_group", self.target_group_digest.to_string()),
                ("allowlist", self.target_allowlist_digest.to_string()),
                ("page", self.page_number.to_string()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                (
                    "marker",
                    self.marker
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), |marker| marker.digest().to_string()),
                ),
            ],
        )
    }
}

impl Serialize for AwsElbReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AwsElbReadRequest", 10)?;
        value.serialize_field("operation", &self.operation)?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.serialize_field("loadBalancerDigest", &self.load_balancer_digest)?;
        value.serialize_field("targetGroupDigest", &self.target_group_digest)?;
        value.serialize_field("targetAllowlistDigest", &self.target_allowlist_digest)?;
        value.serialize_field("pageNumber", &self.page_number)?;
        value.serialize_field("pageSize", &self.page_size)?;
        value.serialize_field("maxPages", &self.max_pages)?;
        value.serialize_field("marker", &self.marker)?;
        value.serialize_field("requestDigest", &self.request_digest)?;
        value.end()
    }
}

pub type DescribeLoadBalancersRequest = AwsElbReadRequest;
pub type DescribeTargetGroupsRequest = AwsElbReadRequest;
pub type DescribeTargetHealthRequest = AwsElbReadRequest;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerFailure,
    Timeout,
    ProviderUnknown,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::ServerFailure => Some(500),
            Self::Timeout | Self::ProviderUnknown => None,
        }
    }

    pub const fn evidence_state(self) -> EvidenceState {
        match self {
            Self::BadRequest => EvidenceState::BadRequest,
            Self::Unauthorized => EvidenceState::Unauthorized,
            Self::Forbidden => EvidenceState::Forbidden,
            Self::NotFound => EvidenceState::NotFound,
            Self::Conflict => EvidenceState::Conflict,
            Self::Throttled => EvidenceState::Throttled,
            Self::ServerFailure => EvidenceState::ServerFailure,
            Self::Timeout => EvidenceState::Timeout,
            Self::ProviderUnknown => EvidenceState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub retry_count: u8,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        Self {
            failure,
            status_code: failure.status_code(),
            retry_count: 0,
            error_digest: Digest::from_parts(
                "aws-elb-transport-error/v1",
                &[("failure", format!("{failure:?}"))],
            ),
        }
    }

    pub fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = Some(status_code);
        self
    }

    pub fn with_retry_count(mut self, retry_count: u8) -> Self {
        self.retry_count = retry_count.min(MAX_RETRIES);
        self
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportError")
            .field("failure", &self.failure)
            .field("status_code", &self.status_code)
            .field("retry_count", &self.retry_count)
            .field("error_digest", &self.error_digest)
            .finish()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AWS ELB transport failure: {:?}", self.failure)
    }
}

impl std::error::Error for TransportError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Healthy,
    Unhealthy,
    Initial,
    Unavailable,
    Stale,
    Partial,
    ScopeDrift,
    TargetGroupDrift,
    AccessLoss,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerFailure,
    Timeout,
    Tampered,
    Replay,
    RegistrationRevoked,
    ProviderUnknown,
}

impl EvidenceState {
    pub const fn is_fail_closed(&self) -> bool {
        !matches!(self, Self::Healthy | Self::Unhealthy)
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Healthy | Self::Unhealthy)
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    ScopeDrift,
    TargetGroupDrift,
    MarkerLoop,
    MarkerReplay,
    PageBudget,
    ResponseTooLarge,
    Stale,
    Initial,
    Unavailable,
    PartialHealth,
    AccessLoss,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerFailure,
    Timeout,
    Tampered,
    Replay,
    RegistrationRevoked,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub header_digest: Digest,
    pub response_bytes: usize,
    pub estimated_cost_units: u16,
    pub provenance: ProviderProvenance,
    pub redacted: bool,
    pub raw_path_retained: bool,
    pub raw_headers_retained: bool,
    pub raw_body_retained: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    pub fn new(
        request: &AwsElbReadRequest,
        response_bytes: usize,
        provenance: ProviderProvenance,
    ) -> Self {
        let mut value = Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            path_digest: Digest::from_parts(
                "aws-elb-request-path/v1",
                &[("operation", request.operation.as_str().to_owned())],
            ),
            header_digest: Digest::from_parts(
                "aws-elb-request-headers/v1",
                &[
                    ("region", request.scope_digest.to_string()),
                    ("operation", request.operation.as_str().to_owned()),
                ],
            ),
            response_bytes,
            estimated_cost_units: 1,
            provenance,
            redacted: true,
            raw_path_retained: false,
            raw_headers_retained: false,
            raw_body_retained: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::zero(),
        };
        value.receipt_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.request_digest,
            &self.path_digest,
            &self.header_digest,
            self.response_bytes,
            self.estimated_cost_units,
            self.provenance,
            self.redacted,
            self.raw_path_retained,
            self.raw_headers_retained,
            self.raw_body_retained,
            self.connected,
            self.native,
            self.first_party,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub request_count: u16,
    pub response_bytes: usize,
    pub estimated_cost_units: u16,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub cost_digest: Digest,
}

impl CostReceipt {
    pub fn from_requests(requests: &[RequestReceipt]) -> Self {
        let request_count = u16::try_from(requests.len()).unwrap_or(u16::MAX);
        let response_bytes = requests.iter().map(|receipt| receipt.response_bytes).sum();
        let estimated_cost_units = requests
            .iter()
            .map(|receipt| receipt.estimated_cost_units)
            .sum();
        let mut value = Self {
            request_count,
            response_bytes,
            estimated_cost_units,
            redacted: true,
            connected: false,
            native: false,
            first_party: false,
            cost_digest: Digest::zero(),
        };
        value.cost_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.request_count,
            self.response_bytes,
            self.estimated_cost_units,
            self.redacted,
            self.connected,
            self.native,
            self.first_party,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorReceipt {
    pub operation: ReadOperation,
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub request_digest: Digest,
    pub error_digest: Digest,
    pub raw_error_retained: bool,
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
    pub load_balancer_digest: Digest,
    pub target_group_digest: Digest,
    pub target_health_digest: Digest,
    pub topology_digest: Digest,
    pub health_digest: Digest,
    pub request_digest: Digest,
    pub cost_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceAuthority {
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub availability_certification: bool,
    pub truth_authority: bool,
    pub durable_receipt: bool,
    pub work_product_adoption: bool,
}

impl EvidenceAuthority {
    pub const fn layer_one() -> Self {
        Self {
            read_only: true,
            proposal_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            availability_certification: false,
            truth_authority: false,
            durable_receipt: false,
            work_product_adoption: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}
