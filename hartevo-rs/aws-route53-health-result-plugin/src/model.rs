//! Typed, bounded AWS Route 53 health-check scope and evidence models.
//!
//! The public model contains no raw endpoint, IP address, CloudWatch alarm
//! name, DNS record, provider body, pagination token, or secret material.
//! Values that must be correlated are represented by bounded digests.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_MARKER_BYTES: usize = 512;
pub const MAX_HEALTH_CHECKS_PER_PAGE: usize = 64;
pub const MAX_HEALTH_CHECKS: usize = 256;
pub const MAX_OBSERVATIONS: usize = 256;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 12;
pub const MAX_RETRIES: u8 = 2;
pub const MAX_OBSERVATION_WINDOW_SECONDS: i64 = 86_400;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque marker")]
    InvalidMarker { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is outside the allowed observation window")]
    OutsideWindow { field: &'static str },
    #[error("{field} is too large")]
    TooLarge { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("hartevo-route53-", $field, "/v1"),
                    std::slice::from_ref(&self.0),
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
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(HealthCheckId, "health-check id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
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

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAccountId")
            .field("digest", &Digest::from_text(&self.0))
            .finish()
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "AWS region")?;
        if value.starts_with('-') || value.ends_with('-') {
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

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type HealthCheckRevision = Revision;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::from_bytes(&bytes))
        .map_err(|_| ModelError::Invalid {
            field: "digest input",
        })
}

pub fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    digest_serializable(value).unwrap_or_else(|_| Digest::zero())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthCheckType {
    Http,
    Https,
    Tcp,
    Calculated,
    CloudWatchMetric,
}

impl HealthCheckType {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value {
            "HTTP" => Ok(Self::Http),
            "HTTPS" => Ok(Self::Https),
            "TCP" => Ok(Self::Tcp),
            "CALCULATED" => Ok(Self::Calculated),
            "CLOUDWATCH_METRIC" => Ok(Self::CloudWatchMetric),
            _ => Err(ModelError::Unsupported {
                field: "Route 53 health-check type",
            }),
        }
    }

    pub const fn is_calculated(self) -> bool {
        matches!(self, Self::Calculated)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum HealthCheckTarget {
    Endpoint {
        endpoint_digest: Digest,
    },
    CloudWatchAlarm {
        alarm_digest: Digest,
        region: AwsRegion,
    },
    Calculated {
        child_count: u16,
    },
}

impl HealthCheckTarget {
    pub fn endpoint(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, "health-check endpoint", MAX_IDENTIFIER_BYTES)?;
        Ok(Self::Endpoint {
            endpoint_digest: Digest::from_parts(
                "hartevo-aws-route53-health-endpoint/v1",
                &[value.to_owned()],
            ),
        })
    }

    pub fn from_endpoint_digest(endpoint_digest: Digest) -> Self {
        Self::Endpoint { endpoint_digest }
    }

    pub fn cloudwatch_alarm(value: impl AsRef<str>, region: AwsRegion) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, "CloudWatch alarm", MAX_IDENTIFIER_BYTES)?;
        Ok(Self::CloudWatchAlarm {
            alarm_digest: Digest::from_parts(
                "hartevo-aws-route53-health-cloudwatch-alarm/v1",
                &[value.to_owned(), region.as_str().to_owned()],
            ),
            region,
        })
    }

    pub fn from_cloudwatch_alarm_digest(alarm_digest: Digest, region: AwsRegion) -> Self {
        Self::CloudWatchAlarm {
            alarm_digest,
            region,
        }
    }

    pub fn calculated(child_count: u16) -> Result<Self, ModelError> {
        if child_count == 0 {
            return Err(ModelError::MustBePositive {
                field: "calculated health-check child count",
            });
        }
        Ok(Self::Calculated { child_count })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn endpoint_digest(&self) -> Option<&Digest> {
        match self {
            Self::Endpoint { endpoint_digest } => Some(endpoint_digest),
            Self::CloudWatchAlarm { .. } | Self::Calculated { .. } => None,
        }
    }

    pub fn alarm_digest(&self) -> Option<&Digest> {
        match self {
            Self::CloudWatchAlarm { alarm_digest, .. } => Some(alarm_digest),
            Self::Endpoint { .. } | Self::Calculated { .. } => None,
        }
    }

    pub const fn is_calculated(&self) -> bool {
        matches!(self, Self::Calculated { .. })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckBinding {
    pub id: HealthCheckId,
    pub revision: Revision,
    pub target: HealthCheckTarget,
}

impl HealthCheckBinding {
    pub fn new(
        id: HealthCheckId,
        revision: Revision,
        target: HealthCheckTarget,
    ) -> Result<Self, ModelError> {
        if target.is_calculated() {
            // Calculated checks are representable for scope fencing so that
            // their unsupported status is explicit rather than silently lost.
        }
        Ok(Self {
            id,
            revision,
            target,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    ListHealthChecks,
    GetHealthCheck,
    GetHealthCheckStatus,
}

impl PermissionFence {
    pub fn new(
        id: PermissionId,
        revision: Revision,
        actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "Route 53 permission fence",
            });
        }
        Ok(Self {
            id,
            revision,
            allowed_actions,
        })
    }

    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::ListHealthChecks,
                PermissionAction::GetHealthCheck,
                PermissionAction::GetHealthCheckStatus,
            ],
        )
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn is_complete_read_only(&self) -> bool {
        [
            PermissionAction::ListHealthChecks,
            PermissionAction::GetHealthCheck,
            PermissionAction::GetHealthCheckStatus,
        ]
        .into_iter()
        .all(|action| self.allows(action))
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

/// A SigV4 reference is reduced to a digest before entering the service.
/// The supplied reference and signing material are never retained.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
}

impl SecretReference {
    pub fn new(reference: impl AsRef<str>, region: AwsRegion) -> Result<Self, ModelError> {
        let value = reference.as_ref();
        validate_text(value, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-aws-route53-sigv4-secret-reference/v1",
                &[value.to_owned(), region.as_str().to_owned()],
            ),
            region,
        })
    }

    pub fn for_route53(reference: impl AsRef<str>, region: &AwsRegion) -> Result<Self, ModelError> {
        Self::new(reference, region.clone())
    }

    pub fn for_health(reference: impl AsRef<str>, region: &AwsRegion) -> Result<Self, ModelError> {
        Self::for_route53(reference, region)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn region(&self) -> &AwsRegion {
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
            .field("signing_service", &"route53")
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

pub type SigV4SecretReference = SecretReference;

/// Provider pagination markers are intentionally non-serializing. Only a
/// digest and the query binding survive a page boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueMarker {
    token_digest: Digest,
    binding_digest: Digest,
}

impl OpaqueMarker {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        validate_text(value, "Route 53 next marker", MAX_MARKER_BYTES)?;
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-route53-next-marker/v1",
                &[value.to_owned()],
            ),
            binding_digest: Digest::zero(),
        })
    }

    pub fn from_digest(token_digest: Digest) -> Self {
        Self {
            token_digest,
            binding_digest: Digest::zero(),
        }
    }

    pub fn bind(&self, query_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: query_digest.clone(),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn is_bound(&self) -> bool {
        self.binding_digest != Digest::zero()
    }
}

impl fmt::Debug for OpaqueMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueMarker")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account: AwsAccountId,
    pub region: AwsRegion,
    pub health_check: HealthCheckBinding,
    pub permission_digest: Digest,
}

impl AwsRoute53HealthScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account: AwsAccountId,
        region: AwsRegion,
        health_check: HealthCheckBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account,
            region,
            health_check,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::InvalidDigest {
                field: "scope permission digest",
            });
        }
        if self.health_check.target.is_calculated() {
            // Calculated scope is intentionally valid so the service can emit
            // a typed UNSUPPORTED result rather than silently widening scope.
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn health_check_id(&self) -> &HealthCheckId {
        &self.health_check.id
    }

    pub fn health_check_revision(&self) -> Revision {
        self.health_check.revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission.id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project.id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBounds {
    pub page_size: u16,
    pub max_pages: u16,
    pub max_health_checks: u16,
    pub max_observations: u16,
    pub max_response_bytes: usize,
    pub max_requests_per_read: u16,
    pub max_retries: u8,
    pub observation_window_seconds: i64,
}

impl ReadBounds {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        page_size: u16,
        max_pages: u16,
        max_health_checks: u16,
        max_observations: u16,
        max_response_bytes: usize,
        max_requests_per_read: u16,
        max_retries: u8,
        observation_window: Duration,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            page_size,
            max_pages,
            max_health_checks,
            max_observations,
            max_response_bytes,
            max_requests_per_read,
            max_retries,
            observation_window_seconds: observation_window.num_seconds(),
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_size == 0 || self.page_size > PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if self.max_pages == 0 || self.max_pages > MAX_PAGES {
            return Err(ModelError::Invalid { field: "max pages" });
        }
        if self.max_health_checks == 0 || usize::from(self.max_health_checks) > MAX_HEALTH_CHECKS {
            return Err(ModelError::Invalid {
                field: "max health-checks",
            });
        }
        if self.max_observations == 0 || usize::from(self.max_observations) > MAX_OBSERVATIONS {
            return Err(ModelError::Invalid {
                field: "max observations",
            });
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "max response bytes",
            });
        }
        if self.max_requests_per_read == 0 || self.max_requests_per_read > MAX_REQUESTS_PER_READ {
            return Err(ModelError::Invalid {
                field: "max requests per read",
            });
        }
        if self.max_retries > MAX_RETRIES {
            return Err(ModelError::Invalid {
                field: "max retries",
            });
        }
        if self.observation_window_seconds <= 0
            || self.observation_window_seconds > MAX_OBSERVATION_WINDOW_SECONDS
        {
            return Err(ModelError::Invalid {
                field: "observation window",
            });
        }
        Ok(())
    }

    pub fn observation_window(&self) -> Duration {
        Duration::seconds(self.observation_window_seconds)
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            page_size: PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_health_checks: MAX_HEALTH_CHECKS as u16,
            max_observations: MAX_OBSERVATIONS as u16,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_requests_per_read: MAX_REQUESTS_PER_READ,
            max_retries: MAX_RETRIES,
            observation_window_seconds: MAX_OBSERVATION_WINDOW_SECONDS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthReadRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_health_checks: u16,
    pub max_observations: u16,
    pub max_response_bytes: usize,
    pub max_requests_per_read: u16,
    pub max_retries: u8,
    pub observation_window_seconds: i64,
    pub as_of: DateTime<Utc>,
    pub initial_marker: Option<OpaqueMarker>,
    pub request_digest: Digest,
}

impl AwsRoute53HealthReadRequest {
    pub fn new(
        scope: &AwsRoute53HealthScope,
        bounds: ReadBounds,
        as_of: DateTime<Utc>,
        initial_marker: Option<OpaqueMarker>,
    ) -> Result<Self, ModelError> {
        bounds.validate()?;
        let query = RequestQueryBody {
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            page_size: bounds.page_size,
            max_pages: bounds.max_pages,
            max_health_checks: bounds.max_health_checks,
            max_observations: bounds.max_observations,
            max_response_bytes: bounds.max_response_bytes,
            max_requests_per_read: bounds.max_requests_per_read,
            max_retries: bounds.max_retries,
            observation_window_seconds: bounds.observation_window_seconds,
            as_of,
        };
        let query_digest = digest_serialized(&query);
        let initial_marker = initial_marker
            .map(|marker| bind_marker(marker, &query_digest))
            .transpose()?;
        let request_digest = digest_serialized(&RequestDigestBody {
            query_digest: query_digest.clone(),
            marker_digest: initial_marker
                .as_ref()
                .map(|marker| marker.token_digest.clone()),
        });
        Ok(Self {
            scope_digest: query.scope_digest,
            permission_digest: query.permission_digest,
            page_size: query.page_size,
            max_pages: query.max_pages,
            max_health_checks: query.max_health_checks,
            max_observations: query.max_observations,
            max_response_bytes: query.max_response_bytes,
            max_requests_per_read: query.max_requests_per_read,
            max_retries: query.max_retries,
            observation_window_seconds: query.observation_window_seconds,
            as_of: query.as_of,
            initial_marker,
            request_digest,
        })
    }

    pub fn validate_against(&self, scope: &AwsRoute53HealthScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest() {
            return Err(ModelError::ScopeMismatch {
                field: "read request scope digest",
            });
        }
        if self.permission_digest != scope.permission_digest {
            return Err(ModelError::ScopeMismatch {
                field: "read request permission digest",
            });
        }
        ReadBounds {
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_health_checks: self.max_health_checks,
            max_observations: self.max_observations,
            max_response_bytes: self.max_response_bytes,
            max_requests_per_read: self.max_requests_per_read,
            max_retries: self.max_retries,
            observation_window_seconds: self.observation_window_seconds,
        }
        .validate()?;
        if self.initial_marker.as_ref().is_some_and(|marker| {
            marker.is_bound() && marker.binding_digest() != &self.query_digest()
        }) {
            return Err(ModelError::ScopeMismatch {
                field: "initial marker query binding",
            });
        }
        if self.request_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "read request digest",
            });
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&RequestQueryBody {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_health_checks: self.max_health_checks,
            max_observations: self.max_observations,
            max_response_bytes: self.max_response_bytes,
            max_requests_per_read: self.max_requests_per_read,
            max_retries: self.max_retries,
            observation_window_seconds: self.observation_window_seconds,
            as_of: self.as_of,
        })
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RequestDigestBody {
            query_digest: self.query_digest(),
            marker_digest: self
                .initial_marker
                .as_ref()
                .map(|marker| marker.token_digest.clone()),
        })
    }

    pub fn with_marker(&self, marker: Option<OpaqueMarker>) -> Result<Self, ModelError> {
        let initial_marker = marker
            .map(|marker| bind_marker(marker, &self.query_digest()))
            .transpose()?;
        let mut request = self.clone();
        request.initial_marker = initial_marker;
        request.request_digest = request.recomputed_digest();
        Ok(request)
    }

    pub fn with_as_of(&self, as_of: DateTime<Utc>) -> Result<Self, ModelError> {
        let mut request = self.clone();
        request.as_of = as_of;
        let query_digest = request.query_digest();
        request.initial_marker = request
            .initial_marker
            .take()
            .map(|marker| bind_marker(marker, &query_digest))
            .transpose()?;
        request.request_digest = request.recomputed_digest();
        Ok(request)
    }
}

pub type AwsRoute53ReadRequest = AwsRoute53HealthReadRequest;
pub type Route53HealthReadRequest = AwsRoute53HealthReadRequest;
pub type AwsRoute53HealthReadOperation = ReadOperation;
pub type AwsRoute53ReadOperation = ReadOperation;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestQueryBody {
    scope_digest: Digest,
    permission_digest: Digest,
    page_size: u16,
    max_pages: u16,
    max_health_checks: u16,
    max_observations: u16,
    max_response_bytes: usize,
    max_requests_per_read: u16,
    max_retries: u8,
    observation_window_seconds: i64,
    as_of: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestDigestBody {
    query_digest: Digest,
    marker_digest: Option<Digest>,
}

fn bind_marker(marker: OpaqueMarker, query_digest: &Digest) -> Result<OpaqueMarker, ModelError> {
    if marker.is_bound() && marker.binding_digest() != query_digest {
        return Err(ModelError::ScopeMismatch {
            field: "marker query binding",
        });
    }
    Ok(marker.bind(query_digest))
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckConfiguration {
    pub check_type: HealthCheckType,
    pub target: HealthCheckTarget,
    pub port: Option<u16>,
    pub resource_path_digest: Option<Digest>,
    pub request_interval_seconds: u16,
    pub failure_threshold: u16,
    pub regions: BTreeSet<AwsRegion>,
    pub measure_latency: bool,
    pub enable_sni: bool,
    pub child_count: u16,
    pub configuration_digest: Digest,
}

impl HealthCheckConfiguration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        check_type: HealthCheckType,
        target: HealthCheckTarget,
        port: Option<u16>,
        resource_path: Option<impl AsRef<str>>,
        request_interval_seconds: u16,
        failure_threshold: u16,
        regions: impl IntoIterator<Item = AwsRegion>,
        measure_latency: bool,
        enable_sni: bool,
        child_count: u16,
    ) -> Result<Self, ModelError> {
        if request_interval_seconds == 0 || failure_threshold == 0 {
            return Err(ModelError::MustBePositive {
                field: "health-check interval and threshold",
            });
        }
        if matches!(
            check_type,
            HealthCheckType::Http | HealthCheckType::Https | HealthCheckType::Tcp
        ) && !matches!(&target, HealthCheckTarget::Endpoint { .. })
        {
            return Err(ModelError::ScopeMismatch {
                field: "endpoint health-check target",
            });
        }
        if matches!(check_type, HealthCheckType::CloudWatchMetric)
            && !matches!(&target, HealthCheckTarget::CloudWatchAlarm { .. })
        {
            return Err(ModelError::ScopeMismatch {
                field: "CloudWatch health-check target",
            });
        }
        if check_type.is_calculated() && !matches!(&target, HealthCheckTarget::Calculated { .. }) {
            return Err(ModelError::ScopeMismatch {
                field: "calculated health-check target",
            });
        }
        let resource_path_digest = resource_path
            .map(|path| {
                let path = path.as_ref();
                validate_text(path, "health-check resource path", MAX_IDENTIFIER_BYTES)?;
                Ok(Digest::from_parts(
                    "hartevo-aws-route53-resource-path/v1",
                    &[path.to_owned()],
                ))
            })
            .transpose()?;
        let regions = regions.into_iter().collect::<BTreeSet<_>>();
        if regions.is_empty() {
            return Err(ModelError::Empty {
                field: "health-check regions",
            });
        }
        if let HealthCheckTarget::Calculated {
            child_count: target_count,
        } = &target
            && (child_count == 0 || child_count != *target_count)
        {
            return Err(ModelError::Invalid {
                field: "calculated child count",
            });
        }
        if check_type.is_calculated() && child_count == 0 {
            return Err(ModelError::MustBePositive {
                field: "calculated child count",
            });
        }
        let body = ConfigurationBody {
            check_type,
            target: target.clone(),
            port,
            resource_path_digest: resource_path_digest.clone(),
            request_interval_seconds,
            failure_threshold,
            regions: regions.clone(),
            measure_latency,
            enable_sni,
            child_count,
        };
        Ok(Self {
            check_type,
            target,
            port,
            resource_path_digest,
            request_interval_seconds,
            failure_threshold,
            regions,
            measure_latency,
            enable_sni,
            child_count,
            configuration_digest: digest_serialized(&body),
        })
    }

    pub fn endpoint(
        check_type: HealthCheckType,
        endpoint: impl AsRef<str>,
        port: u16,
        resource_path: Option<impl AsRef<str>>,
        request_interval_seconds: u16,
        failure_threshold: u16,
        regions: impl IntoIterator<Item = AwsRegion>,
    ) -> Result<Self, ModelError> {
        Self::new(
            check_type,
            HealthCheckTarget::endpoint(endpoint)?,
            Some(port),
            resource_path,
            request_interval_seconds,
            failure_threshold,
            regions,
            false,
            matches!(check_type, HealthCheckType::Https),
            0,
        )
    }

    pub fn cloudwatch_alarm(
        alarm: impl AsRef<str>,
        alarm_region: AwsRegion,
        request_interval_seconds: u16,
        failure_threshold: u16,
        regions: impl IntoIterator<Item = AwsRegion>,
    ) -> Result<Self, ModelError> {
        Self::new(
            HealthCheckType::CloudWatchMetric,
            HealthCheckTarget::cloudwatch_alarm(alarm, alarm_region)?,
            None,
            Option::<String>::None,
            request_interval_seconds,
            failure_threshold,
            regions,
            false,
            false,
            0,
        )
    }

    pub fn calculated(
        child_count: u16,
        request_interval_seconds: u16,
        failure_threshold: u16,
        regions: impl IntoIterator<Item = AwsRegion>,
    ) -> Result<Self, ModelError> {
        Self::new(
            HealthCheckType::Calculated,
            HealthCheckTarget::calculated(child_count)?,
            None,
            Option::<String>::None,
            request_interval_seconds,
            failure_threshold,
            regions,
            false,
            false,
            child_count,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.configuration_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "health-check configuration digest",
            });
        }
        if self.regions.is_empty()
            || self.request_interval_seconds == 0
            || self.failure_threshold == 0
        {
            return Err(ModelError::Invalid {
                field: "health-check configuration bounds",
            });
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ConfigurationBody {
            check_type: self.check_type,
            target: self.target.clone(),
            port: self.port,
            resource_path_digest: self.resource_path_digest.clone(),
            request_interval_seconds: self.request_interval_seconds,
            failure_threshold: self.failure_threshold,
            regions: self.regions.clone(),
            measure_latency: self.measure_latency,
            enable_sni: self.enable_sni,
            child_count: self.child_count,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationBody {
    check_type: HealthCheckType,
    target: HealthCheckTarget,
    port: Option<u16>,
    resource_path_digest: Option<Digest>,
    request_interval_seconds: u16,
    failure_threshold: u16,
    regions: BTreeSet<AwsRegion>,
    measure_latency: bool,
    enable_sni: bool,
    child_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckSummary {
    pub id: HealthCheckId,
    pub revision: Revision,
    pub caller_reference_digest: Digest,
    pub configuration: HealthCheckConfiguration,
    pub summary_digest: Digest,
}

impl HealthCheckSummary {
    pub fn new(
        id: HealthCheckId,
        revision: Revision,
        caller_reference: impl AsRef<str>,
        configuration: HealthCheckConfiguration,
    ) -> Result<Self, ModelError> {
        validate_text(
            caller_reference.as_ref(),
            "health-check caller reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        configuration.validate()?;
        let caller_reference_digest = Digest::from_parts(
            "hartevo-aws-route53-caller-reference/v1",
            &[caller_reference.as_ref().to_owned()],
        );
        let summary_digest = digest_serialized(&SummaryBody {
            id: id.clone(),
            revision,
            caller_reference_digest: caller_reference_digest.clone(),
            configuration: configuration.clone(),
        });
        Ok(Self {
            id,
            revision,
            caller_reference_digest,
            configuration,
            summary_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.configuration.validate()?;
        if self.summary_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "health-check summary digest",
            });
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&SummaryBody {
            id: self.id.clone(),
            revision: self.revision,
            caller_reference_digest: self.caller_reference_digest.clone(),
            configuration: self.configuration.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryBody {
    id: HealthCheckId,
    revision: Revision,
    caller_reference_digest: Digest,
    configuration: HealthCheckConfiguration,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

impl ObservationStatus {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value {
            "Success" | "SUCCESS" | "HEALTHY" => Ok(Self::Healthy),
            "Failure" | "FAILURE" | "UNHEALTHY" => Ok(Self::Unhealthy),
            "Unknown" | "UNKNOWN" | "INSUFFICIENT_DATA" => Ok(Self::Unknown),
            _ => Err(ModelError::Unsupported {
                field: "Route 53 status observation",
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckObservation {
    pub region: AwsRegion,
    pub status: ObservationStatus,
    pub checked_at: DateTime<Utc>,
    pub checker_digest: Digest,
    pub failure_digest: Option<Digest>,
    pub observation_digest: Digest,
}

impl HealthCheckObservation {
    pub fn new(
        region: AwsRegion,
        checker_reference: impl AsRef<str>,
        status: ObservationStatus,
        checked_at: DateTime<Utc>,
        failure_detail: Option<impl AsRef<str>>,
    ) -> Result<Self, ModelError> {
        validate_text(
            checker_reference.as_ref(),
            "Route 53 checker reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let checker_digest = Digest::from_parts(
            "hartevo-aws-route53-checker/v1",
            &[checker_reference.as_ref().to_owned()],
        );
        let failure_digest = failure_detail
            .map(|detail| {
                let detail = detail.as_ref();
                validate_text(detail, "Route 53 failure detail", MAX_IDENTIFIER_BYTES)?;
                Ok(Digest::from_parts(
                    "hartevo-aws-route53-failure/v1",
                    &[detail.to_owned()],
                ))
            })
            .transpose()?;
        let observation_digest = digest_serialized(&ObservationBody {
            region: region.clone(),
            status,
            checked_at,
            checker_digest: checker_digest.clone(),
            failure_digest: failure_digest.clone(),
        });
        Ok(Self {
            region,
            status,
            checked_at,
            checker_digest,
            failure_digest,
            observation_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.observation_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "health-check observation digest",
            });
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ObservationBody {
            region: self.region.clone(),
            status: self.status,
            checked_at: self.checked_at,
            checker_digest: self.checker_digest.clone(),
            failure_digest: self.failure_digest.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservationBody {
    region: AwsRegion,
    status: ObservationStatus,
    checked_at: DateTime<Utc>,
    checker_digest: Digest,
    failure_digest: Option<Digest>,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Healthy,
    Unhealthy,
    InsufficientData,
    Unsupported,
    NotFound,
    #[serde(rename = "partial")]
    Partial,
    #[serde(rename = "access_loss")]
    AccessLoss,
    #[serde(rename = "throttled")]
    Throttled,
    #[serde(rename = "timeout")]
    Timeout,
    #[serde(rename = "provider_unknown")]
    ProviderUnknown,
}

impl EvidenceState {
    pub const fn is_adoptable(self) -> bool {
        false
    }

    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Healthy | Self::Unhealthy)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PaginationBudget,
    PaginationLoop,
    HealthCheckLimit,
    MissingHealthCheck,
    HealthCheckRevisionDrift,
    ScopeMismatch,
    PermissionLoss,
    DigestMismatch,
    TamperedResponse,
    Replay,
    PartialStatus,
    StaleObservation,
    DuplicateObservation,
    CalculatedCheckUnsupported,
    ProviderConflict,
    MissingObservation,
    ResponseTooLarge,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn durable_receipt(self) -> bool {
        false
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    ListHealthChecks,
    GetHealthCheck,
    GetHealthCheckStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: ReadOperation,
    pub category: String,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRoute53HealthEvidence {
    pub state: EvidenceState,
    pub partial_reason: Option<PartialReason>,
    pub health_check: Option<HealthCheckSummary>,
    pub observations: Vec<HealthCheckObservation>,
    pub list_page_count: u16,
    pub list_complete: bool,
    pub request_count: u16,
    pub retry_count: u8,
    pub response_bytes: usize,
    pub observation_window_start: DateTime<Utc>,
    pub observation_window_end: DateTime<Utc>,
    pub request_digest: Digest,
    pub list_page_digests: Vec<Digest>,
    pub get_response_digest: Option<Digest>,
    pub status_response_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_id: ProviderId,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_receipt: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub evidence_digest: Digest,
}

impl AwsRoute53HealthEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.observations.len() > MAX_OBSERVATIONS
            || self.list_page_digests.len() > usize::from(MAX_PAGES)
        {
            return Err(ModelError::TooMany {
                field: "Route 53 evidence entries",
            });
        }
        if self.health_check.is_none()
            && matches!(
                self.state,
                EvidenceState::Healthy | EvidenceState::Unhealthy | EvidenceState::Unsupported
            )
        {
            return Err(ModelError::Invalid {
                field: "health-check evidence state",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        if let Some(health_check) = &self.health_check {
            health_check.validate()?;
        }
        if self.connected
            || self.native
            || self.first_party
            || self.durable_receipt
            || self.certification_claim
            || self.adopted_outcome
            || self.truth_authority
        {
            return Err(ModelError::Unsupported {
                field: "Layer-1 authority claim",
            });
        }
        if self.evidence_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "Route 53 evidence digest",
            });
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            state: self.state,
            partial_reason: self.partial_reason,
            health_check: self.health_check.clone(),
            observations: self.observations.clone(),
            list_page_count: self.list_page_count,
            list_complete: self.list_complete,
            request_count: self.request_count,
            retry_count: self.retry_count,
            response_bytes: self.response_bytes,
            observation_window_start: self.observation_window_start,
            observation_window_end: self.observation_window_end,
            request_digest: self.request_digest.clone(),
            list_page_digests: self.list_page_digests.clone(),
            get_response_digest: self.get_response_digest.clone(),
            status_response_digest: self.status_response_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_revision: self.provider_revision.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            contract_digest: self.contract_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            provider_errors: self.provider_errors.clone(),
            provenance: self.provenance,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody {
    state: EvidenceState,
    partial_reason: Option<PartialReason>,
    health_check: Option<HealthCheckSummary>,
    observations: Vec<HealthCheckObservation>,
    list_page_count: u16,
    list_complete: bool,
    request_count: u16,
    retry_count: u8,
    response_bytes: usize,
    observation_window_start: DateTime<Utc>,
    observation_window_end: DateTime<Utc>,
    request_digest: Digest,
    list_page_digests: Vec<Digest>,
    get_response_digest: Option<Digest>,
    status_response_digest: Option<Digest>,
    scope_digest: Digest,
    permission_digest: Digest,
    provider_id: ProviderId,
    provider_revision: ProviderRevision,
    provider_digest: Digest,
    api_digest: Digest,
    contract_digest: Digest,
    registration_digest: Digest,
    provider_errors: Vec<ProviderErrorEvidence>,
    provenance: TransportProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ListHealthChecksPage {
    pub operation: ReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub health_checks: Vec<HealthCheckSummary>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

impl ListHealthChecksPage {
    pub fn new(
        request: &crate::provider::ListHealthChecksRequest,
        page_number: u16,
        health_checks: Vec<HealthCheckSummary>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || health_checks.len() > MAX_HEALTH_CHECKS_PER_PAGE {
            return Err(ModelError::Invalid {
                field: "Route 53 list page",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooLarge {
                field: "Route 53 response",
            });
        }
        for health_check in &health_checks {
            health_check.validate()?;
        }
        let next_marker = next_marker
            .map(|marker| bind_marker(marker, &request.query_digest()))
            .transpose()?;
        let page_digest = digest_serialized(&ListPageBody {
            operation: ReadOperation::ListHealthChecks,
            query_digest: request.query_digest(),
            page_number,
            health_checks: health_checks.clone(),
            next_marker_digest: next_marker
                .as_ref()
                .map(|marker| marker.token_digest.clone()),
            response_bytes,
            provider_revision: provider_revision.clone(),
        });
        Ok(Self {
            operation: ReadOperation::ListHealthChecks,
            query_digest: request.query_digest(),
            page_number,
            health_checks,
            next_marker,
            response_bytes,
            provider_revision,
            page_digest,
        })
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ListPageBody {
            operation: self.operation,
            query_digest: self.query_digest.clone(),
            page_number: self.page_number,
            health_checks: self.health_checks.clone(),
            next_marker_digest: self
                .next_marker
                .as_ref()
                .map(|marker| marker.token_digest.clone()),
            response_bytes: self.response_bytes,
            provider_revision: self.provider_revision.clone(),
        })
    }

    pub fn validate_for(
        &self,
        request: &crate::provider::ListHealthChecksRequest,
    ) -> Result<(), ModelError> {
        if self.operation != ReadOperation::ListHealthChecks
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.health_checks.len() > MAX_HEALTH_CHECKS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
            || self
                .next_marker
                .as_ref()
                .is_some_and(|marker| marker.binding_digest() != &request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "Route 53 list page binding",
            });
        }
        for health_check in &self.health_checks {
            health_check.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ListPageBody {
    operation: ReadOperation,
    query_digest: Digest,
    page_number: u16,
    health_checks: Vec<HealthCheckSummary>,
    next_marker_digest: Option<Digest>,
    response_bytes: usize,
    provider_revision: ProviderRevision,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GetHealthCheckResponse {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub health_check: HealthCheckSummary,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub response_digest: Digest,
}

impl GetHealthCheckResponse {
    pub fn new(
        request: &crate::provider::GetHealthCheckRequest,
        health_check: HealthCheckSummary,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooLarge {
                field: "Route 53 response",
            });
        }
        health_check.validate()?;
        let response_digest = digest_serialized(&GetBody {
            operation: ReadOperation::GetHealthCheck,
            request_digest: request.request_digest(),
            health_check: health_check.clone(),
            response_bytes,
            provider_revision: provider_revision.clone(),
        });
        Ok(Self {
            operation: ReadOperation::GetHealthCheck,
            request_digest: request.request_digest(),
            health_check,
            response_bytes,
            provider_revision,
            response_digest,
        })
    }

    pub fn validate_for(
        &self,
        request: &crate::provider::GetHealthCheckRequest,
    ) -> Result<(), ModelError> {
        if self.operation != ReadOperation::GetHealthCheck
            || self.request_digest != request.request_digest()
            || self.response_digest != self.recomputed_digest()
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
        {
            return Err(ModelError::ScopeMismatch {
                field: "Route 53 get response binding",
            });
        }
        self.health_check.validate()
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&GetBody {
            operation: self.operation,
            request_digest: self.request_digest.clone(),
            health_check: self.health_check.clone(),
            response_bytes: self.response_bytes,
            provider_revision: self.provider_revision.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GetHealthCheckStatusResponse {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub health_check_id: HealthCheckId,
    pub observations: Vec<HealthCheckObservation>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub response_digest: Digest,
}

impl GetHealthCheckStatusResponse {
    pub fn new(
        request: &crate::provider::GetHealthCheckStatusRequest,
        observations: Vec<HealthCheckObservation>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if observations.len() > MAX_OBSERVATIONS {
            return Err(ModelError::TooMany {
                field: "Route 53 observations",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::TooLarge {
                field: "Route 53 response",
            });
        }
        for observation in &observations {
            observation.validate()?;
        }
        let response_digest = digest_serialized(&StatusBody {
            operation: ReadOperation::GetHealthCheckStatus,
            request_digest: request.request_digest(),
            health_check_id: request.health_check_id.clone(),
            observations: observations.clone(),
            response_bytes,
            provider_revision: provider_revision.clone(),
        });
        Ok(Self {
            operation: ReadOperation::GetHealthCheckStatus,
            request_digest: request.request_digest(),
            health_check_id: request.health_check_id.clone(),
            observations,
            response_bytes,
            provider_revision,
            response_digest,
        })
    }

    pub fn validate_for(
        &self,
        request: &crate::provider::GetHealthCheckStatusRequest,
    ) -> Result<(), ModelError> {
        if self.operation != ReadOperation::GetHealthCheckStatus
            || self.request_digest != request.request_digest()
            || self.health_check_id != request.health_check_id
            || self.response_digest != self.recomputed_digest()
            || self.observations.len() > request.max_observations as usize
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
        {
            return Err(ModelError::ScopeMismatch {
                field: "Route 53 status response binding",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&StatusBody {
            operation: self.operation,
            request_digest: self.request_digest.clone(),
            health_check_id: self.health_check_id.clone(),
            observations: self.observations.clone(),
            response_bytes: self.response_bytes,
            provider_revision: self.provider_revision.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GetBody {
    operation: ReadOperation,
    request_digest: Digest,
    health_check: HealthCheckSummary,
    response_bytes: usize,
    provider_revision: ProviderRevision,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusBody {
    operation: ReadOperation,
    request_digest: Digest,
    health_check_id: HealthCheckId,
    observations: Vec<HealthCheckObservation>,
    response_bytes: usize,
    provider_revision: ProviderRevision,
}

pub type ListHealthChecksResponse = ListHealthChecksPage;
pub type GetHealthCheckResult = GetHealthCheckResponse;
pub type GetHealthCheckStatusResult = GetHealthCheckStatusResponse;
