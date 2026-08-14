//! Typed, bounded CloudWatch alarm scope and evidence models.
//!
//! The model deliberately has no representation for credentials, alarm
//! actions, dashboards, logs, raw dimensions, raw provider payloads, or an
//! unbounded datapoint list. Those values cannot cross the Layer-1 boundary
//! because they are not representable in the public evidence types.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    API_REVISION, CONTRACT_VERSION, MAX_DATAPOINTS, MAX_IDENTIFIER_BYTES, MAX_PAGES,
    MAX_PROVIDER_ERRORS, MAX_RECEIPTS, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, MAX_RETRIES,
    MAX_WINDOW_SECONDS, PLUGIN_VERSION,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
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
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is not finite")]
    NonFinite { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("secret reference is revoked")]
    SecretRevoked,
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

fn validate_identifier(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    validate_text(value, field, max)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@".contains(&byte)))
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
                validate_identifier(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("hartevo-aws-cloudwatch-", $field, "/v1"),
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
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(DeploymentId, "deployment-id");
bounded_identifier!(MissionId, "mission-id");
bounded_identifier!(ProjectId, "project-id");
bounded_identifier!(WorkProductId, "work-product-id");
bounded_identifier!(PermissionId, "permission-id");
bounded_identifier!(ProviderId, "provider-id");
bounded_identifier!(ProviderRevision, "provider-revision");

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
            .field("digest", &Digest::from_text(self.as_str()))
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
        validate_identifier(&value, "AWS region", 63)?;
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
pub type AccountId = AwsAccountId;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AlarmName(String);

impl AlarmName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "CloudWatch alarm name", 255)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-cloudwatch-alarm-name/v1",
            &[("value", self.0.clone())],
        )
    }
}

impl fmt::Debug for AlarmName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlarmName")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AlarmName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct MetricNamespace(String);

impl MetricNamespace {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "metric namespace", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MetricNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricNamespace")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for MetricNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct MetricName(String);

impl MetricName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "metric name", MAX_IDENTIFIER_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MetricName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetricName")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for MetricName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

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

pub type AlarmRevision = Revision;
pub type AwsCloudWatchAlarmRevision = Revision;

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

    pub fn from_parts<I>(domain: impl AsRef<str>, fields: I) -> Self
    where
        I: IntoIterator,
        I::Item: DigestField,
    {
        let mut bytes = Vec::new();
        append_digest_part(&mut bytes, domain.as_ref());
        for field in fields {
            append_digest_part(&mut bytes, field.name());
            append_digest_part(&mut bytes, field.value());
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

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest { field: "digest" })
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

fn append_digest_part(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

pub trait DigestField {
    fn name(&self) -> &str;
    fn value(&self) -> &str;
}

impl<K, V> DigestField for (K, V)
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn name(&self) -> &str {
        self.0.as_ref()
    }

    fn value(&self) -> &str {
        self.1.as_ref()
    }
}

impl<K, V> DigestField for &(K, V)
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn name(&self) -> &str {
        self.0.as_ref()
    }

    fn value(&self) -> &str {
        self.1.as_ref()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
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
pub enum AlarmState {
    Ok,
    Alarm,
    InsufficientData,
}

impl AlarmState {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value {
            "OK" => Ok(Self::Ok),
            "ALARM" => Ok(Self::Alarm),
            "INSUFFICIENT_DATA" => Ok(Self::InsufficientData),
            _ => Err(ModelError::Invalid {
                field: "CloudWatch alarm state",
            }),
        }
    }

    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Alarm => "ALARM",
            Self::InsufficientData => "INSUFFICIENT_DATA",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum ComparisonOperator {
    GreaterThanOrEqualToThreshold,
    GreaterThanThreshold,
    LessThanThreshold,
    LessThanOrEqualToThreshold,
    LessThanLowerOrGreaterThanUpperThreshold,
    LessThanLowerThreshold,
    GreaterThanUpperThreshold,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum TreatMissingData {
    Missing,
    Ignore,
    Breaching,
    NotBreaching,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationSummary {
    pub threshold: f64,
    pub comparison_operator: ComparisonOperator,
    pub evaluation_periods: u16,
    pub datapoints_to_alarm: Option<u16>,
    pub period_seconds: u32,
    pub treat_missing_data: TreatMissingData,
}

impl EvaluationSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        threshold: f64,
        comparison_operator: ComparisonOperator,
        evaluation_periods: u16,
        datapoints_to_alarm: Option<u16>,
        period_seconds: u32,
        treat_missing_data: TreatMissingData,
    ) -> Result<Self, ModelError> {
        if !threshold.is_finite() {
            return Err(ModelError::NonFinite {
                field: "alarm threshold",
            });
        }
        if evaluation_periods == 0 || evaluation_periods > 1_440 {
            return Err(ModelError::Invalid {
                field: "evaluation periods",
            });
        }
        if let Some(datapoints_to_alarm) = datapoints_to_alarm
            && (datapoints_to_alarm == 0 || datapoints_to_alarm > evaluation_periods)
        {
            return Err(ModelError::Invalid {
                field: "datapoints to alarm",
            });
        }
        if !valid_period(period_seconds) {
            return Err(ModelError::Invalid {
                field: "alarm period",
            });
        }
        Ok(Self {
            threshold,
            comparison_operator,
            evaluation_periods,
            datapoints_to_alarm,
            period_seconds,
            treat_missing_data,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

fn valid_period(value: u32) -> bool {
    matches!(value, 10 | 20 | 30) || (value >= 60 && value.is_multiple_of(60) && value <= 86_400)
}

#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "camelCase")]
pub struct AlarmIdentity {
    pub name: AlarmName,
    pub revision: Revision,
}

impl AlarmIdentity {
    pub fn new(name: AlarmName, revision: Revision) -> Result<Self, ModelError> {
        let identity = Self { name, revision };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.revision.get() == 0 {
            return Err(ModelError::Invalid {
                field: "alarm revision",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "camelCase")]
pub struct MetricIdentity {
    pub namespace: MetricNamespace,
    pub metric_name: MetricName,
    pub statistic: String,
    pub period_seconds: u32,
    pub dimensions_digest: Digest,
}

impl MetricIdentity {
    pub fn new(
        namespace: MetricNamespace,
        metric_name: MetricName,
        statistic: impl Into<String>,
        period_seconds: u32,
        dimensions_digest: Digest,
    ) -> Result<Self, ModelError> {
        let statistic = statistic.into();
        validate_identifier(&statistic, "metric statistic", 64)?;
        if !valid_period(period_seconds) {
            return Err(ModelError::Invalid {
                field: "metric period",
            });
        }
        dimensions_digest.validate()?;
        if dimensions_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "metric dimensions digest",
            });
        }
        Ok(Self {
            namespace,
            metric_name,
            statistic,
            period_seconds,
            dimensions_digest,
        })
    }

    /// Hashes a bounded dimension set immediately; raw dimension names and
    /// values are not stored in the returned identity.
    pub fn from_dimensions<I, K, V>(
        namespace: MetricNamespace,
        metric_name: MetricName,
        statistic: impl Into<String>,
        period_seconds: u32,
        dimensions: I,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut dimensions = dimensions
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect::<Vec<_>>();
        if dimensions.len() > 16 {
            return Err(ModelError::TooMany {
                field: "metric dimensions",
            });
        }
        dimensions.sort();
        if dimensions.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ModelError::Duplicate {
                field: "metric dimension name",
            });
        }
        for (key, value) in &dimensions {
            validate_identifier(key, "metric dimension name", 255)?;
            validate_text(value, "metric dimension value", 1_024)?;
        }
        let dimension_fields = dimensions
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let dimensions_digest =
            Digest::from_parts("hartevo-aws-cloudwatch-dimensions/v1", &dimension_fields);
        Self::new(
            namespace,
            metric_name,
            statistic,
            period_seconds,
            dimensions_digest,
        )
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricWindow {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

impl MetricWindow {
    pub fn new(start_time: DateTime<Utc>, end_time: DateTime<Utc>) -> Result<Self, ModelError> {
        let window = Self {
            start_time,
            end_time,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn duration_seconds(&self) -> i64 {
        (self.end_time - self.start_time).num_seconds()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let duration = self.duration_seconds();
        if duration <= 0 || duration > MAX_WINDOW_SECONDS {
            return Err(ModelError::Invalid {
                field: "bounded metric window",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    DescribeAlarms,
    GetMetricData,
    ListMetrics,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionSnapshot {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::DescribeAlarms,
                PermissionAction::GetMetricData,
                PermissionAction::ListMetrics,
            ],
        )
    }

    pub fn new<I>(
        id: PermissionId,
        revision: Revision,
        allowed_actions: I,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = PermissionAction>,
    {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "CloudWatch permission allowlist",
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
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchAlarmScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub alarm: AlarmIdentity,
    pub metric: MetricIdentity,
    pub window: MetricWindow,
    pub permission_digest: Digest,
    pub allow_metric_discovery: bool,
}

impl AwsCloudWatchAlarmScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        account_id: AwsAccountId,
        region: AwsRegion,
        alarm: AlarmIdentity,
        metric: MetricIdentity,
        window: MetricWindow,
        permission_digest: Digest,
        allow_metric_discovery: bool,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            account_id,
            region,
            alarm,
            metric,
            window,
            permission_digest,
            allow_metric_discovery,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.alarm.validate()?;
        self.window.validate()?;
        self.metric.dimensions_digest.validate()?;
        if self.permission_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AwsCloudWatchAlarmScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let mut handle = opaque_handle.into();
        if handle.is_empty()
            || handle.len() > MAX_IDENTIFIER_BYTES
            || handle.chars().any(char::is_control)
        {
            handle.zeroize();
            return Err(ModelError::Invalid {
                field: "SigV4 secret reference",
            });
        }
        let revision = match Revision::new(revision) {
            Ok(revision) => revision,
            Err(error) => {
                handle.zeroize();
                return Err(error);
            }
        };
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential"),
                ("handle", handle.as_str()),
                ("scope", scope_digest.as_str()),
                ("revision", &revision.get().to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsCloudWatchAlarmScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, scope, revision)
    }

    pub fn for_cloudwatch(
        opaque_handle: impl Into<String>,
        scope: &AwsCloudWatchAlarmScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, scope, revision)
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> &Digest {
        self.reference_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self, scope: &AwsCloudWatchAlarmScope) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::SecretRevoked);
        }
        if self.kind != SecretKind::Sigv4Credential
            || self.scope_digest != scope.digest()
            || self.revision.get() == 0
        {
            return Err(ModelError::ScopeMismatch {
                field: "SigV4 secret reference",
            });
        }
        self.reference_digest.validate()
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

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    page_number: u16,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::with_page(value, 2)
    }

    pub fn with_page(value: impl AsRef<str>, page_number: u16) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(char::is_control)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(ModelError::InvalidCursor {
                field: "CloudWatch next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-cloudwatch-opaque-cursor/v1",
                &[("token", value)],
            ),
            binding_digest: None,
            page_number,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
            page_number: self.page_number,
        }
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
        let mut value = serializer.serialize_struct("OpaqueCursor", 2)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("pageNumber", &self.page_number)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsCloudWatchOperation {
    DescribeAlarms,
    GetMetricData,
    ListMetrics,
}

impl AwsCloudWatchOperation {
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::DescribeAlarms => PermissionAction::DescribeAlarms,
            Self::GetMetricData => PermissionAction::GetMetricData,
            Self::ListMetrics => PermissionAction::ListMetrics,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    Empty,
    Stale,
    AccessLoss,
    ProviderUnknown,
    RegistrationRevoked,
    Tampered,
}

impl EvidenceStatus {
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    RequestBudget,
    ResponseTooLarge,
    ScanLoop,
    CursorReplay,
    EmptyResponse,
    MissingAlarm,
    MissingMetricData,
    StaleAlarmRevision,
    MetricDrift,
    WindowDrift,
    ProviderError,
    AccessLoss,
    Tampered,
    RegistrationRevoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    AccessDenied,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    MalformedResponse,
    ScanLoop,
    EmptyResponse,
    PartialResponse,
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
    ) -> Self {
        let error_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-provider-error/v1",
            &[
                ("kind", format!("{kind:?}")),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            kind,
            status_code,
            retry_after_seconds,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlarmSnapshot {
    pub identity: AlarmIdentity,
    pub state: AlarmState,
    pub state_updated_at: DateTime<Utc>,
    pub configuration_updated_at: DateTime<Utc>,
    pub evaluation: EvaluationSummary,
    pub metric: MetricIdentity,
    pub alarm_digest: Digest,
}

impl AlarmSnapshot {
    pub fn new(
        identity: AlarmIdentity,
        state: AlarmState,
        state_updated_at: DateTime<Utc>,
        configuration_updated_at: DateTime<Utc>,
        evaluation: EvaluationSummary,
        metric: MetricIdentity,
    ) -> Result<Self, ModelError> {
        if configuration_updated_at > state_updated_at {
            return Err(ModelError::Invalid {
                field: "alarm timestamp ordering",
            });
        }
        let mut snapshot = Self {
            identity,
            state,
            state_updated_at,
            configuration_updated_at,
            evaluation,
            metric,
            alarm_digest: Digest::zero(),
        };
        snapshot.alarm_digest = snapshot.recomputed_digest();
        Ok(snapshot)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.identity,
            self.state,
            self.state_updated_at,
            self.configuration_updated_at,
            &self.evaluation,
            &self.metric,
        ))
    }

    pub fn validate_against(&self, scope: &AwsCloudWatchAlarmScope) -> Result<(), ModelError> {
        self.validate_integrity()?;
        if self.identity != scope.alarm || self.metric != scope.metric {
            return Err(ModelError::ScopeMismatch {
                field: "alarm or metric revision",
            });
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.configuration_updated_at > self.state_updated_at
            || self.alarm_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "alarm snapshot digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.alarm_digest.clone()
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricDataAggregate {
    pub metric: MetricIdentity,
    pub window: MetricWindow,
    pub datapoint_count: u32,
    pub minimum: f64,
    pub maximum: f64,
    pub sum: f64,
    pub average: f64,
    pub datapoints_digest: Digest,
    pub aggregate_digest: Digest,
}

impl MetricDataAggregate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metric: MetricIdentity,
        window: MetricWindow,
        datapoint_count: u32,
        minimum: f64,
        maximum: f64,
        sum: f64,
        average: f64,
        datapoints_digest: Digest,
    ) -> Result<Self, ModelError> {
        window.validate()?;
        if datapoint_count == 0
            || usize::try_from(datapoint_count).unwrap_or(usize::MAX) > MAX_DATAPOINTS
        {
            return Err(ModelError::Invalid {
                field: "bounded datapoint count",
            });
        }
        if [minimum, maximum, sum, average]
            .iter()
            .any(|value| !value.is_finite())
        {
            return Err(ModelError::NonFinite {
                field: "datapoint aggregate",
            });
        }
        if minimum > maximum || average < minimum || average > maximum {
            return Err(ModelError::Invalid {
                field: "datapoint aggregate range",
            });
        }
        datapoints_digest.validate()?;
        if datapoints_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "datapoint digest",
            });
        }
        let mut aggregate = Self {
            metric,
            window,
            datapoint_count,
            minimum,
            maximum,
            sum,
            average,
            datapoints_digest,
            aggregate_digest: Digest::zero(),
        };
        aggregate.aggregate_digest = aggregate.recomputed_digest();
        Ok(aggregate)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            &self.metric,
            &self.window,
            self.datapoint_count,
            self.minimum.to_bits(),
            self.maximum.to_bits(),
            self.sum.to_bits(),
            self.average.to_bits(),
            &self.datapoints_digest,
        ))
    }

    pub fn validate_against(&self, scope: &AwsCloudWatchAlarmScope) -> Result<(), ModelError> {
        self.validate_integrity()?;
        if self.metric != scope.metric || self.window != scope.window {
            return Err(ModelError::ScopeMismatch {
                field: "metric identity or bounded window",
            });
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.window.validate().is_err()
            || self.datapoint_count == 0
            || usize::try_from(self.datapoint_count).unwrap_or(usize::MAX) > MAX_DATAPOINTS
            || [self.minimum, self.maximum, self.sum, self.average]
                .iter()
                .any(|value| !value.is_finite())
            || self.minimum > self.maximum
            || self.average < self.minimum
            || self.average > self.maximum
            || self.aggregate_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "metric aggregate digest",
            });
        }
        self.datapoints_digest.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.aggregate_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub request_digest: Digest,
    pub billed_metric_count: u16,
    pub returned_datapoints: u32,
    pub response_bytes: usize,
    pub cost_digest: Digest,
}

impl CostReceipt {
    pub fn new(
        request_digest: Digest,
        billed_metric_count: u16,
        returned_datapoints: u32,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        if billed_metric_count == 0
            || billed_metric_count > 8
            || usize::try_from(returned_datapoints).unwrap_or(usize::MAX) > MAX_DATAPOINTS
            || response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::Invalid {
                field: "bounded cost receipt",
            });
        }
        let cost_digest = Digest::from_parts(
            "hartevo-aws-cloudwatch-cost-receipt/v1",
            &[
                ("request", request_digest.as_str()),
                ("metrics", &billed_metric_count.to_string()),
                ("datapoints", &returned_datapoints.to_string()),
                ("bytes", &response_bytes.to_string()),
            ],
        );
        Ok(Self {
            request_digest,
            billed_metric_count,
            returned_datapoints,
            response_bytes,
            cost_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedRequestReceipt {
    pub operation: AwsCloudWatchOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub cost_digest: Digest,
    pub response_bytes: usize,
    pub attempt: u8,
    pub cursor_digest: Option<Digest>,
    pub receipt_digest: Digest,
}

impl RedactedRequestReceipt {
    pub fn new(
        operation: AwsCloudWatchOperation,
        request_digest: Digest,
        response_digest: Digest,
        cost: &CostReceipt,
        response_bytes: usize,
        attempt: u8,
        cursor_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES || attempt == 0 {
            return Err(ModelError::Invalid {
                field: "redacted request receipt",
            });
        }
        let mut receipt = Self {
            operation,
            request_digest,
            response_digest,
            cost_digest: cost.cost_digest.clone(),
            response_bytes,
            attempt,
            cursor_digest,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        Ok(receipt)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&(
            self.operation,
            &self.request_digest,
            &self.response_digest,
            &self.cost_digest,
            self.response_bytes,
            self.attempt,
            &self.cursor_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.attempt == 0
            || self.receipt_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "request receipt digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchAlarmEvidence {
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub alarm: Option<AlarmSnapshot>,
    pub metric_data: Option<MetricDataAggregate>,
    pub alarm_state: Option<AlarmState>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub window_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub request_receipts: Vec<RedactedRequestReceipt>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub response_bytes: usize,
    pub truncated: bool,
    pub discovery_used: bool,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    status: EvidenceStatus,
    partial_reason: Option<PartialReason>,
    alarm: &'a Option<AlarmSnapshot>,
    metric_data: &'a Option<MetricDataAggregate>,
    alarm_state: Option<AlarmState>,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    query_digest: &'a Digest,
    window_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    request_receipts: &'a [RedactedRequestReceipt],
    provider_errors: &'a [ProviderErrorEvidence],
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    response_bytes: usize,
    truncated: bool,
    discovery_used: bool,
    provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsCloudWatchAlarmEvidence {
    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            status: self.status,
            partial_reason: self.partial_reason.clone(),
            alarm: &self.alarm,
            metric_data: &self.metric_data,
            alarm_state: self.alarm_state,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            query_digest: &self.query_digest,
            window_digest: &self.window_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            request_receipts: &self.request_receipts,
            provider_errors: &self.provider_errors,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            response_bytes: self.response_bytes,
            truncated: self.truncated,
            discovery_used: self.discovery_used,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate(&self, scope: &AwsCloudWatchAlarmScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.window_digest != scope.window.digest()
            || self.permission_digest != scope.permission_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "CloudWatch evidence scope",
            });
        }
        self.validate_digest_only()?;
        if let Some(alarm) = &self.alarm {
            alarm.validate_against(scope)?;
        }
        if let Some(metric_data) = &self.metric_data {
            metric_data.validate_against(scope)?;
        }
        Ok(())
    }

    pub fn validate_digest_only(&self) -> Result<(), ModelError> {
        if self.window_digest.is_zero()
            || self.scope_digest.is_zero()
            || self.permission_digest.is_zero()
            || self.query_digest.is_zero()
            || self.provider_digest.is_zero()
            || self.api_digest.is_zero()
            || self.contract_digest.is_zero()
            || self.request_count > MAX_REQUESTS_PER_READ
            || self.page_count > MAX_PAGES
            || self.retry_count > MAX_RETRIES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.request_receipts.len() > MAX_RECEIPTS
            || self.provider_errors.len() > MAX_PROVIDER_ERRORS
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "CloudWatch evidence digest or authority",
            });
        }
        for receipt in &self.request_receipts {
            receipt.validate()?;
        }
        if let Some(alarm) = &self.alarm {
            alarm.validate_integrity()?;
        }
        if let Some(metric_data) = &self.metric_data {
            metric_data.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        self.status.is_adoptable()
            && self.alarm.is_some()
            && self.metric_data.is_some()
            && self.provider_errors.is_empty()
            && !self.truncated
            && self.page_count > 0
            && self.request_count > 0
            && self.response_bytes > 0
            && !self.request_receipts.is_empty()
            && !self.connected
            && !self.native
            && !self.first_party
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudWatchReadRequest {
    pub discover_metrics: bool,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub max_retries: u8,
    pub scope_digest: Digest,
    pub query_digest: Digest,
}

impl AwsCloudWatchReadRequest {
    pub fn for_scope(scope: &AwsCloudWatchAlarmScope) -> Result<Self, ModelError> {
        Self::bounded(
            scope,
            scope.allow_metric_discovery,
            MAX_PAGES,
            MAX_RESPONSE_BYTES,
            MAX_RETRIES,
        )
    }

    pub fn bounded(
        scope: &AwsCloudWatchAlarmScope,
        discover_metrics: bool,
        max_pages: u16,
        max_response_bytes: usize,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        if discover_metrics != scope.allow_metric_discovery
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "CloudWatch query bounds",
            });
        }
        let request = Self {
            discover_metrics,
            max_pages,
            max_response_bytes,
            max_retries,
            scope_digest: scope.digest(),
            query_digest: Digest::zero(),
        };
        Ok(Self {
            query_digest: digest_serialized(&(
                request.discover_metrics,
                request.max_pages,
                request.max_response_bytes,
                request.max_retries,
                &request.scope_digest,
            )),
            ..request
        })
    }

    pub fn validate_against(&self, scope: &AwsCloudWatchAlarmScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.discover_metrics != scope.allow_metric_discovery
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retries > MAX_RETRIES
            || self.query_digest
                != digest_serialized(&(
                    self.discover_metrics,
                    self.max_pages,
                    self.max_response_bytes,
                    self.max_retries,
                    &self.scope_digest,
                ))
        {
            return Err(ModelError::ScopeMismatch {
                field: "CloudWatch query digest or bounds",
            });
        }
        Ok(())
    }

    pub const fn max_requests(&self) -> u16 {
        MAX_REQUESTS_PER_READ
    }
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded CloudWatch values serialize");
    Digest::from_bytes(&bytes)
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub type AwsCloudWatchAlarmState = AlarmState;
pub type AwsCloudWatchScope = AwsCloudWatchAlarmScope;
pub type CloudWatchMetricIdentity = MetricIdentity;
pub type SigV4SecretReference = SecretReference;
pub type AwsCloudWatchEvidence = AwsCloudWatchAlarmEvidence;
pub type AwsCloudWatchTransportProvenance = TransportProvenance;
pub type AwsCloudWatchProviderErrorEvidence = ProviderErrorEvidence;

// Keep the constants referenced in this module visible to downstream callers
// through the model module as well as the crate root.
pub const CLOUDWATCH_PLUGIN_VERSION: &str = PLUGIN_VERSION;
pub const CLOUDWATCH_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const CLOUDWATCH_API_REVISION: &str = API_REVISION;

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn scope() -> AwsCloudWatchAlarmScope {
        let permission = PermissionSnapshot::readonly(
            PermissionId::new("cloudwatch-read").expect("permission id"),
            Revision::new(1).expect("revision"),
        )
        .expect("permission");
        let metric = MetricIdentity::from_dimensions(
            MetricNamespace::new("AWS/Lambda").expect("namespace"),
            MetricName::new("Errors").expect("metric"),
            "Sum",
            60,
            [("FunctionName", "fixture")],
        )
        .expect("metric");
        AwsCloudWatchAlarmScope::new(
            DeploymentBinding::new(
                DeploymentId::new("deployment").expect("deployment"),
                Revision::new(1).expect("revision"),
            ),
            MissionBinding::new(
                MissionId::new("mission").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectBinding::new(
                ProjectId::new("project").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            WorkProductBinding::new(
                WorkProductId::new("work-product").expect("work product"),
                Revision::new(1).expect("revision"),
            ),
            AwsAccountId::new("123456789012").expect("account"),
            AwsRegion::new("us-east-1").expect("region"),
            AlarmIdentity::new(
                AlarmName::new("fixture-alarm").expect("alarm"),
                Revision::new(1).expect("revision"),
            )
            .expect("identity"),
            metric,
            MetricWindow::new(
                DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
                    .expect("time")
                    .with_timezone(&Utc),
                DateTime::parse_from_rfc3339("2026-08-15T01:00:00Z")
                    .expect("time")
                    .with_timezone(&Utc),
            )
            .expect("window"),
            permission.digest(),
            true,
        )
        .expect("scope")
    }

    #[test]
    fn secret_reference_never_serializes_the_handle() {
        let scope = scope();
        let secret = SecretReference::new("do-not-retain-this", &scope, 1).expect("secret");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("do-not-retain-this"));
        assert!(secret.is_opaque());
    }

    #[test]
    fn dimensions_are_digest_only() {
        let metric = &scope().metric;
        let json = serde_json::to_string(metric).expect("metric JSON");
        assert!(!json.contains("FunctionName"));
        assert!(!json.contains("fixture"));
        assert!(json.contains("dimensionsDigest"));
    }

    #[test]
    fn bounded_windows_reject_large_ranges() {
        let result = MetricWindow::new(
            Utc::now(),
            Utc::now() + Duration::seconds(MAX_WINDOW_SECONDS + 1),
        );
        assert!(result.is_err());
    }
}
