use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    HONEYCOMB_TRACE_RESULT_CONSUMER_ID, HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION,
    HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION, HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION,
    HONEYCOMB_TRACE_RESULT_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CALCULATIONS: usize = 4;
pub const MAX_BREAKDOWNS: usize = 4;
pub const MAX_FILTERS: usize = 8;
pub const MAX_LIMIT: u16 = 1_000;
pub const MAX_QUERY_RANGE_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_RESULT_POINTS: usize = 4_096;
pub const MAX_RESULT_SERIES: usize = 32;
pub const MAX_RETRIES: u8 = 4;
pub const MAX_BACKOFF_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("time window is empty, reversed, or longer than seven days")]
    InvalidTimeWindow,
    #[error("query scope is inconsistent with its dataset or time window")]
    QueryScopeMismatch,
    #[error("required Honeycomb permission is missing")]
    MissingPermission,
    #[error("consent scope is empty or contains a forbidden capability")]
    InvalidConsent,
    #[error("query calculation is not allowed or is not bounded")]
    InvalidCalculation,
    #[error("query field is not on the approved non-sensitive allowlist")]
    InvalidField,
    #[error("query filter is malformed")]
    InvalidFilter,
    #[error("query contains a duplicate field or calculation")]
    DuplicateQueryTerm,
    #[error("query exceeds a Layer-1 bound")]
    QueryBoundExceeded,
    #[error("aggregate result is malformed or exceeds a Layer-1 bound")]
    InvalidAggregateResult,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
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

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
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

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
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

string_identifier!(TeamId);
string_identifier!(EnvironmentId);
string_identifier!(DatasetId);
string_identifier!(QueryId);
string_identifier!(QueryResultId);
string_identifier!(DeploymentId);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

pub type TeamSlug = TeamId;
pub type EnvironmentSlug = EnvironmentId;
pub type DatasetSlug = DatasetId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneycombRegion {
    Us,
    Eu1,
}

pub type Region = HoneycombRegion;

impl HoneycombRegion {
    pub const fn base_url(self) -> &'static str {
        match self {
            Self::Us => "https://api.honeycomb.io",
            Self::Eu1 => "https://api.eu1.honeycomb.io",
        }
    }

    pub const fn api_version(self) -> HoneycombApiVersion {
        HoneycombApiVersion::V1
    }

    pub const fn ui_base_url(self) -> &'static str {
        match self {
            Self::Us => "https://ui.honeycomb.io",
            Self::Eu1 => "https://ui.eu1.honeycomb.io",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::Eu1 => "eu1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneycombApiVersion {
    V1,
    V2,
}

pub type ApiVersion = HoneycombApiVersion;

impl HoneycombApiVersion {
    pub const fn path_prefix(self) -> &'static str {
        match self {
            Self::V1 => "/1",
            Self::V2 => "/2",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "1",
            Self::V2 => "2",
        }
    }

    pub const fn content_type(self) -> &'static str {
        match self {
            Self::V1 => "application/json",
            Self::V2 => "application/vnd.api+json",
        }
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
pub enum HoneycombPermission {
    RunQueries,
    ManageQueries,
}

pub type Permission = HoneycombPermission;

impl HoneycombPermission {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::RunQueries => "Run Queries",
            Self::ManageQueries => "Manage Queries",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionScope {
    permissions: BTreeSet<HoneycombPermission>,
    permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        permissions: impl IntoIterator<Item = HoneycombPermission>,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&HoneycombPermission::RunQueries)
            || !permissions.contains(&HoneycombPermission::ManageQueries)
        {
            return Err(ModelError::MissingPermission);
        }
        let permission_digest = Digest::from_fields(
            "honeycomb-permission-scope/v1",
            &permissions
                .iter()
                .map(|permission| permission.api_name().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    pub fn least_privilege() -> Self {
        Self::new([
            HoneycombPermission::RunQueries,
            HoneycombPermission::ManageQueries,
        ])
        .expect("the two required permissions are always valid")
    }

    pub fn permissions(&self) -> &BTreeSet<HoneycombPermission> {
        &self.permissions
    }

    pub fn contains(&self, permission: HoneycombPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt.permission_digest == self.permission_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentCapability {
    QueryDefinition,
    AggregateQueryResult,
    DeploymentMarkerContext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsentScope {
    purpose_digest: Digest,
    capabilities: BTreeSet<ConsentCapability>,
    consent_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        purpose: impl AsRef<[u8]>,
        capabilities: impl IntoIterator<Item = ConsentCapability>,
    ) -> Result<Self, ModelError> {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() {
            return Err(ModelError::InvalidConsent);
        }
        let purpose_digest = Digest::from_text(purpose);
        let consent_digest = Self::compute_digest(&purpose_digest, &capabilities);
        Ok(Self {
            purpose_digest,
            capabilities,
            consent_digest,
        })
    }

    pub fn aggregate_trace_read_only(purpose: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        Self::new(
            purpose,
            [
                ConsentCapability::QueryDefinition,
                ConsentCapability::AggregateQueryResult,
                ConsentCapability::DeploymentMarkerContext,
            ],
        )
    }

    pub fn purpose_digest(&self) -> &Digest {
        &self.purpose_digest
    }

    pub fn capabilities(&self) -> &BTreeSet<ConsentCapability> {
        &self.capabilities
    }

    pub fn contains(&self, capability: ConsentCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if Self::compute_digest(&self.purpose_digest, &self.capabilities) == self.consent_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        purpose_digest: &Digest,
        capabilities: &BTreeSet<ConsentCapability>,
    ) -> Digest {
        Digest::from_fields(
            "honeycomb-consent-scope/v1",
            &[
                purpose_digest.as_str().to_owned(),
                capabilities
                    .iter()
                    .map(|capability| format!("{capability:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                "raw_events=false".to_owned(),
                "raw_spans=false".to_owned(),
                "raw_logs=false".to_owned(),
                "pii=false".to_owned(),
                "writes=false".to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Project {
    pub id: ProjectId,
    pub revision: Revision,
    pub digest: Digest,
}

impl Project {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "honeycomb-project-scope/v1",
            &[id.as_str().to_owned(), revision.get().to_string()],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "honeycomb-project-scope/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Mission {
    pub id: MissionId,
    pub revision: Revision,
    pub digest: Digest,
}

impl Mission {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "honeycomb-mission-scope/v1",
            &[id.as_str().to_owned(), revision.get().to_string()],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "honeycomb-mission-scope/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: Revision,
    pub digest: Digest,
}

impl WorkProduct {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        let digest = Digest::from_fields(
            "honeycomb-work-product-scope/v1",
            &[id.as_str().to_owned(), revision.get().to_string()],
        );
        Self {
            id,
            revision,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "honeycomb-work-product-scope/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimeWindow {
    start_time: i64,
    end_time: i64,
    window_digest: Digest,
}

impl TimeWindow {
    pub fn new(start_time: i64, end_time: i64) -> Result<Self, ModelError> {
        let duration = end_time
            .checked_sub(start_time)
            .ok_or(ModelError::InvalidTimeWindow)?;
        if start_time < 0 || duration <= 0 || duration > MAX_QUERY_RANGE_SECONDS {
            return Err(ModelError::InvalidTimeWindow);
        }
        let window_digest = Digest::from_fields(
            "honeycomb-time-window/v1",
            &[
                start_time.to_string(),
                end_time.to_string(),
                duration.to_string(),
            ],
        );
        Ok(Self {
            start_time,
            end_time,
            window_digest,
        })
    }

    pub fn from_end_and_range(end_time: i64, range_seconds: i64) -> Result<Self, ModelError> {
        let start_time = end_time
            .checked_sub(range_seconds)
            .ok_or(ModelError::InvalidTimeWindow)?;
        Self::new(start_time, end_time)
    }

    pub const fn start_time(&self) -> i64 {
        self.start_time
    }

    pub const fn end_time(&self) -> i64 {
        self.end_time
    }

    pub const fn duration_seconds(&self) -> i64 {
        self.end_time - self.start_time
    }

    pub fn digest(&self) -> &Digest {
        &self.window_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.start_time, self.end_time)?;
        if rebuilt.window_digest == self.window_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeploymentMarker {
    pub marker_id: DeploymentId,
    pub deployment_id: DeploymentId,
    pub deployment_revision: Revision,
    pub occurred_at: i64,
    pub marker_digest: Digest,
}

impl DeploymentMarker {
    pub fn new(
        marker_id: DeploymentId,
        deployment_id: DeploymentId,
        deployment_revision: Revision,
        occurred_at: i64,
    ) -> Result<Self, ModelError> {
        if occurred_at < 0 {
            return Err(ModelError::InvalidTimeWindow);
        }
        let marker_digest = Digest::from_fields(
            "honeycomb-deployment-marker/v1",
            &[
                marker_id.as_str().to_owned(),
                deployment_id.as_str().to_owned(),
                deployment_revision.get().to_string(),
                occurred_at.to_string(),
            ],
        );
        Ok(Self {
            marker_id,
            deployment_id,
            deployment_revision,
            occurred_at,
            marker_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.marker_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.marker_id.clone(),
            self.deployment_id.clone(),
            self.deployment_revision,
            self.occurred_at,
        )?;
        if rebuilt.marker_digest == self.marker_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedField {
    ServiceName,
    Environment,
    StatusCode,
    Error,
    DurationMs,
    DeploymentId,
    SpanKind,
}

pub type QueryField = ApprovedField;

impl ApprovedField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceName => "service.name",
            Self::Environment => "environment",
            Self::StatusCode => "status_code",
            Self::Error => "error",
            Self::DurationMs => "duration_ms",
            Self::DeploymentId => "deployment.id",
            Self::SpanKind => "span.kind",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "service.name" => Ok(Self::ServiceName),
            "environment" => Ok(Self::Environment),
            "status_code" => Ok(Self::StatusCode),
            "error" => Ok(Self::Error),
            "duration_ms" => Ok(Self::DurationMs),
            "deployment.id" => Ok(Self::DeploymentId),
            "span.kind" => Ok(Self::SpanKind),
            _ => Err(ModelError::InvalidField),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Percentile {
    P50,
    P95,
    P99,
}

impl Percentile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P50 => "P50",
            Self::P95 => "P95",
            Self::P99 => "P99",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Calculation {
    Count,
    Rate,
    ErrorCount,
    ErrorRate,
    P50(ApprovedField),
    P95(ApprovedField),
    P99(ApprovedField),
    LatencyPercentile {
        percentile: Percentile,
        field: ApprovedField,
    },
}

impl Calculation {
    pub const fn p50(field: ApprovedField) -> Self {
        Self::P50(field)
    }

    pub const fn p95(field: ApprovedField) -> Self {
        Self::P95(field)
    }

    pub const fn p99(field: ApprovedField) -> Self {
        Self::P99(field)
    }

    fn canonical(&self) -> String {
        match self {
            Self::Count => "COUNT".to_owned(),
            Self::Rate => "RATE_AVG".to_owned(),
            Self::ErrorCount => "ERROR_COUNT".to_owned(),
            Self::ErrorRate => "ERROR_RATE".to_owned(),
            Self::P50(field) => format!("P50({})", field.as_str()),
            Self::P95(field) => format!("P95({})", field.as_str()),
            Self::P99(field) => format!("P99({})", field.as_str()),
            Self::LatencyPercentile { percentile, field } => {
                format!("{}({})", percentile.as_str(), field.as_str())
            }
        }
    }

    fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Count | Self::Rate | Self::ErrorCount | Self::ErrorRate => Ok(()),
            Self::P50(field)
            | Self::P95(field)
            | Self::P99(field)
            | Self::LatencyPercentile { field, .. }
                if *field == ApprovedField::DurationMs =>
            {
                Ok(())
            }
            Self::P50(_) | Self::P95(_) | Self::P99(_) | Self::LatencyPercentile { .. } => {
                Err(ModelError::InvalidCalculation)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilterCombination {
    And,
    Or,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FilterOperator {
    #[serde(rename = "=")]
    Equals,
    #[serde(rename = "!=")]
    NotEquals,
    #[serde(rename = ">")]
    GreaterThan,
    #[serde(rename = ">=")]
    GreaterThanOrEqual,
    #[serde(rename = "<")]
    LessThan,
    #[serde(rename = "<=")]
    LessThanOrEqual,
    Exists,
    DoesNotExist,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub enum FilterValue {
    TextDigest(Digest),
    Integer(i64),
    Boolean(bool),
}

impl fmt::Debug for FilterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextDigest(digest) => formatter
                .debug_tuple("FilterValue::TextDigest")
                .field(digest)
                .finish(),
            Self::Integer(value) => formatter
                .debug_tuple("FilterValue::Integer")
                .field(value)
                .finish(),
            Self::Boolean(value) => formatter
                .debug_tuple("FilterValue::Boolean")
                .field(value)
                .finish(),
        }
    }
}

impl FilterValue {
    pub fn text(value: impl AsRef<[u8]>) -> Self {
        Self::TextDigest(Digest::from_text(value))
    }

    pub const fn integer(value: i64) -> Self {
        Self::Integer(value)
    }

    pub const fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    fn canonical(&self) -> String {
        match self {
            Self::TextDigest(digest) => format!("text:{}", digest.as_str()),
            Self::Integer(value) => format!("integer:{value}"),
            Self::Boolean(value) => format!("boolean:{value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryFilter {
    pub field: ApprovedField,
    pub operator: FilterOperator,
    pub value: Option<FilterValue>,
}

impl QueryFilter {
    pub fn new(
        field: ApprovedField,
        operator: FilterOperator,
        value: Option<FilterValue>,
    ) -> Result<Self, ModelError> {
        let requires_value = !matches!(
            operator,
            FilterOperator::Exists | FilterOperator::DoesNotExist
        );
        if requires_value != value.is_some() {
            return Err(ModelError::InvalidFilter);
        }
        Ok(Self {
            field,
            operator,
            value,
        })
    }

    pub fn exists(field: ApprovedField) -> Self {
        Self {
            field,
            operator: FilterOperator::Exists,
            value: None,
        }
    }

    fn canonical(&self) -> String {
        format!(
            "{}:{:?}:{}",
            self.field.as_str(),
            self.operator,
            self.value
                .as_ref()
                .map_or_else(|| "none".to_owned(), FilterValue::canonical)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryOrder {
    pub field: Option<ApprovedField>,
    pub calculation: Option<Calculation>,
    pub descending: bool,
}

impl QueryOrder {
    pub fn by_field(field: ApprovedField, descending: bool) -> Self {
        Self {
            field: Some(field),
            calculation: None,
            descending,
        }
    }

    pub fn by_calculation(calculation: Calculation, descending: bool) -> Self {
        Self {
            field: None,
            calculation: Some(calculation),
            descending,
        }
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.field.is_some() == self.calculation.is_some() {
            return Err(ModelError::InvalidCalculation);
        }
        if let Some(calculation) = &self.calculation {
            calculation.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct HoneycombQuery {
    dataset: DatasetId,
    time_window: TimeWindow,
    calculations: Vec<Calculation>,
    breakdowns: Vec<ApprovedField>,
    filters: Vec<QueryFilter>,
    filter_combination: FilterCombination,
    orders: Vec<QueryOrder>,
    limit: u16,
    query_digest: Digest,
}

pub type Query = HoneycombQuery;
pub type QueryAst = HoneycombQuery;
pub type QuerySpecification = HoneycombQuery;

impl fmt::Debug for HoneycombQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HoneycombQuery")
            .field("dataset", &self.dataset)
            .field("time_window", &self.time_window)
            .field("calculations", &self.calculations)
            .field("breakdowns", &self.breakdowns)
            .field("filters", &self.filters)
            .field("filter_combination", &self.filter_combination)
            .field("orders", &self.orders)
            .field("limit", &self.limit)
            .field("query_digest", &self.query_digest)
            .finish()
    }
}

impl HoneycombQuery {
    pub fn new(
        dataset: DatasetId,
        time_window: TimeWindow,
        calculations: Vec<Calculation>,
        breakdowns: Vec<ApprovedField>,
        filters: Vec<QueryFilter>,
        limit: u16,
    ) -> Result<Self, ModelError> {
        Self::with_options(
            dataset,
            time_window,
            calculations,
            breakdowns,
            filters,
            FilterCombination::And,
            Vec::new(),
            limit,
        )
    }

    pub fn with_options(
        dataset: DatasetId,
        time_window: TimeWindow,
        calculations: Vec<Calculation>,
        breakdowns: Vec<ApprovedField>,
        filters: Vec<QueryFilter>,
        filter_combination: FilterCombination,
        orders: Vec<QueryOrder>,
        limit: u16,
    ) -> Result<Self, ModelError> {
        if calculations.is_empty() || calculations.len() > MAX_CALCULATIONS {
            return Err(ModelError::QueryBoundExceeded);
        }
        if breakdowns.len() > MAX_BREAKDOWNS
            || filters.len() > MAX_FILTERS
            || orders.len() > MAX_BREAKDOWNS + MAX_CALCULATIONS
            || !(1..=MAX_LIMIT).contains(&limit)
        {
            return Err(ModelError::QueryBoundExceeded);
        }
        let mut seen_calculations = BTreeSet::new();
        for calculation in &calculations {
            calculation.validate()?;
            if !seen_calculations.insert(calculation.canonical()) {
                return Err(ModelError::DuplicateQueryTerm);
            }
        }
        let mut seen_breakdowns = BTreeSet::new();
        for breakdown in &breakdowns {
            if !seen_breakdowns.insert(breakdown.as_str()) {
                return Err(ModelError::DuplicateQueryTerm);
            }
        }
        for filter in &filters {
            let _ = QueryFilter::new(filter.field, filter.operator, filter.value.clone())?;
        }
        for order in &orders {
            order.validate()?;
        }
        let query_digest = Digest::from_fields(
            "honeycomb-query-ast/v1",
            &[
                dataset.as_str().to_owned(),
                time_window.digest().as_str().to_owned(),
                calculations
                    .iter()
                    .map(Calculation::canonical)
                    .collect::<Vec<_>>()
                    .join(","),
                breakdowns
                    .iter()
                    .map(|field| field.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                filters
                    .iter()
                    .map(QueryFilter::canonical)
                    .collect::<Vec<_>>()
                    .join(","),
                format!("{filter_combination:?}"),
                orders
                    .iter()
                    .map(|order| format!("{order:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                limit.to_string(),
            ],
        );
        Ok(Self {
            dataset,
            time_window,
            calculations,
            breakdowns,
            filters,
            filter_combination,
            orders,
            limit,
            query_digest,
        })
    }

    pub fn dataset(&self) -> &DatasetId {
        &self.dataset
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn calculations(&self) -> &[Calculation] {
        &self.calculations
    }

    pub fn breakdowns(&self) -> &[ApprovedField] {
        &self.breakdowns
    }

    pub fn filters(&self) -> &[QueryFilter] {
        &self.filters
    }

    pub fn filter_combination(&self) -> FilterCombination {
        self.filter_combination
    }

    pub fn orders(&self) -> &[QueryOrder] {
        &self.orders
    }

    pub const fn limit(&self) -> u16 {
        self.limit
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::with_options(
            self.dataset.clone(),
            self.time_window.clone(),
            self.calculations.clone(),
            self.breakdowns.clone(),
            self.filters.clone(),
            self.filter_combination,
            self.orders.clone(),
            self.limit,
        )?;
        if rebuilt.query_digest == self.query_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactionPolicy {
    pub version: String,
    pub denied_fields: Vec<String>,
    pub raw_events: bool,
    pub raw_spans: bool,
    pub raw_logs: bool,
    pub pii: bool,
    pub ui_links: bool,
    pub policy_digest: Digest,
}

impl RedactionPolicy {
    pub fn layer1() -> Self {
        let denied_fields = [
            "trace.id",
            "span.id",
            "parent.id",
            "log.message",
            "log.body",
            "url",
            "user.id",
            "user.email",
            "user.name",
            "request.body",
            "response.body",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let policy_digest = Digest::from_fields("honeycomb-redaction-policy/v1", &denied_fields);
        Self {
            version: "honeycomb-redaction/v1".to_owned(),
            denied_fields,
            raw_events: false,
            raw_spans: false,
            raw_logs: false,
            pii: false,
            ui_links: false,
            policy_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::layer1();
        if self == &expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombTraceScope {
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query: HoneycombQuery,
    pub deployment_marker: DeploymentMarker,
    pub time_window: TimeWindow,
    pub mission: Mission,
    pub project: Project,
    pub work_product: WorkProduct,
    pub consent: ConsentScope,
    pub permissions: PermissionScope,
    pub redaction_policy: RedactionPolicy,
    pub scope_digest: Digest,
}

pub type Scope = HoneycombTraceScope;

impl HoneycombTraceScope {
    pub fn new(
        region: HoneycombRegion,
        team: TeamId,
        environment: EnvironmentId,
        dataset: DatasetId,
        query: HoneycombQuery,
        deployment_marker: DeploymentMarker,
        time_window: TimeWindow,
        mission: Mission,
        project: Project,
        work_product: WorkProduct,
        consent: ConsentScope,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        query.validate()?;
        deployment_marker.validate()?;
        time_window.validate()?;
        mission.validate()?;
        project.validate()?;
        work_product.validate()?;
        consent.validate()?;
        permissions.validate()?;
        if query.dataset() != &dataset || query.time_window() != &time_window {
            return Err(ModelError::QueryScopeMismatch);
        }
        let api_version = region.api_version();
        let redaction_policy = RedactionPolicy::layer1();
        let scope_digest = Digest::from_fields(
            "honeycomb-trace-result-scope/v1",
            &[
                region.as_str().to_owned(),
                api_version.as_str().to_owned(),
                team.as_str().to_owned(),
                environment.as_str().to_owned(),
                dataset.as_str().to_owned(),
                query.query_digest().as_str().to_owned(),
                deployment_marker.digest().as_str().to_owned(),
                time_window.digest().as_str().to_owned(),
                mission.digest.as_str().to_owned(),
                project.digest.as_str().to_owned(),
                work_product.digest.as_str().to_owned(),
                consent.digest().as_str().to_owned(),
                permissions.digest().as_str().to_owned(),
                redaction_policy.digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            region,
            api_version,
            team,
            environment,
            dataset,
            query,
            deployment_marker,
            time_window,
            mission,
            project,
            work_product,
            consent,
            permissions,
            redaction_policy,
            scope_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permissions.digest()
    }

    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }

    pub fn query_digest(&self) -> &Digest {
        self.query.query_digest()
    }

    pub fn fence(&self) -> ScopeFence {
        ScopeFence {
            scope_digest: self.scope_digest.clone(),
            region: self.region,
            api_version: self.api_version,
            team: self.team.clone(),
            environment: self.environment.clone(),
            dataset: self.dataset.clone(),
            query_digest: self.query.query_digest().clone(),
            deployment_marker_digest: self.deployment_marker.digest().clone(),
            time_window_digest: self.time_window.digest().clone(),
            mission_digest: self.mission.digest.clone(),
            project_digest: self.project.digest.clone(),
            work_product_digest: self.work_product.digest.clone(),
            consent_digest: self.consent.digest().clone(),
            permission_digest: self.permissions.digest().clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.query.validate()?;
        self.deployment_marker.validate()?;
        self.time_window.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.consent.validate()?;
        self.permissions.validate()?;
        self.redaction_policy.validate()?;
        if self.query.dataset() != &self.dataset || self.query.time_window() != &self.time_window {
            return Err(ModelError::QueryScopeMismatch);
        }
        let rebuilt = Self::new(
            self.region,
            self.team.clone(),
            self.environment.clone(),
            self.dataset.clone(),
            self.query.clone(),
            self.deployment_marker.clone(),
            self.time_window.clone(),
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
            self.consent.clone(),
            self.permissions.clone(),
        )?;
        if rebuilt.scope_digest == self.scope_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeFence {
    pub scope_digest: Digest,
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query_digest: Digest,
    pub deployment_marker_digest: Digest,
    pub time_window_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
}

/// Opaque reference into a host-owned secret store. The supplied reference id
/// is immediately digested and is never retained, serialized, or printed.
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
        scope: &HoneycombTraceScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        if !valid_identifier(reference_id.as_ref()) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let reference_digest = Digest::from_fields(
            "honeycomb-secret-reference/v1",
            &[
                reference_id.as_ref().to_owned(),
                scope.digest().as_str().to_owned(),
                credential_revision.get().to_string(),
                "configuration_key".to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.digest().clone(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub time_window_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

impl HoneycombRegistration {
    pub fn new(scope: &HoneycombTraceScope, provider_digest: Digest) -> Result<Self, ModelError> {
        let service_id = ServiceId::new(HONEYCOMB_TRACE_RESULT_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let provider_id = ProviderId::new(crate::HONEYCOMB_TRACE_RESULT_PROVIDER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(HONEYCOMB_TRACE_RESULT_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let revision = Revision::new(1)?;
        let plugin_version_digest = Digest::from_text(HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION);
        let contract_digest =
            Digest::from_bytes(crate::HONEYCOMB_TRACE_RESULT_CONTRACT_JSON.as_bytes());
        let registration_digest = Self::compute_digest(
            scope,
            &provider_digest,
            &plugin_version_digest,
            &contract_digest,
            revision,
        );
        Ok(Self {
            schema_version: HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            plugin_version_digest,
            contract_digest,
            provider_digest,
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest().clone(),
            query_digest: scope.query_digest().clone(),
            time_window_digest: scope.time_window.digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            registration_digest,
            revision,
            state: RegistrationState::Active,
        })
    }

    pub fn validate(&self, scope: &HoneycombTraceScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.schema_version != HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION
            || self.contract_version != HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION
            || self.plugin_version != HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION
            || self.scope_digest != *scope.digest()
            || self.permission_digest != *scope.permission_digest()
            || self.query_digest != *scope.query_digest()
            || self.time_window_digest != *scope.time_window.digest()
            || self.consent_digest != *scope.consent_digest()
            || self.service_id.as_str() != HONEYCOMB_TRACE_RESULT_SERVICE_ID
            || self.provider_id.as_str() != crate::HONEYCOMB_TRACE_RESULT_PROVIDER_ID
            || self.consumer_id.as_str() != HONEYCOMB_TRACE_RESULT_CONSUMER_ID
            || self.plugin_version_digest
                != Digest::from_text(HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION)
            || self.contract_digest
                != Digest::from_bytes(crate::HONEYCOMB_TRACE_RESULT_CONTRACT_JSON.as_bytes())
            || self.registration_digest
                != Self::compute_digest(
                    scope,
                    &self.provider_digest,
                    &self.plugin_version_digest,
                    &self.contract_digest,
                    self.revision,
                )
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "honeycomb-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    fn compute_digest(
        scope: &HoneycombTraceScope,
        provider_digest: &Digest,
        plugin_version_digest: &Digest,
        contract_digest: &Digest,
        revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "honeycomb-registration/v1",
            &[
                HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION.to_owned(),
                HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION.to_owned(),
                HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION.to_owned(),
                HONEYCOMB_TRACE_RESULT_SERVICE_ID.to_owned(),
                crate::HONEYCOMB_TRACE_RESULT_PROVIDER_ID.to_owned(),
                HONEYCOMB_TRACE_RESULT_CONSUMER_ID.to_owned(),
                plugin_version_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.digest().as_str().to_owned(),
                scope.query_digest().as_str().to_owned(),
                scope.time_window.digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn durable_receipt(self) -> bool {
        false
    }

    pub const fn outcome(self) -> bool {
        false
    }

    pub const fn work_product_adoption(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryResultState {
    Queued,
    Running,
    Complete,
    Partial,
    Empty,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

pub type ResultState = QueryResultState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AggregateValue {
    Count(u64),
    RateMilliPerSecond(u64),
    ErrorCount(u64),
    ErrorRateBasisPoints(u16),
    LatencyMillis { percentile: Percentile, value: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum DimensionValue {
    TextDigest(Digest),
    Integer(i64),
    Boolean(bool),
}

impl DimensionValue {
    pub fn text(value: impl AsRef<[u8]>) -> Self {
        Self::TextDigest(Digest::from_text(value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregatePoint {
    pub bucket_start: i64,
    pub breakdowns: Vec<DimensionValue>,
    pub values: Vec<AggregateValue>,
    pub point_digest: Digest,
}

impl AggregatePoint {
    pub fn new(
        bucket_start: i64,
        breakdowns: Vec<DimensionValue>,
        values: Vec<AggregateValue>,
    ) -> Result<Self, ModelError> {
        if bucket_start < 0 || values.is_empty() || breakdowns.len() > MAX_BREAKDOWNS {
            return Err(ModelError::InvalidAggregateResult);
        }
        let point_digest = Digest::from_fields(
            "honeycomb-aggregate-point/v1",
            &[
                bucket_start.to_string(),
                format!("{breakdowns:?}"),
                format!("{values:?}"),
            ],
        );
        Ok(Self {
            bucket_start,
            breakdowns,
            values,
            point_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.bucket_start,
            self.breakdowns.clone(),
            self.values.clone(),
        )?;
        if rebuilt.point_digest == self.point_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateSeries {
    pub points: Vec<AggregatePoint>,
    pub series_digest: Digest,
}

impl AggregateSeries {
    pub fn new(points: Vec<AggregatePoint>) -> Result<Self, ModelError> {
        if points.len() > MAX_RESULT_POINTS {
            return Err(ModelError::InvalidAggregateResult);
        }
        if points
            .windows(2)
            .any(|window| window[0].bucket_start >= window[1].bucket_start)
        {
            return Err(ModelError::InvalidAggregateResult);
        }
        let series_digest = Digest::from_fields(
            "honeycomb-aggregate-series/v1",
            &points
                .iter()
                .map(|point| point.point_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            points,
            series_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        for point in &self.points {
            point.validate_digest()?;
        }
        let rebuilt = Self::new(self.points.clone())?;
        if rebuilt.series_digest == self.series_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResultSnapshot {
    pub query_id: QueryId,
    pub query_result_id: QueryResultId,
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub deployment_marker_digest: Digest,
    pub time_window_digest: Digest,
    pub state: QueryResultState,
    pub series: Vec<AggregateSeries>,
    pub error_kind: Option<ProviderErrorKind>,
    pub observed_at: i64,
    pub response_digest: Digest,
    pub redaction_policy_digest: Digest,
    pub result_digest: Digest,
}

impl QueryResultSnapshot {
    pub fn new(
        scope: &HoneycombTraceScope,
        query_id: QueryId,
        query_result_id: QueryResultId,
        state: QueryResultState,
        series: Vec<AggregateSeries>,
        error_kind: Option<ProviderErrorKind>,
        observed_at: i64,
        response_digest: Digest,
    ) -> Result<Self, ModelError> {
        if series.len() > MAX_RESULT_SERIES || observed_at < 0 {
            return Err(ModelError::InvalidAggregateResult);
        }
        if matches!(state, QueryResultState::Complete | QueryResultState::Empty)
            && error_kind.is_some()
        {
            return Err(ModelError::InvalidAggregateResult);
        }
        if matches!(state, QueryResultState::Empty) && series.iter().any(|s| !s.points.is_empty()) {
            return Err(ModelError::InvalidAggregateResult);
        }
        let result_digest = Digest::from_fields(
            "honeycomb-query-result/v1",
            &[
                query_id.as_str().to_owned(),
                query_result_id.as_str().to_owned(),
                scope.region.as_str().to_owned(),
                scope.api_version.as_str().to_owned(),
                scope.team.as_str().to_owned(),
                scope.environment.as_str().to_owned(),
                scope.dataset.as_str().to_owned(),
                scope.digest().as_str().to_owned(),
                scope.query_digest().as_str().to_owned(),
                scope.deployment_marker.digest().as_str().to_owned(),
                scope.time_window.digest().as_str().to_owned(),
                format!("{state:?}"),
                series
                    .iter()
                    .map(|item| item.series_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                error_kind.map_or_else(|| "none".to_owned(), |kind| format!("{kind:?}")),
                observed_at.to_string(),
                response_digest.as_str().to_owned(),
                scope.redaction_policy.digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            query_id,
            query_result_id,
            region: scope.region,
            api_version: scope.api_version,
            team: scope.team.clone(),
            environment: scope.environment.clone(),
            dataset: scope.dataset.clone(),
            scope_digest: scope.digest().clone(),
            query_digest: scope.query_digest().clone(),
            deployment_marker_digest: scope.deployment_marker.digest().clone(),
            time_window_digest: scope.time_window.digest().clone(),
            state,
            series,
            error_kind,
            observed_at,
            response_digest,
            redaction_policy_digest: scope.redaction_policy.digest().clone(),
            result_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.series.len() > MAX_RESULT_SERIES
            || self.observed_at < 0
            || (matches!(
                self.state,
                QueryResultState::Complete | QueryResultState::Empty
            ) && self.error_kind.is_some())
            || (matches!(self.state, QueryResultState::Empty)
                && self.series.iter().any(|series| !series.points.is_empty()))
        {
            return Err(ModelError::InvalidAggregateResult);
        }
        for series in &self.series {
            series.validate_digest()?;
        }
        if self.compute_digest() == self.result_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "honeycomb-query-result/v1",
            &[
                self.query_id.as_str().to_owned(),
                self.query_result_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.api_version.as_str().to_owned(),
                self.team.as_str().to_owned(),
                self.environment.as_str().to_owned(),
                self.dataset.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.deployment_marker_digest.as_str().to_owned(),
                self.time_window_digest.as_str().to_owned(),
                format!("{:?}", self.state),
                self.series
                    .iter()
                    .map(|series| series.series_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                self.error_kind
                    .map_or_else(|| "none".to_owned(), |kind| format!("{kind:?}")),
                self.observed_at.to_string(),
                self.response_digest.as_str().to_owned(),
                self.redaction_policy_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    UnsupportedMediaType,
    RateLimited,
    ServerFailure,
    Timeout,
    RegionMismatch,
    ApiVersionMismatch,
    ScopeDrift,
    QueryDrift,
    Tampered,
    BlockedEnv,
    Unknown,
}
