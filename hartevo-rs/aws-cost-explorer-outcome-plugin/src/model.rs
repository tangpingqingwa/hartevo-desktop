use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_COST_EXPLORER_CONSUMER_ID, AWS_COST_EXPLORER_CONTRACT_VERSION,
    AWS_COST_EXPLORER_SCHEMA_VERSION, AWS_COST_EXPLORER_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_TEXT_BYTES: usize = 512;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 8192;
pub(crate) const MAX_FILTER_CLAUSES: usize = 4;
pub(crate) const MAX_FILTER_VALUES: usize = 32;
pub(crate) const MAX_GROUPS: usize = 2;
pub(crate) const MAX_METRICS: usize = 7;
pub(crate) const MAX_PAGE_COUNT: u8 = 16;
pub(crate) const MAX_GROUP_COUNT: u32 = 2048;
pub(crate) const MAX_DIMENSION_VALUE_COUNT: u32 = 2048;
pub(crate) const MAX_EVIDENCE_BYTES: u32 = 4_000_000;
pub(crate) const MAX_RETRY_ATTEMPTS: u8 = 4;
pub(crate) const MAX_COST_PERIOD_DAYS: u32 = 731;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("account id must contain exactly twelve digits")]
    InvalidAccountId,
    #[error("billing-view ARN is malformed or outside the AWS shape")]
    InvalidBillingViewArn,
    #[error("AWS region is malformed")]
    InvalidRegion,
    #[error("date is not a valid YYYY-MM-DD value")]
    InvalidDate,
    #[error("time period must have a later exclusive end")]
    InvalidTimePeriod,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("response digest does not match the response fields")]
    DigestMismatch,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("filter is empty, duplicated, or exceeds the allowlist")]
    InvalidFilter,
    #[error("grouping is empty, duplicated, or exceeds the two-group bound")]
    InvalidGrouping,
    #[error("metric is not allowlisted")]
    InvalidMetric,
    #[error("amount is not a bounded decimal")]
    InvalidAmount,
    #[error("metric unit is empty or malformed")]
    InvalidUnit,
    #[error("objective is invalid")]
    InvalidObjective,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("opaque page token is empty or too large")]
    InvalidPageToken,
    #[error("secret reference is malformed")]
    InvalidSecretReference,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
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

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.chars().all(|character| !character.is_control())
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

string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ObjectiveId);
string_identifier!(PermissionId);
string_identifier!(ProviderId);
string_identifier!(ServiceId);
string_identifier!(ConsumerId);

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

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidAccountId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AccountId").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BillingViewArn(String);

impl BillingViewArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let parts: Vec<&str> = value.split(':').collect();
        let valid_resource = parts.get(5).is_some_and(|resource| {
            let Some(suffix) = resource.strip_prefix("billingview/") else {
                return false;
            };
            !suffix.is_empty()
                && suffix.len() <= 43
                && suffix.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'/' | b':' | b'_' | b'+' | b'=' | b'.' | b'-' | b'@')
                })
        });
        let valid = (20..=2048).contains(&value.len())
            && parts.len() == 6
            && parts[0] == "arn"
            && parts[1].starts_with("aws")
            && parts[1]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            && parts[2] == "billing"
            && parts[3].is_empty()
            && parts[4].len() == 12
            && parts[4].bytes().all(|byte| byte.is_ascii_digit())
            && valid_resource;
        if valid {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidBillingViewArn)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BillingViewArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BillingViewArn")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if (3..=32).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-')
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRegion)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Date(String);

impl Date {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid_shape = bytes.len() == 10
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
        if !valid_shape {
            return Err(ModelError::InvalidDate);
        }
        let year = parse_digits(&bytes[0..4]);
        let month = parse_digits(&bytes[5..7]);
        let day = parse_digits(&bytes[8..10]);
        let valid_calendar = year >= 1970
            && month != 0
            && month <= 12
            && day != 0
            && day <= days_in_month(year, month);
        if valid_calendar {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDate)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn ordinal(&self) -> i64 {
        let bytes = self.0.as_bytes();
        let year = i64::from(parse_digits(&bytes[0..4]));
        let month = parse_digits(&bytes[5..7]);
        let day = parse_digits(&bytes[8..10]);
        let previous_year = year - 1;
        let leap_days = previous_year / 4 - previous_year / 100 + previous_year / 400;
        let month_days: i64 = (1..month)
            .map(|value| i64::from(days_in_month(year as u32, value)))
            .sum();
        365 * previous_year + leap_days + month_days + i64::from(day)
    }
}

impl fmt::Debug for Date {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Date").field(&self.0).finish()
    }
}

fn parse_digits(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TimePeriod {
    start: Date,
    end: Date,
}

impl TimePeriod {
    pub fn new(start: Date, end: Date) -> Result<Self, ModelError> {
        if start.ordinal() < end.ordinal() {
            Ok(Self { start, end })
        } else {
            Err(ModelError::InvalidTimePeriod)
        }
    }

    pub fn start(&self) -> &Date {
        &self.start
    }

    pub fn end(&self) -> &Date {
        &self.end
    }

    pub fn span_days(&self) -> u32 {
        (self.end.ordinal() - self.start.ordinal()) as u32
    }

    pub(crate) fn canonical(&self) -> String {
        format!("{}..{}", self.start.as_str(), self.end.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Granularity {
    Daily,
    Monthly,
    Hourly,
}

impl Granularity {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Daily => "DAILY",
            Self::Monthly => "MONTHLY",
            Self::Hourly => "HOURLY",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CostMetric {
    AmortizedCost,
    BlendedCost,
    NetAmortizedCost,
    NetUnblendedCost,
    NormalizedUsageAmount,
    UnblendedCost,
    UsageQuantity,
}

impl CostMetric {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let normalized: String = value
            .as_ref()
            .chars()
            .filter(|character| !matches!(character, '_' | '-' | ' '))
            .collect::<String>()
            .to_ascii_uppercase();
        match normalized.as_str() {
            "AMORTIZEDCOST" | "AMORTIZEDCOSTS" => Ok(Self::AmortizedCost),
            "BLENDEDCOST" | "BLENDEDCOSTS" => Ok(Self::BlendedCost),
            "NETAMORTIZEDCOST" | "NETAMORTIZEDCOSTS" => Ok(Self::NetAmortizedCost),
            "NETUNBLENDEDCOST" | "NETUNBLENDEDCOSTS" => Ok(Self::NetUnblendedCost),
            "NORMALIZEDUSAGEAMOUNT" => Ok(Self::NormalizedUsageAmount),
            "UNBLENDEDCOST" | "UNBLENDEDCOSTS" => Ok(Self::UnblendedCost),
            "USAGEQUANTITY" => Ok(Self::UsageQuantity),
            _ => Err(ModelError::InvalidMetric),
        }
    }

    pub const fn api_name(self) -> &'static str {
        match self {
            Self::AmortizedCost => "AmortizedCost",
            Self::BlendedCost => "BlendedCost",
            Self::NetAmortizedCost => "NetAmortizedCost",
            Self::NetUnblendedCost => "NetUnblendedCost",
            Self::NormalizedUsageAmount => "NormalizedUsageAmount",
            Self::UnblendedCost => "UnblendedCost",
            Self::UsageQuantity => "UsageQuantity",
        }
    }

    pub const fn forecast_api_name(self) -> &'static str {
        match self {
            Self::AmortizedCost => "AMORTIZED_COST",
            Self::BlendedCost => "BLENDED_COST",
            Self::NetAmortizedCost => "NET_AMORTIZED_COST",
            Self::NetUnblendedCost => "NET_UNBLENDED_COST",
            Self::NormalizedUsageAmount => "NORMALIZED_USAGE_AMOUNT",
            Self::UnblendedCost => "UNBLENDED_COST",
            Self::UsageQuantity => "USAGE_QUANTITY",
        }
    }

    pub const fn is_currency(self) -> bool {
        !matches!(self, Self::NormalizedUsageAmount | Self::UsageQuantity)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MatchOption {
    Equals,
    CaseSensitive,
}

impl MatchOption {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Equals => "EQUALS",
            Self::CaseSensitive => "CASE_SENSITIVE",
        }
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DimensionKey(String);

impl DimensionKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_uppercase();
        if is_allowlisted_dimension(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidFilter)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_resource_id(&self) -> bool {
        self.0 == "RESOURCE_ID"
    }
}

impl fmt::Debug for DimensionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DimensionKey")
            .field(&self.0)
            .finish()
    }
}

fn is_allowlisted_dimension(value: &str) -> bool {
    matches!(
        value,
        "AZ" | "INSTANCE_TYPE"
            | "LEGAL_ENTITY_NAME"
            | "INVOICING_ENTITY"
            | "LINKED_ACCOUNT"
            | "LINKED_ACCOUNT_NAME"
            | "OPERATION"
            | "PLATFORM"
            | "PURCHASE_TYPE"
            | "REGION"
            | "RECORD_TYPE"
            | "SERVICE"
            | "SERVICE_CODE"
            | "TENANCY"
            | "USAGE_TYPE"
            | "USAGE_TYPE_GROUP"
            | "BILLING_ENTITY"
            | "DATABASE_ENGINE"
            | "CACHE_ENGINE"
            | "DEPLOYMENT_OPTION"
            | "INSTANCE_TYPE_FAMILY"
            | "OPERATING_SYSTEM"
            | "SCOPE"
            | "SUBSCRIPTION_ID"
            | "RESOURCE_ID"
    )
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TagKey(String);

impl TagKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_text(&value, 128) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidFilter)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TagKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("TagKey").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FilterClause {
    Dimension {
        key: DimensionKey,
        values: Vec<String>,
        match_option: MatchOption,
    },
    Tag {
        key: TagKey,
        values: Vec<String>,
        match_option: MatchOption,
    },
}

impl FilterClause {
    pub fn dimension(
        key: DimensionKey,
        values: impl IntoIterator<Item = impl Into<String>>,
        match_option: MatchOption,
    ) -> Result<Self, ModelError> {
        let values = normalized_values(values)?;
        Ok(Self::Dimension {
            key,
            values,
            match_option,
        })
    }

    pub fn tag(
        key: TagKey,
        values: impl IntoIterator<Item = impl Into<String>>,
        match_option: MatchOption,
    ) -> Result<Self, ModelError> {
        let values = normalized_values(values)?;
        Ok(Self::Tag {
            key,
            values,
            match_option,
        })
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Dimension {
                key,
                values,
                match_option,
            } => format!(
                "dimension:{}:{}:{:?}",
                key.as_str(),
                values.join("|"),
                match_option
            ),
            Self::Tag {
                key,
                values,
                match_option,
            } => format!("tag:{}:{}:{match_option:?}", key.as_str(), values.join("|")),
        }
    }

    pub fn is_resource_id(&self) -> bool {
        matches!(self, Self::Dimension { key, .. } if key.is_resource_id())
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        let (values, key_is_valid) = match self {
            Self::Dimension { key, values, .. } => (values, is_allowlisted_dimension(key.as_str())),
            Self::Tag { key, values, .. } => (values, valid_text(key.as_str(), 128)),
        };
        if key_is_valid
            && !values.is_empty()
            && values.len() <= MAX_FILTER_VALUES
            && values.iter().all(|value| valid_text(value, MAX_TEXT_BYTES))
        {
            Ok(())
        } else {
            Err(ModelError::InvalidFilter)
        }
    }
}

fn normalized_values(
    values: impl IntoIterator<Item = impl Into<String>>,
) -> Result<Vec<String>, ModelError> {
    let mut values: Vec<String> = values.into_iter().map(Into::into).collect();
    values.sort();
    values.dedup();
    if values.is_empty()
        || values.len() > MAX_FILTER_VALUES
        || values
            .iter()
            .any(|value| !valid_text(value, MAX_TEXT_BYTES))
    {
        Err(ModelError::InvalidFilter)
    } else {
        Ok(values)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CostFilter {
    clauses: Vec<FilterClause>,
}

impl CostFilter {
    pub fn new(clauses: impl IntoIterator<Item = FilterClause>) -> Result<Self, ModelError> {
        let mut clauses: Vec<FilterClause> = clauses.into_iter().collect();
        if clauses.len() > MAX_FILTER_CLAUSES {
            return Err(ModelError::InvalidFilter);
        }
        for clause in &clauses {
            clause.validate()?;
        }
        clauses.sort_by_key(FilterClause::canonical);
        let mut identities = BTreeSet::new();
        if clauses
            .iter()
            .any(|clause| !identities.insert(clause.canonical()))
        {
            return Err(ModelError::InvalidFilter);
        }
        Ok(Self { clauses })
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn clauses(&self) -> &[FilterClause] {
        &self.clauses
    }

    pub(crate) fn canonical(&self) -> String {
        self.clauses
            .iter()
            .map(FilterClause::canonical)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum GroupDefinition {
    Dimension { key: DimensionKey },
    Tag { key: TagKey },
}

impl GroupDefinition {
    pub fn dimension(key: DimensionKey) -> Self {
        Self::Dimension { key }
    }

    pub fn tag(key: TagKey) -> Self {
        Self::Tag { key }
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Dimension { key } => format!("dimension:{}", key.as_str()),
            Self::Tag { key } => format!("tag:{}", key.as_str()),
        }
    }

    pub fn is_resource_id(&self) -> bool {
        matches!(self, Self::Dimension { key } if key.is_resource_id())
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Dimension { key } if is_allowlisted_dimension(key.as_str()) => Ok(()),
            Self::Tag { key } if valid_text(key.as_str(), 128) => Ok(()),
            _ => Err(ModelError::InvalidGrouping),
        }
    }
}

pub fn normalize_grouping(
    groups: impl IntoIterator<Item = GroupDefinition>,
) -> Result<Vec<GroupDefinition>, ModelError> {
    let mut groups: Vec<GroupDefinition> = groups.into_iter().collect();
    if groups.len() > MAX_GROUPS {
        return Err(ModelError::InvalidGrouping);
    }
    for group in &groups {
        group.validate()?;
    }
    groups.sort_by_key(GroupDefinition::canonical);
    let mut identities = BTreeSet::new();
    if groups
        .iter()
        .any(|group| !identities.insert(group.canonical()))
    {
        return Err(ModelError::InvalidGrouping);
    }
    Ok(groups)
}

pub fn normalize_metrics(
    metrics: impl IntoIterator<Item = CostMetric>,
) -> Result<Vec<CostMetric>, ModelError> {
    let mut metrics: Vec<CostMetric> = metrics.into_iter().collect();
    metrics.sort();
    metrics.dedup();
    if metrics.is_empty() || metrics.len() > MAX_METRICS {
        Err(ModelError::InvalidMetric)
    } else {
        Ok(metrics)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceBounds {
    max_pages: u8,
    max_groups: u32,
    max_dimension_values: u32,
    max_bytes: u32,
    max_retries: u8,
}

impl EvidenceBounds {
    pub fn new(
        max_pages: u8,
        max_groups: u32,
        max_dimension_values: u32,
        max_bytes: u32,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        if (1..=MAX_PAGE_COUNT).contains(&max_pages)
            && (1..=MAX_GROUP_COUNT).contains(&max_groups)
            && (1..=MAX_DIMENSION_VALUE_COUNT).contains(&max_dimension_values)
            && (1..=MAX_EVIDENCE_BYTES).contains(&max_bytes)
            && (1..=MAX_RETRY_ATTEMPTS).contains(&max_retries)
        {
            Ok(Self {
                max_pages,
                max_groups,
                max_dimension_values,
                max_bytes,
                max_retries,
            })
        } else {
            Err(ModelError::InvalidBounds)
        }
    }

    pub const fn max_pages(&self) -> u8 {
        self.max_pages
    }

    pub const fn max_groups(&self) -> u32 {
        self.max_groups
    }

    pub const fn max_dimension_values(&self) -> u32 {
        self.max_dimension_values
    }

    pub const fn max_bytes(&self) -> u32 {
        self.max_bytes
    }

    pub const fn max_retries(&self) -> u8 {
        self.max_retries
    }
}

impl Default for EvidenceBounds {
    fn default() -> Self {
        Self {
            max_pages: 8,
            max_groups: 512,
            max_dimension_values: 512,
            max_bytes: 1_000_000,
            max_retries: 3,
        }
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NormalizedAmount(String);

impl NormalizedAmount {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() > 64 || value.is_empty() {
            return Err(ModelError::InvalidAmount);
        }
        let (negative, unsigned) = match value.strip_prefix('-') {
            Some(unsigned) => (true, unsigned),
            None => (false, value.as_str()),
        };
        if unsigned.is_empty() || unsigned.bytes().filter(|byte| *byte == b'.').count() > 1 {
            return Err(ModelError::InvalidAmount);
        }
        let mut parts = unsigned.split('.');
        let integer = parts.next().unwrap_or_default();
        let fraction = parts.next().unwrap_or_default();
        if integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.len() > 12
        {
            return Err(ModelError::InvalidAmount);
        }
        let integer = integer.trim_start_matches('0');
        let integer = if integer.is_empty() { "0" } else { integer };
        let fraction = fraction.trim_end_matches('0');
        let canonical = if fraction.is_empty() {
            integer.to_owned()
        } else {
            format!("{integer}.{fraction}")
        };
        if negative && canonical != "0" {
            Ok(Self(format!("-{canonical}")))
        } else {
            Ok(Self(canonical))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NormalizedAmount")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetricValue {
    amount: NormalizedAmount,
    unit: String,
}

impl MetricValue {
    pub fn new(amount: impl Into<String>, unit: impl Into<String>) -> Result<Self, ModelError> {
        let unit = unit.into().trim().to_ascii_uppercase();
        if !valid_text(&unit, 32)
            || !unit.bytes().all(|byte| {
                byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'/' | b'-' | b'_' | b' ')
            })
        {
            return Err(ModelError::InvalidUnit);
        }
        Ok(Self {
            amount: NormalizedAmount::new(amount)?,
            unit,
        })
    }

    pub fn amount(&self) -> &NormalizedAmount {
        &self.amount
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub(crate) fn canonical(&self) -> String {
        format!("{} {}", self.amount.as_str(), self.unit)
    }
}

impl Default for MetricValue {
    fn default() -> Self {
        Self {
            amount: NormalizedAmount("0".to_owned()),
            unit: "USD".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveKind {
    ReduceSpend,
    KeepBelow,
    InvestigateVariance,
    CompareToForecast,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CostControlObjective {
    id: ObjectiveId,
    kind: ObjectiveKind,
    metric: CostMetric,
    threshold: Option<NormalizedAmount>,
    threshold_bps: Option<u16>,
    objective_digest: Digest,
}

impl CostControlObjective {
    pub fn reduce_spend(id: ObjectiveId, metric: CostMetric) -> Self {
        Self::build(id, ObjectiveKind::ReduceSpend, metric, None, None)
    }

    pub fn keep_below(
        id: ObjectiveId,
        metric: CostMetric,
        threshold: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self::build(
            id,
            ObjectiveKind::KeepBelow,
            metric,
            Some(NormalizedAmount::new(threshold)?),
            None,
        ))
    }

    pub fn investigate_variance(
        id: ObjectiveId,
        metric: CostMetric,
        threshold_bps: u16,
    ) -> Result<Self, ModelError> {
        if threshold_bps == 0 || threshold_bps > 10_000 {
            return Err(ModelError::InvalidObjective);
        }
        Ok(Self::build(
            id,
            ObjectiveKind::InvestigateVariance,
            metric,
            None,
            Some(threshold_bps),
        ))
    }

    pub fn compare_to_forecast(id: ObjectiveId, metric: CostMetric) -> Self {
        Self::build(id, ObjectiveKind::CompareToForecast, metric, None, None)
    }

    fn build(
        id: ObjectiveId,
        kind: ObjectiveKind,
        metric: CostMetric,
        threshold: Option<NormalizedAmount>,
        threshold_bps: Option<u16>,
    ) -> Self {
        let fields = vec![
            id.as_str().to_owned(),
            format!("{kind:?}"),
            metric.api_name().to_owned(),
            threshold
                .as_ref()
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            threshold_bps.map_or_else(String::new, |value| value.to_string()),
        ];
        Self {
            id,
            kind,
            metric,
            threshold,
            threshold_bps,
            objective_digest: Digest::from_fields("aws-cost-objective/v1", &fields),
        }
    }

    pub fn id(&self) -> &ObjectiveId {
        &self.id
    }

    pub const fn kind(&self) -> ObjectiveKind {
        self.kind
    }

    pub const fn metric(&self) -> CostMetric {
        self.metric
    }

    pub fn threshold(&self) -> Option<&NormalizedAmount> {
        self.threshold.as_ref()
    }

    pub const fn threshold_bps(&self) -> Option<u16> {
        self.threshold_bps
    }

    pub fn digest(&self) -> &Digest {
        &self.objective_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsOperation {
    GetCostAndUsage,
    GetUsageForecast,
    GetDimensionValues,
    GetCostAndUsageWithResources,
}

impl AwsOperation {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::GetCostAndUsage => "GetCostAndUsage",
            Self::GetUsageForecast => "GetUsageForecast",
            Self::GetDimensionValues => "GetDimensionValues",
            Self::GetCostAndUsageWithResources => "GetCostAndUsageWithResources",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRegistration {
    permission_id: PermissionId,
    allowed_operations: BTreeSet<AwsOperation>,
    revision: Revision,
    permission_digest: Digest,
    revoked: bool,
}

impl PermissionRegistration {
    pub fn new(
        permission_id: PermissionId,
        allowed_operations: impl IntoIterator<Item = AwsOperation>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let allowed_operations: BTreeSet<AwsOperation> = allowed_operations.into_iter().collect();
        if allowed_operations.is_empty() {
            return Err(ModelError::InvalidRegistration);
        }
        let fields = vec![
            permission_id.as_str().to_owned(),
            revision.get().to_string(),
            allowed_operations
                .iter()
                .map(|operation| operation.api_name())
                .collect::<Vec<_>>()
                .join(","),
        ];
        Ok(Self {
            permission_id,
            allowed_operations,
            revision,
            permission_digest: Digest::from_fields("aws-cost-permission/v1", &fields),
            revoked: false,
        })
    }

    pub fn readonly_default(
        permission_id: PermissionId,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            permission_id,
            [
                AwsOperation::GetCostAndUsage,
                AwsOperation::GetUsageForecast,
                AwsOperation::GetDimensionValues,
            ],
            revision,
        )
    }

    pub fn permission_id(&self) -> &PermissionId {
        &self.permission_id
    }

    pub fn allowed_operations(&self) -> &BTreeSet<AwsOperation> {
        &self.allowed_operations
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn allows(&self, operation: AwsOperation) -> bool {
        !self.revoked && self.allowed_operations.contains(&operation)
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AwsAccountBinding {
    Account { account_id: AccountId },
    BillingView { billing_view_arn: BillingViewArn },
}

impl AwsAccountBinding {
    pub fn account(account_id: AccountId) -> Self {
        Self::Account { account_id }
    }

    pub fn billing_view(billing_view_arn: BillingViewArn) -> Self {
        Self::BillingView { billing_view_arn }
    }

    pub fn account_id(&self) -> Option<&AccountId> {
        match self {
            Self::Account { account_id } => Some(account_id),
            Self::BillingView { .. } => None,
        }
    }

    pub fn billing_view_arn(&self) -> Option<&BillingViewArn> {
        match self {
            Self::Account { .. } => None,
            Self::BillingView { billing_view_arn } => Some(billing_view_arn),
        }
    }

    pub(crate) fn canonical(&self) -> String {
        match self {
            Self::Account { account_id } => format!("account:{}", account_id.as_str()),
            Self::BillingView { billing_view_arn } => {
                format!("billing-view:{}", billing_view_arn.as_str())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsCostExplorerScope {
    project_id: ProjectId,
    mission_id: MissionId,
    work_product_id: WorkProductId,
    mission_revision: Revision,
    account_or_billing_view: AwsAccountBinding,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl AwsCostExplorerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        mission_revision: Revision,
        account_or_billing_view: AwsAccountBinding,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Self {
        let fields = vec![
            project_id.as_str().to_owned(),
            mission_id.as_str().to_owned(),
            work_product_id.as_str().to_owned(),
            mission_revision.get().to_string(),
            account_or_billing_view.canonical(),
            permission_digest.as_str().to_owned(),
            consent_digest.as_str().to_owned(),
        ];
        let scope_digest = Digest::from_fields("aws-cost-scope/v1", &fields);
        Self {
            project_id,
            mission_id,
            work_product_id,
            mission_revision,
            account_or_billing_view,
            permission_digest,
            consent_digest,
            scope_digest,
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn account_or_billing_view(&self) -> &AwsAccountBinding {
        &self.account_or_billing_view
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            mission_revision: self.mission_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
}

impl PermissionFence {
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "aws-cost-fence/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.mission_revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    sigv4_region: AwsRegion,
    sigv4_service: &'static str,
    revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("sigv4_region", &self.sigv4_region)
            .field("sigv4_service", &self.sigv4_service)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsCostExplorerScope,
        credential_revision: Revision,
        sigv4_region: AwsRegion,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_fields(
            "aws-sigv4-secret-reference/v1",
            &[
                reference_id,
                scope.scope_digest().as_str().to_owned(),
                credential_revision.get().to_string(),
                sigv4_region.as_str().to_owned(),
                "ce".to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            sigv4_region,
            sigv4_service: "ce",
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

    pub fn sigv4_region(&self) -> &AwsRegion {
        &self.sigv4_region
    }

    pub const fn sigv4_service(&self) -> &'static str {
        self.sigv4_service
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

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueNextPageToken {
    raw: String,
    digest: Digest,
}

impl OpaqueNextPageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let raw = value.into();
        if raw.is_empty() || raw.len() > MAX_PAGE_TOKEN_BYTES || raw.chars().any(char::is_control) {
            return Err(ModelError::InvalidPageToken);
        }
        let digest = Digest::from_fields("aws-cost-page-token/v1", std::slice::from_ref(&raw));
        Ok(Self { raw, digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaqueNextPageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueNextPageToken")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCostExplorerRegistration {
    schema_version: String,
    contract_version: String,
    service_id: ServiceId,
    provider_id: ProviderId,
    provider_version: String,
    provider_digest: Digest,
    consumer_id: ConsumerId,
    scope_digest: Digest,
    permission_digest: Digest,
    revision: Revision,
    registration_digest: Digest,
    revoked: bool,
}

impl AwsCostExplorerRegistration {
    pub fn new(
        scope: &AwsCostExplorerScope,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        provider_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if !valid_text(&provider_version, 64) {
            return Err(ModelError::InvalidRegistration);
        }
        let fields = vec![
            AWS_COST_EXPLORER_SCHEMA_VERSION.to_owned(),
            AWS_COST_EXPLORER_CONTRACT_VERSION.to_owned(),
            AWS_COST_EXPLORER_SERVICE_ID.to_owned(),
            provider_id.as_str().to_owned(),
            provider_version.clone(),
            provider_digest.as_str().to_owned(),
            AWS_COST_EXPLORER_CONSUMER_ID.to_owned(),
            scope.scope_digest().as_str().to_owned(),
            scope.permission_digest().as_str().to_owned(),
            revision.get().to_string(),
        ];
        Ok(Self {
            schema_version: AWS_COST_EXPLORER_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_COST_EXPLORER_CONTRACT_VERSION.to_owned(),
            service_id: ServiceId::new(AWS_COST_EXPLORER_SERVICE_ID)?,
            provider_id,
            provider_version,
            provider_digest,
            consumer_id: ConsumerId::new(AWS_COST_EXPLORER_CONSUMER_ID)?,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            revision,
            registration_digest: Digest::from_fields("aws-cost-registration/v1", &fields),
            revoked: false,
        })
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn consumer_id(&self) -> &ConsumerId {
        &self.consumer_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            revision: self.revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    AccessDenied,
    NotFound,
    RateLimited,
    Timeout,
    ServerFailure,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Estimated,
    Partial,
    ForecastUnavailable,
    AccessLoss,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    GroupCap,
    DimensionValueCap,
    ByteCap,
    PaginationLoop,
    IncompletePage,
    ProviderRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub operation: AwsOperation,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub attempt: u8,
    pub diagnostic_digest: Digest,
}

pub type MetricMap = BTreeMap<CostMetric, MetricValue>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForecastHorizon {
    period: TimePeriod,
    granularity: Granularity,
}

impl ForecastHorizon {
    pub fn new(period: TimePeriod, granularity: Granularity) -> Result<Self, ModelError> {
        let max_days = match granularity {
            Granularity::Daily => 93,
            Granularity::Monthly => 548,
            Granularity::Hourly => return Err(ModelError::InvalidTimePeriod),
        };
        if period.span_days() <= max_days {
            Ok(Self {
                period,
                granularity,
            })
        } else {
            Err(ModelError::InvalidTimePeriod)
        }
    }

    pub fn period(&self) -> &TimePeriod {
        &self.period
    }

    pub const fn granularity(&self) -> Granularity {
        self.granularity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DimensionValue {
    pub value: String,
    pub attributes: BTreeMap<String, String>,
}

impl DimensionValue {
    pub fn new(
        value: impl Into<String>,
        attributes: BTreeMap<String, String>,
    ) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_text(&value, MAX_TEXT_BYTES)
            || attributes.len() > 8
            || attributes
                .iter()
                .any(|(key, value)| !valid_text(key, 64) || !valid_text(value, MAX_TEXT_BYTES))
        {
            return Err(ModelError::InvalidFilter);
        }
        Ok(Self { value, attributes })
    }
}
