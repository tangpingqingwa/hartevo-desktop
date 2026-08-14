use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION, KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID,
    KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION, KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID,
    KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_STATISTICS: usize = 16;
pub const MAX_WINDOW_SECONDS: u64 = 31_622_400;
pub const MAX_PAGES: u8 = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_SERIES_POINTS: usize = 366;
pub const MAX_RETRIES: u8 = 4;
pub const MAX_ERRORS: usize = 32;
pub const MAX_COST_UNITS: u32 = 64;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("the Klaviyo scope is invalid")]
    InvalidScope,
    #[error("the permission snapshot is invalid or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the report metric selection is empty, duplicated, or over the allowlist")]
    InvalidMetricSelection,
    #[error("the report window is closed, ordered, and bounded")]
    InvalidWindow,
    #[error("the selected series interval exceeds the bounded point ceiling")]
    InvalidSeriesResolution,
    #[error("{label} exceeded the Layer-1 ceiling of {maximum}")]
    BoundExceeded { label: &'static str, maximum: usize },
    #[error("the campaign or flow metadata is invalid")]
    InvalidMetadata,
    #[error("the report row or aggregate is invalid")]
    InvalidReport,
    #[error("the report response contains raw profile or message content")]
    RawProfileOrContent,
    #[error("the immutable value digest does not match its fields")]
    DigestMismatch,
    #[error("the opaque page cursor is empty or too large")]
    InvalidPageCursor,
    #[error("the registration is invalid")]
    InvalidRegistration,
    #[error("the registration is already revoked")]
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

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_api_revision(value: &str) -> bool {
    value.len() <= 32
        && value.len() >= 8
        && value.as_bytes().get(4) == Some(&b'-')
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || byte == b'-' || byte == b'.' || byte.is_ascii_alphabetic()
        })
}

macro_rules! string_identifier {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { label: $label })
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

string_identifier!(ProjectId, "project id");
string_identifier!(AccountId, "account id");
string_identifier!(CampaignId, "campaign id");
string_identifier!(FlowId, "flow id");
string_identifier!(MetricId, "metric id");
string_identifier!(MissionId, "mission id");
string_identifier!(WorkProductId, "work product id");
string_identifier!(ServiceId, "service id");
string_identifier!(ProviderId, "provider id");
string_identifier!(ConsumerId, "consumer id");

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
pub enum SecretKind {
    PrivateApiKey,
    OAuth,
}

impl SecretKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PrivateApiKey => "private_api_key",
            Self::OAuth => "oauth",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Campaign,
    Flow,
}

impl ResourceKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Campaign => "campaign",
            Self::Flow => "flow",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum ResourceId {
    Campaign(CampaignId),
    Flow(FlowId),
}

impl ResourceId {
    pub fn campaign(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Campaign(CampaignId::new(value)?))
    }

    pub fn flow(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Flow(FlowId::new(value)?))
    }

    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Campaign(_) => ResourceKind::Campaign,
            Self::Flow(_) => ResourceKind::Flow,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Campaign(value) => value.as_str(),
            Self::Flow(value) => value.as_str(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-resource/v1",
            &[self.kind().label().to_owned(), self.id().to_owned()],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Draft,
    Scheduled,
    Sending,
    Sent,
    Cancelled,
    Failed,
    Live,
    Paused,
    Archived,
    Expired,
    Unknown,
}

pub type CampaignStatus = DeliveryState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesInterval {
    Hour,
    Day,
    Week,
    Month,
}

impl SeriesInterval {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hour => "hourly",
            Self::Day => "daily",
            Self::Week => "weekly",
            Self::Month => "monthly",
        }
    }

    pub const fn maximum_points(self) -> usize {
        match self {
            Self::Hour => MAX_SERIES_POINTS,
            Self::Day => MAX_SERIES_POINTS,
            Self::Week => MAX_SERIES_POINTS,
            Self::Month => MAX_SERIES_POINTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Values,
    Series,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Timeframe {
    Last7Days,
    Last30Days,
    Last90Days,
    Last12Months,
}

impl Timeframe {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Last7Days => "last_7_days",
            Self::Last30Days => "last_30_days",
            Self::Last90Days => "last_90_days",
            Self::Last12Months => "last_12_months",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowBound {
    EpochSeconds(u64),
    Timestamp(String),
}

impl From<u64> for WindowBound {
    fn from(value: u64) -> Self {
        Self::EpochSeconds(value)
    }
}

impl From<u32> for WindowBound {
    fn from(value: u32) -> Self {
        Self::EpochSeconds(u64::from(value))
    }
}

impl From<usize> for WindowBound {
    fn from(value: usize) -> Self {
        Self::EpochSeconds(value as u64)
    }
}

impl From<i64> for WindowBound {
    fn from(value: i64) -> Self {
        Self::EpochSeconds(value.max(0) as u64)
    }
}

impl From<i32> for WindowBound {
    fn from(value: i32) -> Self {
        Self::EpochSeconds(value.max(0) as u64)
    }
}

impl From<String> for WindowBound {
    fn from(value: String) -> Self {
        Self::Timestamp(value)
    }
}

impl From<&str> for WindowBound {
    fn from(value: &str) -> Self {
        Self::Timestamp(value.to_owned())
    }
}

impl WindowBound {
    fn canonical(self) -> String {
        match self {
            Self::EpochSeconds(value) => value.to_string(),
            Self::Timestamp(value) => value,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportWindow {
    pub start: String,
    pub end: String,
    pub timeframe: Option<Timeframe>,
    pub interval: SeriesInterval,
    pub window_digest: Digest,
}

impl ReportWindow {
    pub fn new<S, E>(start: S, end: E, interval: SeriesInterval) -> Result<Self, ModelError>
    where
        S: Into<WindowBound>,
        E: Into<WindowBound>,
    {
        let mut window = Self {
            start: start.into().canonical(),
            end: end.into().canonical(),
            timeframe: None,
            interval,
            window_digest: Digest::from_text("uninitialized-window"),
        };
        window.validate_shape()?;
        window.window_digest = window.compute_digest();
        Ok(window)
    }

    pub fn timeframe(timeframe: Timeframe, interval: SeriesInterval) -> Result<Self, ModelError> {
        let label = timeframe.label().to_owned();
        let mut window = Self {
            start: label.clone(),
            end: label,
            timeframe: Some(timeframe),
            interval,
            window_digest: Digest::from_text("uninitialized-window"),
        };
        window.validate_shape()?;
        window.window_digest = window.compute_digest();
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.window_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    pub fn digest(&self) -> &Digest {
        &self.window_digest
    }

    pub fn duration_seconds(&self) -> Option<u64> {
        let start = self
            .start
            .parse::<u64>()
            .ok()
            .or_else(|| parse_timestamp_seconds(&self.start).map(|value| value as u64))?;
        let end = self
            .end
            .parse::<u64>()
            .ok()
            .or_else(|| parse_timestamp_seconds(&self.end).map(|value| value as u64))?;
        end.checked_sub(start)
    }

    pub fn estimated_series_points(&self) -> Option<usize> {
        let seconds = self.duration_seconds()?;
        let interval_seconds = match self.interval {
            SeriesInterval::Hour => 3_600,
            SeriesInterval::Day => 86_400,
            SeriesInterval::Week => 604_800,
            SeriesInterval::Month => 2_592_000,
        };
        Some((seconds / interval_seconds).saturating_add(1) as usize)
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if self.start.is_empty()
            || self.end.is_empty()
            || self.start.len() > MAX_IDENTIFIER_BYTES
            || self.end.len() > MAX_IDENTIFIER_BYTES
            || self.start.chars().any(char::is_control)
            || self.end.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidWindow);
        }
        if let Some(timeframe) = self.timeframe {
            if self.start != timeframe.label() || self.end != timeframe.label() {
                return Err(ModelError::InvalidWindow);
            }
            return Ok(());
        }
        let numeric_start = self.start.parse::<u64>().ok();
        let numeric_end = self.end.parse::<u64>().ok();
        let start = numeric_start
            .or_else(|| parse_timestamp_seconds(&self.start).map(|value| value as u64));
        let end =
            numeric_end.or_else(|| parse_timestamp_seconds(&self.end).map(|value| value as u64));
        match (start, end) {
            (Some(start), Some(end)) => {
                let duration = end.checked_sub(start).ok_or(ModelError::InvalidWindow)?;
                if duration == 0 || duration > MAX_WINDOW_SECONDS {
                    return Err(ModelError::InvalidWindow);
                }
            }
            _ if self.start >= self.end => return Err(ModelError::InvalidWindow),
            _ => {}
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-report-window/v1",
            &[
                self.start.clone(),
                self.end.clone(),
                self.timeframe
                    .map_or_else(|| "custom".to_owned(), |value| value.label().to_owned()),
                self.interval.label().to_owned(),
            ],
        )
    }
}

fn parse_timestamp_seconds(value: &str) -> Option<i64> {
    if value.len() < 19
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }
    let year = value.get(0..4)?.parse::<i64>().ok()?;
    let month = value.get(5..7)?.parse::<u32>().ok()?;
    let day = value.get(8..10)?.parse::<u32>().ok()?;
    let hour = value.get(11..13)?.parse::<u32>().ok()?;
    let minute = value.get(14..16)?.parse::<u32>().ok()?;
    let second = value.get(17..19)?.parse::<u32>().ok()?;
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days.saturating_mul(86_400) + i64::from(hour * 3_600 + minute * 60 + second))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "digest")]
pub enum VariationSelector {
    All,
    Id(Digest),
}

impl VariationSelector {
    pub const fn all() -> Self {
        Self::All
    }

    pub fn by_id(value: impl AsRef<[u8]>) -> Self {
        Self::Id(Digest::from_text(value))
    }

    pub fn digest(&self) -> Digest {
        match self {
            Self::All => Digest::from_text("klaviyo-variation-all/v1"),
            Self::Id(value) => {
                Digest::from_fields("klaviyo-variation-id/v1", &[value.as_str().to_owned()])
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Statistic {
    Sent,
    Delivered,
    Recipients,
    Opens,
    OpenRate,
    Clicks,
    ClickRate,
    Conversions,
    ConversionRate,
    ConversionValue,
    Bounced,
    Unsubscribes,
    SpamComplaints,
    TextMessageSpend,
    TextMessageCreditUsageAmount,
    TextMessageRoi,
}

impl Statistic {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Recipients => "recipients",
            Self::Opens => "opens",
            Self::OpenRate => "open_rate",
            Self::Clicks => "clicks",
            Self::ClickRate => "click_rate",
            Self::Conversions => "conversions",
            Self::ConversionRate => "conversion_rate",
            Self::ConversionValue => "conversion_value",
            Self::Bounced => "bounced",
            Self::Unsubscribes => "unsubscribes",
            Self::SpamComplaints => "spam_complaints",
            Self::TextMessageSpend => "text_message_spend",
            Self::TextMessageCreditUsageAmount => "text_message_credit_usage_amount",
            Self::TextMessageRoi => "text_message_roi",
        }
    }

    pub const fn is_rate(self) -> bool {
        matches!(
            self,
            Self::OpenRate | Self::ClickRate | Self::ConversionRate | Self::TextMessageRoi
        )
    }

    pub const fn is_spend(self) -> bool {
        matches!(
            self,
            Self::TextMessageSpend | Self::TextMessageCreditUsageAmount | Self::ConversionValue
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSelection {
    pub statistics: Vec<Statistic>,
    pub conversion_metric_digest: Option<Digest>,
    pub metric_digest: Digest,
}

impl MetricSelection {
    pub fn new(statistics: impl IntoIterator<Item = Statistic>) -> Result<Self, ModelError> {
        let mut values = statistics.into_iter().collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        if values.is_empty() || values.len() > MAX_STATISTICS {
            return Err(ModelError::InvalidMetricSelection);
        }
        let mut selection = Self {
            statistics: values,
            conversion_metric_digest: None,
            metric_digest: Digest::from_text("uninitialized-metric"),
        };
        selection.metric_digest = selection.compute_digest();
        Ok(selection)
    }

    pub fn with_conversion_metric(mut self, metric: &MetricId) -> Self {
        self.conversion_metric_digest = Some(Digest::from_text(metric.as_str()));
        self.metric_digest = self.compute_digest();
        self
    }

    pub fn contains(&self, statistic: Statistic) -> bool {
        self.statistics.contains(&statistic)
    }

    pub fn digest(&self) -> &Digest {
        &self.metric_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.statistics.is_empty()
            || self.statistics.len() > MAX_STATISTICS
            || self
                .statistics
                .windows(2)
                .any(|window| window[0] >= window[1])
            || self.metric_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidMetricSelection);
        }
        if self.statistics.iter().any(|statistic| {
            matches!(
                statistic,
                Statistic::Conversions | Statistic::ConversionRate | Statistic::ConversionValue
            )
        }) && self.conversion_metric_digest.is_none()
        {
            return Err(ModelError::InvalidMetricSelection);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-report-metrics/v1",
            &[
                self.statistics
                    .iter()
                    .map(|value| value.label())
                    .collect::<Vec<_>>()
                    .join(","),
                self.conversion_metric_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KlaviyoPermission {
    CampaignsRead,
    FlowsRead,
    MetricsRead,
}

impl KlaviyoPermission {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CampaignsRead => "campaigns_read",
            Self::FlowsRead => "flows_read",
            Self::MetricsRead => "metrics_read",
        }
    }

    pub const fn required_for(kind: ResourceKind) -> Self {
        match kind {
            ResourceKind::Campaign => Self::CampaignsRead,
            ResourceKind::Flow => Self::FlowsRead,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub auth_kind: SecretKind,
    pub account_id: AccountId,
    pub api_revision: String,
    pub required_scopes: BTreeSet<KlaviyoPermission>,
    pub revision: Revision,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(
        auth_kind: SecretKind,
        account_id: AccountId,
        api_revision: impl Into<String>,
        required_scopes: impl IntoIterator<Item = KlaviyoPermission>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let mut snapshot = Self {
            auth_kind,
            account_id,
            api_revision: api_revision.into(),
            required_scopes: required_scopes.into_iter().collect(),
            revision,
            permission_digest: Digest::from_text("uninitialized-permission"),
        };
        snapshot.validate_shape()?;
        snapshot.permission_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn least_privilege(
        auth_kind: SecretKind,
        account_id: AccountId,
        resource_kind: ResourceKind,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(
            auth_kind,
            account_id,
            KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
            [
                KlaviyoPermission::required_for(resource_kind),
                KlaviyoPermission::MetricsRead,
            ],
            revision,
        )
    }

    pub fn has(&self, permission: KlaviyoPermission) -> bool {
        self.required_scopes.contains(&permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.permission_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if !valid_api_revision(&self.api_revision)
            || self.api_revision != KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION
            || self.required_scopes.is_empty()
            || !self.has(KlaviyoPermission::MetricsRead)
        {
            return Err(ModelError::InvalidPermissionSnapshot);
        }
        Revision::new(self.revision.get())?;
        if self.required_scopes.len() > 3 {
            return Err(ModelError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-permission-snapshot/v1",
            &[
                self.auth_kind.label().to_owned(),
                self.account_id.as_str().to_owned(),
                self.api_revision.clone(),
                self.required_scopes
                    .iter()
                    .map(|permission| permission.label())
                    .collect::<Vec<_>>()
                    .join(","),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeRevisions {
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub account_revision: Revision,
    pub resource_revision: Revision,
}

impl ScopeRevisions {
    pub const fn new(
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
        account_revision: Revision,
        resource_revision: Revision,
    ) -> Self {
        Self {
            project_revision,
            mission_revision,
            work_product_revision,
            account_revision,
            resource_revision,
        }
    }

    fn validate(&self) -> Result<(), ModelError> {
        for revision in [
            self.project_revision,
            self.mission_revision,
            self.work_product_revision,
            self.account_revision,
            self.resource_revision,
        ] {
            Revision::new(revision.get())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoScope {
    pub project_id: ProjectId,
    pub account_id: AccountId,
    pub resource: ResourceId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub revisions: ScopeRevisions,
    pub api_revision: String,
    pub metrics: MetricSelection,
    pub window: ReportWindow,
    pub variation: VariationSelector,
    pub permission_snapshot: PermissionSnapshot,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
}

impl KlaviyoScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        account_id: AccountId,
        resource: ResourceId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        revisions: ScopeRevisions,
        api_revision: impl Into<String>,
        metrics: MetricSelection,
        window: ReportWindow,
        variation: VariationSelector,
        permission_snapshot: PermissionSnapshot,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project_id,
            account_id,
            resource,
            mission_id,
            work_product_id,
            revisions,
            api_revision: api_revision.into(),
            metrics,
            window,
            variation,
            permission_snapshot,
            consent_digest,
            scope_digest: Digest::from_text("uninitialized-scope"),
        };
        scope.validate_shape()?;
        let scope_digest = scope.compute_digest();
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    pub fn for_campaign(
        project_id: ProjectId,
        account_id: AccountId,
        campaign_id: CampaignId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        revisions: ScopeRevisions,
        metrics: MetricSelection,
        window: ReportWindow,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self, ModelError> {
        Self::new(
            project_id,
            account_id,
            ResourceId::Campaign(campaign_id),
            mission_id,
            work_product_id,
            revisions,
            KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
            metrics,
            window,
            VariationSelector::All,
            permission_snapshot,
            Digest::from_text("klaviyo-consent-bound-scope/v1"),
        )
    }

    pub fn for_flow(
        project_id: ProjectId,
        account_id: AccountId,
        flow_id: FlowId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        revisions: ScopeRevisions,
        metrics: MetricSelection,
        window: ReportWindow,
        permission_snapshot: PermissionSnapshot,
    ) -> Result<Self, ModelError> {
        Self::new(
            project_id,
            account_id,
            ResourceId::Flow(flow_id),
            mission_id,
            work_product_id,
            revisions,
            KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
            metrics,
            window,
            VariationSelector::All,
            permission_snapshot,
            Digest::from_text("klaviyo-consent-bound-scope/v1"),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.scope_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    pub const fn project_revision(&self) -> Revision {
        self.revisions.project_revision
    }

    pub const fn mission_revision(&self) -> Revision {
        self.revisions.mission_revision
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.revisions.work_product_revision
    }

    pub const fn account_revision(&self) -> Revision {
        self.revisions.account_revision
    }

    pub const fn resource_revision(&self) -> Revision {
        self.revisions.resource_revision
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_snapshot.permission_digest.clone(),
            project_revision: self.project_revision(),
            mission_revision: self.mission_revision(),
            work_product_revision: self.work_product_revision(),
            account_revision: self.account_revision(),
            resource_revision: self.resource_revision(),
        }
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if !valid_api_revision(&self.api_revision)
            || self.api_revision != self.permission_snapshot.api_revision
            || self.account_id != self.permission_snapshot.account_id
        {
            return Err(ModelError::InvalidScope);
        }
        self.revisions.validate()?;
        self.metrics.validate()?;
        self.window.validate()?;
        self.permission_snapshot.validate()?;
        if !self
            .permission_snapshot
            .has(KlaviyoPermission::required_for(self.resource.kind()))
            || self.consent_digest.as_str().is_empty()
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-scope/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.account_id.as_str().to_owned(),
                self.resource.kind().label().to_owned(),
                self.resource.id().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.work_product_id.as_str().to_owned(),
                self.project_revision().get().to_string(),
                self.mission_revision().get().to_string(),
                self.work_product_revision().get().to_string(),
                self.account_revision().get().to_string(),
                self.resource_revision().get().to_string(),
                self.api_revision.clone(),
                self.metrics.metric_digest.as_str().to_owned(),
                self.window.window_digest.as_str().to_owned(),
                self.variation.digest().as_str().to_owned(),
                self.permission_snapshot
                    .permission_digest
                    .as_str()
                    .to_owned(),
                self.consent_digest.as_str().to_owned(),
            ],
        )
    }
}

/// An opaque host-owned reference.  The private reference id is hashed at
/// construction and is never serializable or present in debug output.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
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
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &KlaviyoScope,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier {
                label: "secret reference",
            });
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "klaviyo-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                kind.label().to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn private_api_key(
        reference_id: impl Into<String>,
        scope: &KlaviyoScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            SecretKind::PrivateApiKey,
        )
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &KlaviyoScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, scope, credential_revision, SecretKind::OAuth)
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

    pub const fn revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn auth_kind(&self) -> SecretKind {
        self.kind
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
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub account_revision: Revision,
    pub resource_revision: Revision,
}

impl PermissionFence {
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignFlowMetadata {
    pub resource: ResourceId,
    pub state: DeliveryState,
    pub resource_revision: Revision,
    pub metadata_digest: Digest,
}

impl CampaignFlowMetadata {
    pub fn new(resource: ResourceId, state: DeliveryState, resource_revision: Revision) -> Self {
        let metadata_digest = Self::compute_digest(&resource, state, resource_revision);
        Self {
            resource,
            state,
            resource_revision,
            metadata_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Revision::new(self.resource_revision.get())?;
        if self.metadata_digest
            != Self::compute_digest(&self.resource, self.state, self.resource_revision)
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    fn compute_digest(resource: &ResourceId, state: DeliveryState, revision: Revision) -> Digest {
        Digest::from_fields(
            "klaviyo-campaign-flow-metadata/v1",
            &[
                resource.kind().label().to_owned(),
                resource.id().to_owned(),
                format!("{state:?}"),
                revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionEvidence {
    pub profile_fields_redacted: u32,
    pub content_fields_redacted: u32,
    pub raw_profile_payload: bool,
    pub raw_content_payload: bool,
    pub redaction_digest: Digest,
}

impl RedactionEvidence {
    pub fn clean() -> Self {
        Self::new(0, 0)
    }

    pub fn new(profile_fields_redacted: u32, content_fields_redacted: u32) -> Self {
        let mut evidence = Self {
            profile_fields_redacted,
            content_fields_redacted,
            raw_profile_payload: false,
            raw_content_payload: false,
            redaction_digest: Digest::from_text("uninitialized-redaction"),
        };
        evidence.redaction_digest = evidence.compute_digest();
        evidence
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.raw_profile_payload || self.raw_content_payload {
            return Err(ModelError::RawProfileOrContent);
        }
        if self.redaction_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-redaction/v1",
            &[
                self.profile_fields_redacted.to_string(),
                self.content_fields_redacted.to_string(),
                self.raw_profile_payload.to_string(),
                self.raw_content_payload.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostEvidence {
    pub request_units: u32,
    pub response_units: u32,
    pub pages: u8,
    pub rate_limit_per_minute: Option<u16>,
    pub window_digest: Digest,
    pub cost_digest: Digest,
}

impl CostEvidence {
    pub fn new(
        request_units: u32,
        response_units: u32,
        pages: u8,
        rate_limit_per_minute: Option<u16>,
        window_digest: Digest,
    ) -> Result<Self, ModelError> {
        if pages == 0 || pages > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                label: "report pages",
                maximum: MAX_PAGES as usize,
            });
        }
        if request_units > MAX_COST_UNITS || response_units > MAX_COST_UNITS {
            return Err(ModelError::BoundExceeded {
                label: "report cost units",
                maximum: MAX_COST_UNITS as usize,
            });
        }
        let mut evidence = Self {
            request_units,
            response_units,
            pages,
            rate_limit_per_minute,
            window_digest,
            cost_digest: Digest::from_text("uninitialized-cost"),
        };
        evidence.cost_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.pages == 0
            || self.pages > MAX_PAGES
            || self.request_units > MAX_COST_UNITS
            || self.response_units > MAX_COST_UNITS
        {
            return Err(ModelError::BoundExceeded {
                label: "report cost units",
                maximum: MAX_COST_UNITS as usize,
            });
        }
        if self.cost_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-report-cost/v1",
            &[
                self.request_units.to_string(),
                self.response_units.to_string(),
                self.pages.to_string(),
                self.rate_limit_per_minute
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                self.window_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageCursor {
    raw: String,
    cursor_digest: Digest,
}

impl fmt::Debug for OpaquePageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageCursor")
            .field("cursor_digest", &self.cursor_digest)
            .finish_non_exhaustive()
    }
}

impl OpaquePageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let raw = value.into();
        if raw.is_empty() || raw.len() > 4 * 1024 || raw.chars().any(char::is_control) {
            return Err(ModelError::InvalidPageCursor);
        }
        Ok(Self {
            cursor_digest: Digest::from_text(&raw),
            raw,
        })
    }

    pub fn digest(&self) -> Digest {
        self.cursor_digest.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageChannel {
    Email,
    Sms,
    MobilePush,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AggregateValue {
    Count {
        value: u64,
    },
    Rate {
        numerator: u64,
        denominator: u64,
    },
    Money {
        minor_units: i64,
        currency: CurrencyCode,
    },
    Missing,
}

impl Eq for AggregateValue {}

impl AggregateValue {
    pub fn count(value: u64) -> Self {
        Self::Count { value }
    }

    pub fn rate(numerator: u64, denominator: u64) -> Result<Self, ModelError> {
        if denominator == 0 || numerator > denominator {
            Err(ModelError::InvalidReport)
        } else {
            Ok(Self::Rate {
                numerator,
                denominator,
            })
        }
    }

    pub fn rate_from_fraction(value: f64) -> Result<Self, ModelError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(ModelError::InvalidReport);
        }
        let denominator = 1_000_000_u64;
        let numerator = (value * denominator as f64).round() as u64;
        Self::rate(numerator, denominator)
    }

    pub fn money(minor_units: i64, currency: CurrencyCode) -> Self {
        Self::Money {
            minor_units,
            currency,
        }
    }

    pub fn validate(&self, statistic: Statistic) -> Result<(), ModelError> {
        match (statistic.is_rate(), self) {
            (
                true,
                Self::Rate {
                    numerator,
                    denominator,
                },
            ) if *denominator > 0 && numerator <= denominator => {}
            (true, Self::Missing) => {}
            (false, Self::Count { .. } | Self::Money { .. } | Self::Missing) => {}
            _ => return Err(ModelError::InvalidReport),
        }
        if matches!(
            statistic,
            Statistic::TextMessageSpend
                | Statistic::TextMessageCreditUsageAmount
                | Statistic::ConversionValue
        ) && !matches!(self, Self::Money { .. } | Self::Missing)
        {
            return Err(ModelError::InvalidReport);
        }
        if matches!(statistic, Statistic::TextMessageRoi)
            && !matches!(self, Self::Rate { .. } | Self::Missing)
        {
            return Err(ModelError::InvalidReport);
        }
        Ok(())
    }

    pub fn combine(&self, other: &Self) -> Result<Self, ModelError> {
        match (self, other) {
            (Self::Missing, value) | (value, Self::Missing) => Ok(value.clone()),
            (Self::Count { value: left }, Self::Count { value: right }) => {
                Ok(Self::count(left.saturating_add(*right)))
            }
            (
                Self::Rate {
                    numerator: left_numerator,
                    denominator: left_denominator,
                },
                Self::Rate {
                    numerator: right_numerator,
                    denominator: right_denominator,
                },
            ) => {
                let numerator = left_numerator
                    .saturating_mul(*right_denominator)
                    .saturating_add(right_numerator.saturating_mul(*left_denominator));
                let denominator = left_denominator
                    .saturating_mul(*right_denominator)
                    .saturating_mul(2);
                Ok(Self::Rate {
                    numerator,
                    denominator,
                })
            }
            (
                Self::Money {
                    minor_units: left,
                    currency: left_currency,
                },
                Self::Money {
                    minor_units: right,
                    currency: right_currency,
                },
            ) if left_currency == right_currency => Ok(Self::Money {
                minor_units: left.saturating_add(*right),
                currency: left_currency.clone(),
            }),
            _ => Err(ModelError::InvalidReport),
        }
    }

    pub fn as_count(&self) -> Option<u64> {
        match self {
            Self::Count { value } => Some(*value),
            _ => None,
        }
    }

    pub fn as_money(&self) -> Option<(i64, &CurrencyCode)> {
        match self {
            Self::Money {
                minor_units,
                currency,
            } => Some((*minor_units, currency)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_uppercase();
        if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier {
                label: "currency code",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRow {
    pub variation_digest: Option<Digest>,
    pub channel: Option<MessageChannel>,
    pub statistics: BTreeMap<Statistic, AggregateValue>,
    pub row_digest: Digest,
}

impl Eq for ReportRow {}

impl ReportRow {
    pub fn new(
        variation_digest: Option<Digest>,
        channel: Option<MessageChannel>,
        statistics: impl IntoIterator<Item = (Statistic, AggregateValue)>,
    ) -> Result<Self, ModelError> {
        let statistics = statistics.into_iter().collect::<BTreeMap<_, _>>();
        let mut row = Self {
            variation_digest,
            channel,
            statistics,
            row_digest: Digest::from_text("uninitialized-row"),
        };
        row.validate_shape()?;
        row.row_digest = row.compute_digest();
        Ok(row)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.row_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if self.statistics.is_empty() || self.statistics.len() > MAX_STATISTICS {
            return Err(ModelError::InvalidReport);
        }
        for (statistic, value) in &self.statistics {
            value.validate(*statistic)?;
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-report-row/v1",
            &[
                self.variation_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                self.channel
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
                serde_json::to_string(&self.statistics).expect("typed aggregate map serializes"),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportPage {
    pub report_kind: ReportKind,
    pub account_id: AccountId,
    pub resource: ResourceId,
    pub report_digest: Digest,
    pub page_number: u8,
    pub rows: Vec<ReportRow>,
    pub next_cursor: Option<OpaquePageCursor>,
    pub complete: bool,
    pub no_data: bool,
    pub expired: bool,
    pub observed_fence: PermissionFence,
    pub observed_window_digest: Digest,
    pub observed_metric_digest: Digest,
    pub observed_variation_digest: Digest,
    pub cost: CostEvidence,
    pub redaction: RedactionEvidence,
    pub page_digest: Digest,
}

impl ReportPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        report_kind: ReportKind,
        account_id: AccountId,
        resource: ResourceId,
        report_digest: Digest,
        page_number: u8,
        rows: Vec<ReportRow>,
        next_cursor: Option<OpaquePageCursor>,
        complete: bool,
        no_data: bool,
        expired: bool,
        observed_fence: PermissionFence,
        observed_window_digest: Digest,
        observed_metric_digest: Digest,
        observed_variation_digest: Digest,
        cost: CostEvidence,
        redaction: RedactionEvidence,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > MAX_PAGES || rows.len() > MAX_PAGE_SIZE as usize {
            return Err(ModelError::BoundExceeded {
                label: "report page",
                maximum: MAX_PAGE_SIZE as usize,
            });
        }
        for row in &rows {
            row.validate()?;
        }
        if no_data && !rows.is_empty() {
            return Err(ModelError::InvalidReport);
        }
        cost.validate()?;
        redaction.validate()?;
        let mut page = Self {
            report_kind,
            account_id,
            resource,
            report_digest,
            page_number,
            rows,
            next_cursor,
            complete,
            no_data,
            expired,
            observed_fence,
            observed_window_digest,
            observed_metric_digest,
            observed_variation_digest,
            cost,
            redaction,
            page_digest: Digest::from_text("uninitialized-page"),
        };
        page.page_digest = page.compute_digest();
        Ok(page)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_number == 0
            || self.page_number > MAX_PAGES
            || self.rows.len() > MAX_PAGE_SIZE as usize
        {
            return Err(ModelError::InvalidReport);
        }
        for row in &self.rows {
            row.validate()?;
        }
        self.cost.validate()?;
        self.redaction.validate()?;
        if self.no_data && !self.rows.is_empty() {
            return Err(ModelError::InvalidReport);
        }
        if self.page_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.validate()
    }

    pub fn next_cursor_digest(&self) -> Option<Digest> {
        self.next_cursor.as_ref().map(OpaquePageCursor::digest)
    }

    fn compute_digest(&self) -> Digest {
        let row_digest = self
            .rows
            .iter()
            .map(|row| row.row_digest.as_str())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_fields(
            "klaviyo-report-page/v1",
            &[
                format!("{:?}", self.report_kind),
                self.account_id.as_str().to_owned(),
                self.resource.kind().label().to_owned(),
                self.resource.id().to_owned(),
                self.report_digest.as_str().to_owned(),
                self.page_number.to_string(),
                row_digest,
                self.next_cursor_digest()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                self.complete.to_string(),
                self.no_data.to_string(),
                self.expired.to_string(),
                serde_json::to_string(&self.observed_fence).expect("permission fence serializes"),
                self.observed_window_digest.as_str().to_owned(),
                self.observed_metric_digest.as_str().to_owned(),
                self.observed_variation_digest.as_str().to_owned(),
                self.cost.cost_digest.as_str().to_owned(),
                self.redaction.redaction_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized401,
    Forbidden403,
    NotFound404,
    Conflict409,
    RateLimited429,
    Server5xx,
    Timeout,
    BlockedEnv,
    InvalidResponse,
    Unknown,
}

impl ProviderErrorKind {
    pub const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited429 | Self::Server5xx | Self::Timeout)
    }

    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::Unauthorized401 => Some(401),
            Self::Forbidden403 => Some(403),
            Self::NotFound404 => Some(404),
            Self::Conflict409 => Some(409),
            Self::RateLimited429 => Some(429),
            Self::Server5xx => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::InvalidResponse | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    Warning,
    Final,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub attempt: u8,
    pub blocked_env: bool,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub(crate) fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        attempt: u8,
        blocked_env: bool,
        diagnostic_digest: &Digest,
    ) -> Self {
        let error_digest = Digest::from_fields(
            "klaviyo-provider-error/v1",
            &[
                format!("{kind:?}"),
                status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                retryable.to_string(),
                attempt.to_string(),
                blocked_env.to_string(),
                diagnostic_digest.as_str().to_owned(),
            ],
        );
        Self {
            kind,
            status_code,
            retryable,
            attempt,
            blocked_env,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub metadata_digest: Digest,
    pub query_digest: Digest,
    pub report_digest: Digest,
    pub window_digest: Digest,
    pub metric_digest: Digest,
    pub cost_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub implementation_digest: Digest,
    pub contract_digest: Digest,
    pub result_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoRegistration {
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub implementation_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub active: bool,
    pub registration_digest: Digest,
}

impl KlaviyoRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_digest: Digest,
        implementation_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        secret_reference_digest: Digest,
        registration_revision: Revision,
        contract_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut registration = Self {
            service_id: ServiceId::new(KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID)?,
            provider_id: ProviderId::new(KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID)?,
            consumer_id: ConsumerId::new(KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID)?,
            contract_version: KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_digest,
            implementation_digest,
            scope_digest,
            permission_digest,
            secret_reference_digest,
            registration_revision,
            active: true,
            registration_digest: Digest::from_text("uninitialized-registration"),
        };
        registration.validate_shape()?;
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if !self.active {
            return Err(ModelError::AlreadyRevoked);
        }
        self.active = false;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            revocation_digest: Digest::from_fields(
                "klaviyo-registration-revocation/v1",
                &[
                    self.registration_digest.as_str().to_owned(),
                    "revoked".to_owned(),
                ],
            ),
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.registration_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if self.contract_version != KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION {
            return Err(ModelError::InvalidRegistration);
        }
        Revision::new(self.registration_revision.get())?;
        for digest in [
            &self.contract_digest,
            &self.provider_digest,
            &self.implementation_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
        ] {
            if !is_digest(digest.as_str()) {
                return Err(ModelError::InvalidRegistration);
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-registration/v1",
            &[
                self.service_id.as_str().to_owned(),
                self.provider_id.as_str().to_owned(),
                self.consumer_id.as_str().to_owned(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.implementation_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub revocation_digest: Digest,
}
