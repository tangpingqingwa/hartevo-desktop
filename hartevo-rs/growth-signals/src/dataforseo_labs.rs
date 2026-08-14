//! DataForSEO Labs `keywords_for_site/live` read adapter.
//!
//! DataForSEO Labs is estimate evidence. A successful authenticated probe only
//! proves the Basic-auth account and the exact Connector scope; it never turns
//! keyword estimates into first-party account facts.

use std::{
    collections::BTreeMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration as StdDuration,
};

use chrono::{DateTime, Duration, NaiveDate, Utc};
use hartevo_connector_sdk::{
    AuthSession, BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorDescriptor,
    ConnectorError, ConnectorScope, ConnectorWorker, CredentialLease, Cursor, DispatchBudget,
    ExecuteRequest, FreshnessWindow, LiveProbeFence, PrepareEffectRequest, PreparedEffect,
    ProbeObservation, ProbeRequest, ProbeResult, ProbeStatus, ProviderAdapterIdentity,
    ProviderAdapterRegistry, ProviderCapabilityKey, ProviderProvenanceClass, ReadObservation,
    ReadRequest, ReceiptCandidate, ReconcileRequest, ReconciliationObservation, RefreshAuthRequest,
    RevokeRequest, SecretReference, VerificationObservation, VerifyRequest, WebhookObservation,
    WebhookRequest,
};
use reqwest::blocking::Client;
use rust_decimal::{Decimal, prelude::ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    DATAFORSEO_API_BASE_URL, DATAFORSEO_API_VERSION, DATAFORSEO_LABS_ADAPTER_ID,
    DATAFORSEO_LABS_ADAPTER_VERSION, DATAFORSEO_LABS_KEYWORDS_FOR_SITE_PATH,
    DATAFORSEO_LABS_READ_CAPABILITY, DATAFORSEO_LABS_READ_CONTRACT_JSON,
    DATAFORSEO_LABS_STATUS_PATH, DATAFORSEO_PROVIDER_ID, DATAFORSEO_USER_DATA_PATH,
};

const MAX_KEYWORD_PAGE_SIZE: u32 = 1_000;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_TOKEN_LENGTH: usize = 4_096;
const DEFAULT_RESULT_TTL_SECONDS: i64 = 900;
const DEFAULT_PROBE_TTL_SECONDS: i64 = 90;
const DATAFORSEO_OK: i64 = 20_000;

/// The provider dataset window represented by the typed signal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoTimeWindow {
    start: NaiveDate,
    end: NaiveDate,
}

impl DataForSeoTimeWindow {
    pub fn new(start: NaiveDate, end: NaiveDate) -> Result<Self, DataForSeoError> {
        if start > end {
            return Err(DataForSeoError::InvalidRequest);
        }
        Ok(Self { start, end })
    }

    pub const fn start(&self) -> NaiveDate {
        self.start
    }

    pub const fn end(&self) -> NaiveDate {
        self.end
    }
}

/// A bounded request for one DataForSEO Labs keyword observation page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoKeywordRequest {
    scope: ConnectorScope,
    target_domain: String,
    market: String,
    location_code: u32,
    language_code: String,
    time_window: DataForSeoTimeWindow,
    limit: u32,
    include_subdomains: bool,
    include_clickstream_data: bool,
    estimated_cost_usd: Decimal,
    max_cost_usd: Decimal,
}

impl DataForSeoKeywordRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ConnectorScope,
        target_domain: impl Into<String>,
        market: impl Into<String>,
        location_code: u32,
        language_code: impl Into<String>,
        time_window: DataForSeoTimeWindow,
        limit: u32,
        include_subdomains: bool,
        include_clickstream_data: bool,
        estimated_cost_usd: Decimal,
        max_cost_usd: Decimal,
    ) -> Result<Self, DataForSeoError> {
        let target_domain = target_domain.into().trim().to_ascii_lowercase();
        let market = market.into();
        let language_code = language_code.into();
        let request = Self {
            scope,
            target_domain,
            market,
            location_code,
            language_code,
            time_window,
            limit,
            include_subdomains,
            include_clickstream_data,
            estimated_cost_usd,
            max_cost_usd,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn target_domain(&self) -> &str {
        &self.target_domain
    }

    pub fn market(&self) -> &str {
        &self.market
    }

    pub const fn location_code(&self) -> u32 {
        self.location_code
    }

    pub fn language_code(&self) -> &str {
        &self.language_code
    }

    pub const fn time_window(&self) -> &DataForSeoTimeWindow {
        &self.time_window
    }

    pub const fn limit(&self) -> u32 {
        self.limit
    }

    pub const fn include_subdomains(&self) -> bool {
        self.include_subdomains
    }

    pub const fn include_clickstream_data(&self) -> bool {
        self.include_clickstream_data
    }

    pub const fn estimated_cost_usd(&self) -> Decimal {
        self.estimated_cost_usd
    }

    pub const fn max_cost_usd(&self) -> Decimal {
        self.max_cost_usd
    }

    /// The digest binds business scope and provider selector, never secret bytes.
    pub fn request_digest(&self) -> String {
        digest_json(self).unwrap_or_else(|_| sha256_bytes(self.target_domain.as_bytes()))
    }

    pub fn estimate_only_evidence(&self) -> DataForSeoEstimateEvidence {
        DataForSeoEstimateEvidence {
            request_digest: self.request_digest(),
            estimated_cost_usd: self.estimated_cost_usd,
            classification: DataForSeoEvidenceClassification::ProviderEstimate,
            first_party: false,
        }
    }

    fn provider_body(&self, cursor: Option<&DataForSeoCursor>) -> Value {
        let mut body = json!({
            "target": self.target_domain,
            "location_code": self.location_code,
            "language_code": self.language_code,
            "include_subdomains": self.include_subdomains,
            "include_clickstream_data": self.include_clickstream_data,
            "limit": self.limit,
            "order_by": ["relevance,desc"]
        });
        if let Some(cursor) = cursor {
            if let Some(token) = cursor.offset_token() {
                body["offset_token"] = Value::String(token.to_owned());
            } else {
                body["offset"] = json!(cursor.offset());
            }
        } else {
            body["offset"] = json!(0_u32);
        }
        body
    }

    fn validate(&self) -> Result<(), DataForSeoError> {
        if self.scope.provider_id() != DATAFORSEO_PROVIDER_ID
            || self.scope.scopes().is_empty()
            || self.target_domain.is_empty()
            || self.target_domain.len() > MAX_DOMAIN_LENGTH
            || self.target_domain.contains("://")
            || self.target_domain.contains('/')
            || self.target_domain.contains(char::is_whitespace)
            || !self
                .target_domain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            || !valid_token(&self.market, 2, 32)
            || self.location_code == 0
            || !valid_token(&self.language_code, 2, 16)
            || !(1..=MAX_KEYWORD_PAGE_SIZE).contains(&self.limit)
            || self.estimated_cost_usd.is_sign_negative()
            || self.max_cost_usd.is_sign_negative()
            || self.estimated_cost_usd > self.max_cost_usd
        {
            return Err(DataForSeoError::InvalidRequest);
        }
        Ok(())
    }
}

/// DataForSEO's live endpoint returns a task identifier even though the
/// keyword result is returned synchronously. We retain it as a receipt
/// reference without inventing a standard-task claim for this Labs endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DataForSeoTaskId(String);

impl DataForSeoTaskId {
    pub fn new(value: impl Into<String>) -> Result<Self, DataForSeoError> {
        let value = value.into();
        let uuid = Uuid::parse_str(&value).map_err(|_| DataForSeoError::InvalidTaskId)?;
        Ok(Self(uuid.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DataForSeoTaskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoExecutionMode {
    Live,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoEvidenceClassification {
    ProviderEstimate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoEstimateEvidence {
    request_digest: String,
    estimated_cost_usd: Decimal,
    classification: DataForSeoEvidenceClassification,
    first_party: bool,
}

impl DataForSeoEstimateEvidence {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn estimated_cost_usd(&self) -> Decimal {
        self.estimated_cost_usd
    }

    pub const fn classification(&self) -> DataForSeoEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoRateLimit {
    limit_per_minute: Option<u64>,
    remaining: Option<u64>,
    reset_at: Option<DateTime<Utc>>,
}

impl DataForSeoRateLimit {
    fn from_headers(headers: &BTreeMap<String, String>, now: DateTime<Utc>) -> Self {
        let reset_at = headers
            .get("x-ratelimit-reset")
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| {
                if value > 1_000_000_000 {
                    DateTime::<Utc>::from_timestamp(value, 0)
                } else {
                    now.checked_add_signed(Duration::seconds(value.max(0)))
                }
            });
        Self {
            limit_per_minute: header_u64(headers, "x-ratelimit-limit"),
            remaining: header_u64(headers, "x-ratelimit-remaining"),
            reset_at,
        }
    }

    pub const fn limit_per_minute(&self) -> Option<u64> {
        self.limit_per_minute
    }

    pub const fn remaining(&self) -> Option<u64> {
        self.remaining
    }

    pub const fn reset_at(&self) -> Option<DateTime<Utc>> {
        self.reset_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoQuota {
    provider_limit: Option<u64>,
    provider_used: Option<u64>,
    local_limit: u64,
    local_used: u64,
}

impl DataForSeoQuota {
    pub const fn provider_limit(&self) -> Option<u64> {
        self.provider_limit
    }

    pub const fn provider_used(&self) -> Option<u64> {
        self.provider_used
    }

    pub const fn local_limit(&self) -> u64 {
        self.local_limit
    }

    pub const fn local_used(&self) -> u64 {
        self.local_used
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoUsage {
    provider_cost_usd: Decimal,
    estimated_cost_usd: Decimal,
    charged: bool,
    attempts: u8,
    rate_limit: DataForSeoRateLimit,
    quota: DataForSeoQuota,
}

impl DataForSeoUsage {
    pub const fn provider_cost_usd(&self) -> Decimal {
        self.provider_cost_usd
    }

    pub const fn estimated_cost_usd(&self) -> Decimal {
        self.estimated_cost_usd
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn rate_limit(&self) -> &DataForSeoRateLimit {
        &self.rate_limit
    }

    pub const fn quota(&self) -> &DataForSeoQuota {
        &self.quota
    }
}

/// Free authenticated `/appendix/user_data` evidence. The login is retained
/// only as a digest, never as a durable field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoAccountProbe {
    scope: ConnectorScope,
    status: ProbeStatus,
    provenance_class: ProviderProvenanceClass,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evidence_digest: String,
    raw_evidence_digest: String,
    account_login_digest: String,
    rate_limit: DataForSeoRateLimit,
    cost_usd: Decimal,
}

impl DataForSeoAccountProbe {
    pub const fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub fn account_login_digest(&self) -> &str {
        &self.account_login_digest
    }

    pub const fn rate_limit(&self) -> &DataForSeoRateLimit {
        &self.rate_limit
    }

    pub const fn cost_usd(&self) -> Decimal {
        self.cost_usd
    }

    pub fn sdk_observation(&self) -> Result<ProbeObservation, ConnectorError> {
        ProbeObservation::new(
            self.status,
            self.provenance_class,
            self.observed_at,
            self.expires_at,
            self.evidence_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoLabsStatus {
    google_date_update: Option<NaiveDate>,
    bing_date_update: Option<NaiveDate>,
    amazon_date_update: Option<NaiveDate>,
    raw_evidence_digest: String,
    source_revision: u64,
    observed_at: DateTime<Utc>,
    cost_usd: Decimal,
}

impl DataForSeoLabsStatus {
    pub fn google_date_update(&self) -> Option<NaiveDate> {
        self.google_date_update
    }

    pub fn bing_date_update(&self) -> Option<NaiveDate> {
        self.bing_date_update
    }

    pub fn amazon_date_update(&self) -> Option<NaiveDate> {
        self.amazon_date_update
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn cost_usd(&self) -> Decimal {
        self.cost_usd
    }
}

/// Durable provider cursor. The SDK cursor is retained as the generic fence;
/// the provider token is the only provider-specific continuation material.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    token_digest: String,
    offset: u32,
    limit: u32,
    offset_token: Option<String>,
    source_revision: u64,
}

impl fmt::Debug for DataForSeoCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoCursor")
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("sequence", &self.sequence)
            .field("token_digest", &self.token_digest)
            .field("offset", &self.offset)
            .field("limit", &self.limit)
            .field("has_offset_token", &self.offset_token.is_some())
            .field("source_revision", &self.source_revision)
            .finish()
    }
}

impl DataForSeoCursor {
    fn new(
        scope: &ConnectorScope,
        request_digest: &str,
        sequence: u64,
        offset: u32,
        limit: u32,
        offset_token: Option<String>,
        source_revision: u64,
    ) -> Result<Self, DataForSeoError> {
        if sequence == 0
            || source_revision == 0
            || !(1..=MAX_KEYWORD_PAGE_SIZE).contains(&limit)
            || offset_token
                .as_deref()
                .is_some_and(|token| token.is_empty() || token.len() > MAX_TOKEN_LENGTH)
        {
            return Err(DataForSeoError::InvalidCursor);
        }
        let token_material = offset_token.as_deref().unwrap_or("offset");
        let token_digest = canonical_digest(&[
            request_digest,
            &offset.to_string(),
            &limit.to_string(),
            token_material,
            &source_revision.to_string(),
        ]);
        Ok(Self {
            scope_digest: scope.digest(),
            request_digest: request_digest.to_owned(),
            sequence,
            token_digest,
            offset,
            limit,
            offset_token,
            source_revision,
        })
    }

    pub fn sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, DataForSeoError> {
        if self.scope_digest != scope.digest() {
            return Err(DataForSeoError::ScopeMismatch);
        }
        Cursor::new(
            scope,
            self.request_digest.clone(),
            self.sequence,
            self.token_digest.clone(),
        )
        .map_err(DataForSeoError::Connector)
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    pub const fn offset(&self) -> u32 {
        self.offset
    }

    pub const fn limit(&self) -> u32 {
        self.limit
    }

    pub fn offset_token(&self) -> Option<&str> {
        self.offset_token.as_deref()
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    fn validate(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        limit: u32,
        source_revision: u64,
    ) -> Result<(), DataForSeoError> {
        let token_material = self.offset_token.as_deref().unwrap_or("offset");
        let expected_digest = canonical_digest(&[
            request_digest,
            &self.offset.to_string(),
            &self.limit.to_string(),
            token_material,
            &self.source_revision.to_string(),
        ]);
        if self.scope_digest != scope.digest()
            || self.request_digest != request_digest
            || self.token_digest != expected_digest
            || self.limit != limit
            || self.source_revision != source_revision
        {
            return Err(DataForSeoError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoMonthlySearch {
    year: i32,
    month: u8,
    search_volume: Option<u64>,
}

impl DataForSeoMonthlySearch {
    pub const fn year(&self) -> i32 {
        self.year
    }

    pub const fn month(&self) -> u8 {
        self.month
    }

    pub const fn search_volume(&self) -> Option<u64> {
        self.search_volume
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoSearchVolumeTrend {
    monthly: Option<i64>,
    quarterly: Option<i64>,
    yearly: Option<i64>,
}

impl DataForSeoSearchVolumeTrend {
    pub const fn monthly(&self) -> Option<i64> {
        self.monthly
    }

    pub const fn quarterly(&self) -> Option<i64> {
        self.quarterly
    }

    pub const fn yearly(&self) -> Option<i64> {
        self.yearly
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoKeywordObservation {
    keyword: String,
    location_code: u32,
    language_code: String,
    search_volume: Option<u64>,
    competition: Option<Decimal>,
    competition_level: Option<String>,
    cpc_usd: Option<Decimal>,
    categories: Vec<String>,
    last_updated_at: Option<String>,
    monthly_searches: Vec<DataForSeoMonthlySearch>,
    search_volume_trend: Option<DataForSeoSearchVolumeTrend>,
}

impl DataForSeoKeywordObservation {
    pub fn keyword(&self) -> &str {
        &self.keyword
    }

    pub const fn location_code(&self) -> u32 {
        self.location_code
    }

    pub fn language_code(&self) -> &str {
        &self.language_code
    }

    pub const fn search_volume(&self) -> Option<u64> {
        self.search_volume
    }

    pub const fn competition(&self) -> Option<Decimal> {
        self.competition
    }

    pub fn competition_level(&self) -> Option<&str> {
        self.competition_level.as_deref()
    }

    pub const fn cpc_usd(&self) -> Option<Decimal> {
        self.cpc_usd
    }

    pub fn categories(&self) -> &[String] {
        &self.categories
    }

    pub fn last_updated_at(&self) -> Option<&str> {
        self.last_updated_at.as_deref()
    }

    pub fn monthly_searches(&self) -> &[DataForSeoMonthlySearch] {
        &self.monthly_searches
    }

    pub const fn search_volume_trend(&self) -> Option<&DataForSeoSearchVolumeTrend> {
        self.search_volume_trend.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoKeywordPage {
    target_domain: String,
    location_code: u32,
    language_code: String,
    total_count: u64,
    items_count: u32,
    offset: u32,
    items: Vec<DataForSeoKeywordObservation>,
    next_offset_token: Option<String>,
}

impl DataForSeoKeywordPage {
    pub fn target_domain(&self) -> &str {
        &self.target_domain
    }

    pub const fn location_code(&self) -> u32 {
        self.location_code
    }

    pub fn language_code(&self) -> &str {
        &self.language_code
    }

    pub const fn total_count(&self) -> u64 {
        self.total_count
    }

    pub const fn items_count(&self) -> u32 {
        self.items_count
    }

    pub const fn offset(&self) -> u32 {
        self.offset
    }

    pub fn items(&self) -> &[DataForSeoKeywordObservation] {
        &self.items
    }

    pub fn has_next_page(&self) -> bool {
        self.next_offset_token.is_some()
    }

    fn next_cursor(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        limit: u32,
        source_revision: u64,
    ) -> Result<Option<DataForSeoCursor>, DataForSeoError> {
        self.next_offset_token
            .clone()
            .map(|token| {
                DataForSeoCursor::new(
                    scope,
                    request_digest,
                    2_u64.saturating_add(u64::from(self.offset / limit)),
                    self.offset.saturating_add(self.items_count),
                    limit,
                    Some(token),
                    source_revision,
                )
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoTaskReceipt {
    task_id: DataForSeoTaskId,
    mode: DataForSeoExecutionMode,
    endpoint: String,
    api_version: String,
    observed_at: DateTime<Utc>,
    provider_version: String,
    cost_usd: Decimal,
    response_digest: String,
    raw_evidence_digest: String,
}

impl DataForSeoTaskReceipt {
    pub const fn task_id(&self) -> &DataForSeoTaskId {
        &self.task_id
    }

    pub const fn mode(&self) -> DataForSeoExecutionMode {
        self.mode
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub const fn cost_usd(&self) -> Decimal {
        self.cost_usd
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoFreshness {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_revision: u64,
}

impl DataForSeoFreshness {
    fn from_sdk(freshness: &FreshnessWindow) -> Self {
        Self {
            observed_at: freshness.observed_at(),
            valid_until: freshness.valid_until(),
            source_revision: freshness.source_revision(),
        }
    }

    pub fn to_sdk(&self) -> Result<FreshnessWindow, DataForSeoError> {
        FreshnessWindow::new(self.observed_at, self.valid_until, self.source_revision)
            .map_err(DataForSeoError::Connector)
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoReadObservation {
    observation_id: String,
    scope: ConnectorScope,
    capability: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    request_digest: String,
    response_digest: String,
    content_digest: String,
    provenance_class: ProviderProvenanceClass,
    freshness: DataForSeoFreshness,
    page_sequence: u64,
    item_count: u32,
    next_cursor: Option<DataForSeoCursor>,
}

impl DataForSeoReadObservation {
    fn from_sdk(observation: &ReadObservation, next_cursor: Option<DataForSeoCursor>) -> Self {
        Self {
            observation_id: observation.observation_id().to_owned(),
            scope: observation.scope().clone(),
            capability: observation.capability().clone(),
            adapter: observation.adapter().clone(),
            request_digest: observation.request_digest().to_owned(),
            response_digest: observation.response_digest().to_owned(),
            content_digest: observation.content_digest().to_owned(),
            provenance_class: observation.provenance_class(),
            freshness: DataForSeoFreshness::from_sdk(observation.freshness()),
            page_sequence: observation.page_sequence(),
            item_count: observation.item_count(),
            next_cursor,
        }
    }

    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn capability(&self) -> &ProviderCapabilityKey {
        &self.capability
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub const fn freshness(&self) -> &DataForSeoFreshness {
        &self.freshness
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub const fn next_cursor(&self) -> Option<&DataForSeoCursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoGrowthSignal {
    scope: ConnectorScope,
    request: DataForSeoKeywordRequest,
    source_uri: String,
    endpoint: String,
    api_version: String,
    observed_at: DateTime<Utc>,
    freshness: DataForSeoFreshness,
    source_revision: u64,
    raw_evidence_digest: String,
    content_digest: String,
    classification: DataForSeoEvidenceClassification,
    first_party: bool,
    estimate: DataForSeoEstimateEvidence,
    account_probe: DataForSeoAccountProbe,
    labs_status: DataForSeoLabsStatus,
    task: DataForSeoTaskReceipt,
    page: DataForSeoKeywordPage,
    read_observation: DataForSeoReadObservation,
    usage: DataForSeoUsage,
    next_cursor: Option<DataForSeoCursor>,
    charged: bool,
    replayed: bool,
}

impl DataForSeoGrowthSignal {
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn request(&self) -> &DataForSeoKeywordRequest {
        &self.request
    }

    pub fn source_uri(&self) -> &str {
        &self.source_uri
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn freshness(&self) -> &DataForSeoFreshness {
        &self.freshness
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub const fn classification(&self) -> DataForSeoEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn estimate(&self) -> &DataForSeoEstimateEvidence {
        &self.estimate
    }

    pub const fn account_probe(&self) -> &DataForSeoAccountProbe {
        &self.account_probe
    }

    pub const fn labs_status(&self) -> &DataForSeoLabsStatus {
        &self.labs_status
    }

    pub const fn task(&self) -> &DataForSeoTaskReceipt {
        &self.task
    }

    pub const fn page(&self) -> &DataForSeoKeywordPage {
        &self.page
    }

    pub const fn read_observation(&self) -> &DataForSeoReadObservation {
        &self.read_observation
    }

    pub const fn usage(&self) -> &DataForSeoUsage {
        &self.usage
    }

    pub const fn next_cursor(&self) -> Option<&DataForSeoCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoHttpMethod {
    Get,
    Post,
}

#[derive(Clone, PartialEq)]
pub struct DataForSeoHttpRequest {
    method: DataForSeoHttpMethod,
    path: String,
    body: Option<Value>,
}

impl fmt::Debug for DataForSeoHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body", &self.body_digest())
            .finish()
    }
}

impl DataForSeoHttpRequest {
    fn get(path: impl Into<String>) -> Self {
        Self {
            method: DataForSeoHttpMethod::Get,
            path: path.into(),
            body: None,
        }
    }

    fn post(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: DataForSeoHttpMethod::Post,
            path: path.into(),
            body: Some(body),
        }
    }

    pub const fn method(&self) -> DataForSeoHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body(&self) -> Option<&Value> {
        self.body.as_ref()
    }

    pub fn body_digest(&self) -> Option<String> {
        self.body.as_ref().and_then(|body| digest_json(body).ok())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DataForSeoHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
    raw_evidence_digest: String,
}

impl DataForSeoHttpResponse {
    pub fn new(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
    ) -> Result<Self, DataForSeoError> {
        let raw =
            serde_json::to_vec(&body).map_err(|_| DataForSeoError::InvalidProviderResponse)?;
        Ok(Self {
            status,
            headers,
            body,
            raw_evidence_digest: sha256_bytes(&raw),
        })
    }

    fn with_raw_evidence_digest(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
        raw_evidence_digest: String,
    ) -> Result<Self, DataForSeoError> {
        if !is_sha256(&raw_evidence_digest) {
            return Err(DataForSeoError::InvalidProviderResponse);
        }
        Ok(Self {
            status,
            headers,
            body,
            raw_evidence_digest,
        })
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    pub const fn body(&self) -> &Value {
        &self.body
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }
}

/// A timeout and bounded retry policy shared by the production adapter and
/// deterministic transport worlds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoTimeoutRetryPolicy {
    timeout_ms: u64,
    max_attempts: u8,
    backoff_ms: u64,
    max_backoff_ms: u64,
}

impl DataForSeoTimeoutRetryPolicy {
    pub fn new(
        timeout_ms: u64,
        max_attempts: u8,
        backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Result<Self, DataForSeoError> {
        if !(1..=30_000).contains(&timeout_ms)
            || !(1..=4).contains(&max_attempts)
            || backoff_ms > max_backoff_ms
            || max_backoff_ms > 10_000
        {
            return Err(DataForSeoError::InvalidRetryPolicy);
        }
        Ok(Self {
            timeout_ms,
            max_attempts,
            backoff_ms,
            max_backoff_ms,
        })
    }

    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub const fn max_attempts(&self) -> u8 {
        self.max_attempts
    }

    pub const fn backoff_ms(&self) -> u64 {
        self.backoff_ms
    }

    pub const fn max_backoff_ms(&self) -> u64 {
        self.max_backoff_ms
    }
}

impl Default for DataForSeoTimeoutRetryPolicy {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            max_attempts: 3,
            backoff_ms: 100,
            max_backoff_ms: 1_000,
        }
    }
}

/// Resolved credentials are held only by the transport and are never
/// serializable or included in Debug output. Callers persist only the SDK's
/// opaque `SecretReference`.
pub struct DataForSeoCredentials {
    login: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl fmt::Debug for DataForSeoCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoCredentials")
            .field("present", &true)
            .finish()
    }
}

impl DataForSeoCredentials {
    pub fn new(
        login: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, DataForSeoError> {
        let login = login.into();
        let password = password.into();
        if login.trim().is_empty() || password.is_empty() {
            return Err(DataForSeoError::MissingCredential);
        }
        Ok(Self {
            login: Zeroizing::new(login),
            password: Zeroizing::new(password),
        })
    }
}

pub trait DataForSeoLabsTransport: fmt::Debug + Send {
    fn execute(
        &mut self,
        request: DataForSeoHttpRequest,
    ) -> Result<DataForSeoHttpResponse, DataForSeoError>;

    fn revoke(&mut self) {}
}

pub struct DataForSeoHttpTransport {
    client: Client,
    base_url: Url,
    credentials: DataForSeoCredentials,
}

impl fmt::Debug for DataForSeoHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoHttpTransport")
            .field("base_url", &self.base_url)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl DataForSeoHttpTransport {
    pub fn new(
        credentials: DataForSeoCredentials,
        timeout: StdDuration,
    ) -> Result<Self, DataForSeoError> {
        let base_url =
            Url::parse(DATAFORSEO_API_BASE_URL).map_err(|_| DataForSeoError::InvalidEndpoint)?;
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| DataForSeoError::Transport)?;
        Ok(Self {
            client,
            base_url,
            credentials,
        })
    }

    pub fn production(
        credentials: DataForSeoCredentials,
        policy: &DataForSeoTimeoutRetryPolicy,
    ) -> Result<Self, DataForSeoError> {
        Self::new(credentials, StdDuration::from_millis(policy.timeout_ms()))
    }
}

impl DataForSeoLabsTransport for DataForSeoHttpTransport {
    fn execute(
        &mut self,
        request: DataForSeoHttpRequest,
    ) -> Result<DataForSeoHttpResponse, DataForSeoError> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| DataForSeoError::InvalidEndpoint)?;
        let builder = match request.method {
            DataForSeoHttpMethod::Get => self.client.get(url),
            DataForSeoHttpMethod::Post => self.client.post(url),
        }
        .basic_auth(
            self.credentials.login.as_str(),
            Some(self.credentials.password.as_str()),
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json");
        let response = match request.body {
            Some(body) => builder.json(&body).send(),
            None => builder.send(),
        }
        .map_err(|error| {
            if error.is_timeout() {
                DataForSeoError::Timeout
            } else {
                DataForSeoError::Transport
            }
        })?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let bytes = response.bytes().map_err(|_| DataForSeoError::Transport)?;
        let raw_evidence_digest = sha256_bytes(&bytes);
        let body = serde_json::from_slice::<Value>(&bytes)
            .map_err(|_| DataForSeoError::InvalidProviderResponse)?;
        DataForSeoHttpResponse::with_raw_evidence_digest(status, headers, body, raw_evidence_digest)
    }

    fn revoke(&mut self) {
        self.credentials.login.zeroize();
        self.credentials.password.zeroize();
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DataForSeoError {
    #[error("DataForSEO request is invalid")]
    InvalidRequest,
    #[error("DataForSEO endpoint is invalid")]
    InvalidEndpoint,
    #[error("DataForSEO credential is missing")]
    MissingCredential,
    #[error("DataForSEO task id is invalid")]
    InvalidTaskId,
    #[error("DataForSEO cursor is invalid")]
    InvalidCursor,
    #[error("DataForSEO retry policy is invalid")]
    InvalidRetryPolicy,
    #[error("DataForSEO provider response is invalid")]
    InvalidProviderResponse,
    #[error("DataForSEO provider returned HTTP status {0}")]
    ProviderHttpStatus(u16),
    #[error("DataForSEO provider rejected the request with status code {0}")]
    ProviderStatus(i64),
    #[error("DataForSEO provider transport failed")]
    Transport,
    #[error("DataForSEO provider request timed out")]
    Timeout,
    #[error("DataForSEO provider cost exceeds the read boundary")]
    CostLimitExceeded,
    #[error("DataForSEO provider quota is exhausted")]
    QuotaExhausted,
    #[error("DataForSEO service is not mounted")]
    NotMounted,
    #[error("DataForSEO service is revoked")]
    Revoked,
    #[error("DataForSEO service scope does not match")]
    ScopeMismatch,
    #[error("DataForSEO provider freshness changed while paging")]
    FreshnessDrift,
    #[error("DataForSEO provider state is not ready")]
    ProviderPending,
    #[error("DataForSEO connector state is unavailable")]
    StateUnavailable,
    #[error("Connector SDK rejected the DataForSEO operation: {0}")]
    Connector(ConnectorError),
}

impl From<ConnectorError> for DataForSeoError {
    fn from(error: ConnectorError) -> Self {
        Self::Connector(error)
    }
}

#[derive(Clone, Debug)]
struct BoundPage {
    request: DataForSeoKeywordRequest,
    cursor: Option<DataForSeoCursor>,
}

#[derive(Default)]
struct AdapterState {
    revoked: bool,
    account_probe: Option<DataForSeoAccountProbe>,
    labs_status: Option<DataForSeoLabsStatus>,
    bound_pages: BTreeMap<(String, u64), BoundPage>,
    signals: BTreeMap<String, DataForSeoGrowthSignal>,
}

/// The DataForSEO provider adapter uses the stable SDK object-safe lifecycle.
/// The state handle exists only to return the provider's typed result after the
/// SDK worker has validated the generic `ReadObservation` binding.
pub struct DataForSeoLabsAdapter<T: DataForSeoLabsTransport> {
    descriptor: ConnectorDescriptor,
    transport: T,
    policy: DataForSeoTimeoutRetryPolicy,
    provenance: ProviderProvenanceClass,
    result_ttl: Duration,
    state: Arc<Mutex<AdapterState>>,
}

impl<T: DataForSeoLabsTransport> fmt::Debug for DataForSeoLabsAdapter<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoLabsAdapter")
            .field("descriptor", &self.descriptor)
            .field("policy", &self.policy)
            .field("result_ttl", &self.result_ttl)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<T: DataForSeoLabsTransport> Drop for DataForSeoLabsAdapter<T> {
    fn drop(&mut self) {
        self.transport.revoke();
        if let Ok(mut state) = self.state.lock() {
            state.revoked = true;
            state.account_probe = None;
            state.labs_status = None;
            state.bound_pages.clear();
            state.signals.clear();
        }
    }
}

impl<T: DataForSeoLabsTransport> DataForSeoLabsAdapter<T> {
    pub fn new(
        transport: T,
        policy: DataForSeoTimeoutRetryPolicy,
    ) -> Result<Self, DataForSeoError> {
        Self::new_with_provenance(
            transport,
            policy,
            ProviderProvenanceClass::ProductionProvider,
        )
    }

    pub fn controlled(
        transport: T,
        policy: DataForSeoTimeoutRetryPolicy,
    ) -> Result<Self, DataForSeoError> {
        Self::new_with_provenance(
            transport,
            policy,
            ProviderProvenanceClass::ControlledProvider,
        )
    }

    fn new_with_provenance(
        transport: T,
        policy: DataForSeoTimeoutRetryPolicy,
        provenance: ProviderProvenanceClass,
    ) -> Result<Self, DataForSeoError> {
        let registry = dataforseo_registry()?;
        let descriptor = ConnectorDescriptor::new(
            ProviderAdapterIdentity::new(
                DATAFORSEO_LABS_ADAPTER_ID,
                DATAFORSEO_LABS_ADAPTER_VERSION,
            )
            .map_err(ConnectorError::from)?,
            registry.registrations().iter().cloned(),
        )
        .map_err(DataForSeoError::Connector)?;
        Ok(Self {
            descriptor,
            transport,
            policy,
            provenance,
            result_ttl: Duration::seconds(DEFAULT_RESULT_TTL_SECONDS),
            state: Arc::new(Mutex::new(AdapterState::default())),
        })
    }

    pub fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    pub fn policy(&self) -> &DataForSeoTimeoutRetryPolicy {
        &self.policy
    }

    fn state_handle(&self) -> Arc<Mutex<AdapterState>> {
        Arc::clone(&self.state)
    }

    /// Binds a provider-specific page selector to the SDK request digest. The
    /// selector is held only until the worker invokes `read`.
    pub fn bind_page(
        &mut self,
        request: DataForSeoKeywordRequest,
        cursor: Option<DataForSeoCursor>,
    ) -> Result<(), DataForSeoError> {
        request.validate()?;
        let request_digest = request.request_digest();
        let source_revision = self.current_source_revision()?;
        if let Some(cursor) = &cursor {
            cursor.validate(
                request.scope(),
                &request_digest,
                request.limit(),
                source_revision,
            )?;
        }
        let sequence = cursor.as_ref().map_or(0, DataForSeoCursor::sequence);
        let mut state = self.lock_state()?;
        if state.revoked {
            return Err(DataForSeoError::Revoked);
        }
        state
            .bound_pages
            .insert((request_digest, sequence), BoundPage { request, cursor });
        Ok(())
    }

    pub fn account_probe(&self) -> Result<Option<DataForSeoAccountProbe>, DataForSeoError> {
        Ok(self.lock_state()?.account_probe.clone())
    }

    pub fn labs_status(&self) -> Result<Option<DataForSeoLabsStatus>, DataForSeoError> {
        Ok(self.lock_state()?.labs_status.clone())
    }

    pub fn take_signal(
        &self,
        observation_id: &str,
    ) -> Result<DataForSeoGrowthSignal, DataForSeoError> {
        self.lock_state()?
            .signals
            .remove(observation_id)
            .ok_or(DataForSeoError::StateUnavailable)
    }

    /// Controlled transport entry point for deterministic worlds. It does not
    /// use the SDK production-only probe fence and therefore cannot claim
    /// Connected/first-party evidence.
    pub fn read_controlled(
        &mut self,
        request: DataForSeoKeywordRequest,
        cursor: Option<DataForSeoCursor>,
        at: DateTime<Utc>,
    ) -> Result<DataForSeoGrowthSignal, DataForSeoError> {
        if self.account_probe()?.is_none() {
            self.probe_transport(
                request.scope(),
                at,
                ProviderProvenanceClass::ControlledProvider,
            )?;
        }
        let request_digest = request.request_digest();
        let sequence = cursor.as_ref().map_or(0, DataForSeoCursor::sequence);
        let scope = request.scope().clone();
        let page_size = request.limit();
        let budget = DispatchBudget::new(
            100,
            at + Duration::minutes(1),
            100,
            decimal_to_minor(request.max_cost_usd())?,
        )
        .map_err(DataForSeoError::Connector)?;
        self.bind_page(request, cursor)?;
        let capability =
            ProviderCapabilityKey::new(DATAFORSEO_PROVIDER_ID, DATAFORSEO_LABS_READ_CAPABILITY)
                .map_err(ConnectorError::from)?;
        let observation = self.read_bound(
            &scope,
            &capability,
            &request_digest,
            page_size,
            at,
            &budget,
            sequence,
            ProviderProvenanceClass::ControlledProvider,
        )?;
        self.take_signal(observation.observation_id())
    }

    fn probe_transport(
        &mut self,
        scope: &ConnectorScope,
        at: DateTime<Utc>,
        provenance: ProviderProvenanceClass,
    ) -> Result<ProbeObservation, DataForSeoError> {
        if scope.provider_id() != DATAFORSEO_PROVIDER_ID {
            return Err(DataForSeoError::ScopeMismatch);
        }
        if self.lock_state()?.revoked {
            return Err(DataForSeoError::Revoked);
        }
        let account_request = DataForSeoHttpRequest::get(DATAFORSEO_USER_DATA_PATH);
        let account_response = self.execute_with_retry(&account_request)?;
        let account_envelope = &account_response;
        let account_result = account_envelope
            .result
            .as_object()
            .ok_or(DataForSeoError::InvalidProviderResponse)?;
        let login = account_result
            .get("login")
            .and_then(Value::as_str)
            .ok_or(DataForSeoError::InvalidProviderResponse)?;
        let status_request = DataForSeoHttpRequest::get(DATAFORSEO_LABS_STATUS_PATH);
        let status_response = self.execute_with_retry(&status_request)?;
        let status_envelope = &status_response;
        let status = parse_labs_status(status_envelope, at)?;
        let raw_evidence_digest = canonical_digest(&[
            account_response.raw_evidence_digest(),
            status_response.raw_evidence_digest(),
        ]);
        let expires_at = at + Duration::seconds(DEFAULT_PROBE_TTL_SECONDS);
        let account_probe = DataForSeoAccountProbe {
            scope: scope.clone(),
            status: ProbeStatus::Reachable,
            provenance_class: provenance,
            observed_at: at,
            expires_at,
            evidence_digest: raw_evidence_digest.clone(),
            raw_evidence_digest: account_response.raw_evidence_digest().to_owned(),
            account_login_digest: sha256_bytes(login.as_bytes()),
            rate_limit: DataForSeoRateLimit::from_headers(account_response.headers(), at),
            cost_usd: account_envelope.cost,
        };
        let mut state = self.lock_state()?;
        state.account_probe = Some(account_probe);
        state.labs_status = Some(status);
        Ok(ProbeObservation::new(
            ProbeStatus::Reachable,
            provenance,
            at,
            expires_at,
            raw_evidence_digest,
        )?)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn read_bound(
        &mut self,
        scope: &ConnectorScope,
        capability: &ProviderCapabilityKey,
        query_digest: &str,
        page_size: u32,
        at: DateTime<Utc>,
        budget: &DispatchBudget,
        sequence: u64,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, DataForSeoError> {
        let bound = {
            let mut state = self.lock_state()?;
            if state.revoked {
                return Err(DataForSeoError::Revoked);
            }
            state
                .bound_pages
                .remove(&(query_digest.to_owned(), sequence))
                .ok_or(DataForSeoError::InvalidRequest)?
        };
        if bound.request.scope() != scope || bound.request.request_digest() != query_digest {
            return Err(DataForSeoError::ScopeMismatch);
        }
        let source_revision = self.current_source_revision()?;
        if let Some(cursor) = &bound.cursor {
            cursor.validate(scope, query_digest, page_size, source_revision)?;
        }
        let estimated_minor = decimal_to_minor(bound.request.estimated_cost_usd())?;
        if estimated_minor > budget.cost.limit_minor() {
            return Err(DataForSeoError::CostLimitExceeded);
        }
        let body = bound.request.provider_body(bound.cursor.as_ref());
        let provider_request =
            DataForSeoHttpRequest::post(DATAFORSEO_LABS_KEYWORDS_FOR_SITE_PATH, body);
        let response = self.execute_with_retry(&provider_request)?;
        let envelope = response;
        let page = parse_keyword_page(&envelope, &bound.request)?;
        if envelope.cost > bound.request.max_cost_usd()
            || decimal_to_minor(envelope.cost)? > budget.cost.limit_minor()
        {
            return Err(DataForSeoError::CostLimitExceeded);
        }
        let next_cursor =
            page.next_cursor(scope, query_digest, bound.request.limit(), source_revision)?;
        let content_digest = digest_json(&page)?;
        let response_digest = envelope.raw_evidence_digest().to_owned();
        let observation_id = format!(
            "read-observation-{}",
            &response_digest[..24.min(response_digest.len())]
        );
        let freshness = FreshnessWindow::new(at, at + self.result_ttl, source_revision)
            .map_err(DataForSeoError::Connector)?;
        let sdk_next_cursor = next_cursor
            .as_ref()
            .map(|cursor| cursor.sdk_cursor(scope))
            .transpose()?;
        let read_observation = ReadObservation::new(
            observation_id.clone(),
            scope.clone(),
            capability.clone(),
            self.descriptor.identity().clone(),
            query_digest.to_owned(),
            response_digest.clone(),
            content_digest.clone(),
            provenance,
            freshness.clone(),
            bound.cursor.as_ref().map_or(1, DataForSeoCursor::sequence),
            page.items_count(),
            sdk_next_cursor,
        )
        .map_err(DataForSeoError::Connector)?;
        let signal_freshness = DataForSeoFreshness::from_sdk(&freshness);
        let signal_read_observation =
            DataForSeoReadObservation::from_sdk(&read_observation, next_cursor.clone());
        let (account_probe, labs_status) = {
            let state = self.lock_state()?;
            (
                state
                    .account_probe
                    .clone()
                    .ok_or(DataForSeoError::ProviderPending)?,
                state
                    .labs_status
                    .clone()
                    .ok_or(DataForSeoError::ProviderPending)?,
            )
        };
        let task = DataForSeoTaskReceipt {
            task_id: envelope.task_id.clone(),
            mode: DataForSeoExecutionMode::Live,
            endpoint: DATAFORSEO_LABS_KEYWORDS_FOR_SITE_PATH.to_owned(),
            api_version: DATAFORSEO_API_VERSION.to_owned(),
            observed_at: at,
            provider_version: envelope.version.clone(),
            cost_usd: envelope.cost,
            response_digest: response_digest.clone(),
            raw_evidence_digest: envelope.raw_evidence_digest().to_owned(),
        };
        let usage = DataForSeoUsage {
            provider_cost_usd: envelope.cost,
            estimated_cost_usd: bound.request.estimated_cost_usd(),
            charged: true,
            attempts: envelope.attempts,
            rate_limit: DataForSeoRateLimit::from_headers(envelope.headers(), at),
            quota: DataForSeoQuota {
                provider_limit: None,
                provider_used: None,
                local_limit: budget.quota.limit(),
                local_used: budget.quota.used().saturating_add(1),
            },
        };
        let signal = DataForSeoGrowthSignal {
            scope: scope.clone(),
            request: bound.request.clone(),
            source_uri: format!(
                "dataforseo://{}/labs/google/keywords_for_site/live?request={}",
                scope.account_id(),
                query_digest
            ),
            endpoint: DATAFORSEO_LABS_KEYWORDS_FOR_SITE_PATH.to_owned(),
            api_version: DATAFORSEO_API_VERSION.to_owned(),
            observed_at: at,
            freshness: signal_freshness,
            source_revision,
            raw_evidence_digest: envelope.raw_evidence_digest().to_owned(),
            content_digest,
            classification: DataForSeoEvidenceClassification::ProviderEstimate,
            first_party: false,
            estimate: bound.request.estimate_only_evidence(),
            account_probe,
            labs_status,
            task,
            page,
            read_observation: signal_read_observation,
            usage,
            next_cursor,
            charged: true,
            replayed: false,
        };
        self.lock_state()?.signals.insert(observation_id, signal);
        Ok(read_observation)
    }

    fn execute_with_retry(
        &mut self,
        request: &DataForSeoHttpRequest,
    ) -> Result<TransportEnvelope, DataForSeoError> {
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            match self.transport.execute(request.clone()) {
                Ok(response)
                    if is_retryable_status(response.status())
                        && attempt < self.policy.max_attempts() =>
                {
                    self.sleep_before_retry(attempt);
                }
                Ok(response) => {
                    let envelope = parse_envelope(&response)?;
                    return Ok(TransportEnvelope {
                        response,
                        task_id: envelope.task_id,
                        version: envelope.version,
                        cost: envelope.cost,
                        result: envelope.result,
                        attempts: attempt,
                    });
                }
                Err(error)
                    if is_retryable_error(&error) && attempt < self.policy.max_attempts() =>
                {
                    self.sleep_before_retry(attempt);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn sleep_before_retry(&self, attempt: u8) {
        let exponent = u32::from(attempt.saturating_sub(1));
        let delay = self
            .policy
            .backoff_ms()
            .saturating_mul(2_u64.saturating_pow(exponent))
            .min(self.policy.max_backoff_ms());
        if delay > 0 {
            std::thread::sleep(StdDuration::from_millis(delay));
        }
    }

    fn current_source_revision(&self) -> Result<u64, DataForSeoError> {
        self.lock_state()?
            .labs_status
            .as_ref()
            .map(DataForSeoLabsStatus::source_revision)
            .ok_or(DataForSeoError::ProviderPending)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, AdapterState>, DataForSeoError> {
        self.state
            .lock()
            .map_err(|_| DataForSeoError::StateUnavailable)
    }
}

impl<T: DataForSeoLabsTransport> ConnectorAdapter for DataForSeoLabsAdapter<T> {
    fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    fn begin_auth(&mut self, request: BeginAuthRequest) -> Result<AuthSession, ConnectorError> {
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn refresh_auth(&mut self, request: RefreshAuthRequest) -> Result<AuthSession, ConnectorError> {
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn probe(&mut self, request: ProbeRequest) -> Result<ProbeObservation, ConnectorError> {
        self.probe_transport(&request.scope, request.at, self.provenance)
            .map_err(|error| match error {
                DataForSeoError::Connector(error) => error,
                _ => ConnectorError::ProviderRejected,
            })
    }

    fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
        let sequence = request.cursor.as_ref().map_or(0, Cursor::sequence);
        self.read_bound(
            &request.scope,
            &request.capability,
            &request.query_digest,
            request.page_size,
            request.at,
            &request.budget,
            sequence,
            self.provenance,
        )
        .map_err(|error| match error {
            DataForSeoError::Connector(error) => error,
            DataForSeoError::CostLimitExceeded => ConnectorError::CostLimitExceeded,
            DataForSeoError::QuotaExhausted => ConnectorError::QuotaExceeded,
            _ => ConnectorError::ProviderRejected,
        })
    }

    fn prepare_effect(
        &mut self,
        _request: PrepareEffectRequest,
    ) -> Result<PreparedEffect, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn execute(&mut self, _request: ExecuteRequest) -> Result<ReceiptCandidate, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn reconcile(
        &mut self,
        _request: ReconcileRequest,
    ) -> Result<ReconciliationObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn verify(
        &mut self,
        _request: VerifyRequest,
    ) -> Result<VerificationObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn handle_webhook(
        &mut self,
        _request: WebhookRequest,
    ) -> Result<WebhookObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn revoke(&mut self, _request: RevokeRequest) -> Result<(), ConnectorError> {
        self.transport.revoke();
        let mut state = self
            .lock_state()
            .map_err(|_| ConnectorError::ProviderRejected)?;
        state.revoked = true;
        state.bound_pages.clear();
        state.signals.clear();
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TransportEnvelope {
    response: DataForSeoHttpResponse,
    task_id: DataForSeoTaskId,
    version: String,
    cost: Decimal,
    result: Value,
    attempts: u8,
}

impl TransportEnvelope {
    fn headers(&self) -> &BTreeMap<String, String> {
        self.response.headers()
    }

    fn raw_evidence_digest(&self) -> &str {
        self.response.raw_evidence_digest()
    }
}

#[derive(Clone, Debug)]
struct ParsedEnvelope {
    task_id: DataForSeoTaskId,
    version: String,
    cost: Decimal,
    result: Value,
}

fn dataforseo_registry() -> Result<ProviderAdapterRegistry, DataForSeoError> {
    ProviderAdapterRegistry::from_contract_json(DATAFORSEO_LABS_READ_CONTRACT_JSON)
        .map_err(|_| DataForSeoError::Connector(ConnectorError::InvalidRegistry))
}

fn parse_envelope(response: &DataForSeoHttpResponse) -> Result<ParsedEnvelope, DataForSeoError> {
    if !(200..300).contains(&response.status()) {
        return Err(DataForSeoError::ProviderHttpStatus(response.status()));
    }
    let status_code = response
        .body()
        .get("status_code")
        .and_then(Value::as_i64)
        .ok_or(DataForSeoError::InvalidProviderResponse)?;
    if status_code != DATAFORSEO_OK {
        return Err(provider_status_error(status_code));
    }
    let version = response
        .body()
        .get("version")
        .and_then(Value::as_str)
        .ok_or(DataForSeoError::InvalidProviderResponse)?
        .to_owned();
    let cost = decimal_field(response.body(), "cost")?;
    let tasks = response
        .body()
        .get("tasks")
        .and_then(Value::as_array)
        .ok_or(DataForSeoError::InvalidProviderResponse)?;
    let task = tasks
        .first()
        .ok_or(DataForSeoError::InvalidProviderResponse)?;
    let task_status = task
        .get("status_code")
        .and_then(Value::as_i64)
        .ok_or(DataForSeoError::InvalidProviderResponse)?;
    if task_status != DATAFORSEO_OK {
        return Err(provider_status_error(task_status));
    }
    let task_id = DataForSeoTaskId::new(
        task.get("id")
            .and_then(Value::as_str)
            .ok_or(DataForSeoError::InvalidProviderResponse)?,
    )?;
    let task_cost = decimal_field(task, "cost").unwrap_or(cost);
    let result = task
        .get("result")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .cloned()
        .ok_or(DataForSeoError::InvalidProviderResponse)?;
    Ok(ParsedEnvelope {
        task_id,
        version,
        cost: task_cost,
        result,
    })
}

fn parse_labs_status(
    envelope: &TransportEnvelope,
    observed_at: DateTime<Utc>,
) -> Result<DataForSeoLabsStatus, DataForSeoError> {
    let google_date_update = parse_update_date(&envelope.result, "google")?;
    let bing_date_update = parse_update_date(&envelope.result, "bing")?;
    let amazon_date_update = parse_update_date(&envelope.result, "amazon")?;
    let raw_evidence_digest = envelope.raw_evidence_digest().to_owned();
    Ok(DataForSeoLabsStatus {
        google_date_update,
        bing_date_update,
        amazon_date_update,
        raw_evidence_digest: raw_evidence_digest.clone(),
        source_revision: source_revision(&raw_evidence_digest),
        observed_at,
        cost_usd: envelope.cost,
    })
}

fn parse_update_date(result: &Value, provider: &str) -> Result<Option<NaiveDate>, DataForSeoError> {
    result
        .get(provider)
        .and_then(Value::as_object)
        .map_or(Ok(None), |provider| {
            provider
                .get("date_update")
                .and_then(Value::as_str)
                .map(|value| {
                    NaiveDate::parse_from_str(value, "%Y-%m-%d")
                        .map_err(|_| DataForSeoError::InvalidProviderResponse)
                })
                .transpose()
        })
}

fn parse_keyword_page(
    envelope: &TransportEnvelope,
    request: &DataForSeoKeywordRequest,
) -> Result<DataForSeoKeywordPage, DataForSeoError> {
    let result = &envelope.result;
    let target_domain = result
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or(request.target_domain())
        .to_owned();
    let location_code = result
        .get("location_code")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(request.location_code());
    let language_code = result
        .get("language_code")
        .and_then(Value::as_str)
        .unwrap_or(request.language_code())
        .to_owned();
    let total_count = result
        .get("total_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let items = result
        .get("items")
        .and_then(Value::as_array)
        .ok_or(DataForSeoError::InvalidProviderResponse)?
        .iter()
        .map(parse_keyword_item)
        .collect::<Result<Vec<_>, _>>()?;
    let items_count = result
        .get("items_count")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| u32::try_from(items.len()).unwrap_or(u32::MAX));
    let offset = result
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let next_offset_token = result
        .get("offset_token")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if next_offset_token
        .as_deref()
        .is_some_and(|token| token.is_empty() || token.len() > MAX_TOKEN_LENGTH)
    {
        return Err(DataForSeoError::InvalidProviderResponse);
    }
    Ok(DataForSeoKeywordPage {
        target_domain,
        location_code,
        language_code,
        total_count,
        items_count,
        offset,
        items,
        next_offset_token,
    })
}

fn parse_keyword_item(value: &Value) -> Result<DataForSeoKeywordObservation, DataForSeoError> {
    let keyword = value
        .get("keyword")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(DataForSeoError::InvalidProviderResponse)?
        .to_owned();
    let location_code = value
        .get("location_code")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let language_code = value
        .get("language_code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let info = value
        .get("keyword_info")
        .and_then(Value::as_object)
        .ok_or(DataForSeoError::InvalidProviderResponse)?;
    let categories = info
        .get("categories")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let monthly_searches = info
        .get("monthly_searches")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(DataForSeoMonthlySearch {
                        year: i32::try_from(item.get("year")?.as_i64()?).ok()?,
                        month: u8::try_from(item.get("month")?.as_u64()?).ok()?,
                        search_volume: item.get("search_volume").and_then(Value::as_u64),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let search_volume_trend = info
        .get("search_volume_trend")
        .and_then(Value::as_object)
        .map(|trend| DataForSeoSearchVolumeTrend {
            monthly: trend.get("monthly").and_then(Value::as_i64),
            quarterly: trend.get("quarterly").and_then(Value::as_i64),
            yearly: trend.get("yearly").and_then(Value::as_i64),
        });
    Ok(DataForSeoKeywordObservation {
        keyword,
        location_code,
        language_code,
        search_volume: info.get("search_volume").and_then(Value::as_u64),
        competition: info.get("competition").and_then(parse_decimal),
        competition_level: info
            .get("competition_level")
            .and_then(Value::as_str)
            .map(str::to_owned),
        cpc_usd: info.get("cpc").and_then(parse_decimal),
        categories,
        last_updated_at: info
            .get("last_updated_time")
            .and_then(Value::as_str)
            .map(str::to_owned),
        monthly_searches,
        search_volume_trend,
    })
}

fn decimal_field(value: &Value, field: &str) -> Result<Decimal, DataForSeoError> {
    value
        .get(field)
        .and_then(parse_decimal)
        .ok_or(DataForSeoError::InvalidProviderResponse)
}

fn parse_decimal(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(number) => Decimal::from_str(&number.to_string()).ok(),
        Value::String(value) => Decimal::from_str(value).ok(),
        _ => None,
    }
}

fn provider_status_error(status: i64) -> DataForSeoError {
    if status == 40_501 {
        DataForSeoError::InvalidCursor
    } else if (40_000..50_000).contains(&status) || status == 30_000 {
        DataForSeoError::QuotaExhausted
    } else if status == 20_100 {
        DataForSeoError::ProviderPending
    } else {
        DataForSeoError::ProviderStatus(status)
    }
}

fn is_retryable_status(status: u16) -> bool {
    status == 429 || status >= 500
}

fn is_retryable_error(error: &DataForSeoError) -> bool {
    matches!(error, DataForSeoError::Transport | DataForSeoError::Timeout)
}

fn decimal_to_minor(value: Decimal) -> Result<i64, DataForSeoError> {
    value
        .checked_mul(Decimal::new(100, 0))
        .and_then(|scaled| scaled.to_i64())
        .ok_or(DataForSeoError::CostLimitExceeded)
}

fn header_u64(headers: &BTreeMap<String, String>, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|value| value.parse::<u64>().ok())
}

fn valid_token(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, DataForSeoError> {
    let bytes = serde_json::to_vec(value).map_err(|_| DataForSeoError::InvalidRequest)?;
    Ok(sha256_bytes(&bytes))
}

fn canonical_digest(parts: &[&str]) -> String {
    let mut material = String::new();
    for part in parts {
        material.push_str(&part.len().to_string());
        material.push(':');
        material.push_str(part);
        material.push('|');
    }
    sha256_bytes(material.as_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn source_revision(raw_digest: &str) -> u64 {
    u64::from_str_radix(&raw_digest[..16], 16)
        .unwrap_or(1)
        .max(1)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoReplayLedger {
    pages: BTreeMap<String, DataForSeoGrowthSignal>,
}

impl DataForSeoReplayLedger {
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    /// Returns a durable replay without charging the provider again.
    pub fn replay(&self, request_digest: &str, sequence: u64) -> Option<DataForSeoGrowthSignal> {
        self.get(request_digest, sequence).map(replayed_signal)
    }

    /// Records a typed result after the provider read has completed.
    pub fn record(&mut self, signal: DataForSeoGrowthSignal) {
        self.insert(signal);
    }

    fn key(request_digest: &str, sequence: u64) -> String {
        canonical_digest(&[request_digest, &sequence.to_string()])
    }

    fn get(&self, request_digest: &str, sequence: u64) -> Option<&DataForSeoGrowthSignal> {
        self.pages.get(&Self::key(request_digest, sequence))
    }

    fn insert(&mut self, signal: DataForSeoGrowthSignal) {
        let key = Self::key(
            signal.request().request_digest().as_str(),
            signal.read_observation().page_sequence(),
        );
        self.pages.insert(key, signal);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoRegistrationState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoServiceDefinition {
    service_id: String,
    provider_id: String,
    adapter_id: String,
    adapter_version: u32,
    capability_id: String,
    read_only: bool,
}

impl DataForSeoServiceDefinition {
    fn new() -> Self {
        Self {
            service_id: "growth-signal.dataforseo.labs.read".to_owned(),
            provider_id: DATAFORSEO_PROVIDER_ID.to_owned(),
            adapter_id: DATAFORSEO_LABS_ADAPTER_ID.to_owned(),
            adapter_version: DATAFORSEO_LABS_ADAPTER_VERSION,
            capability_id: DATAFORSEO_LABS_READ_CAPABILITY.to_owned(),
            read_only: true,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoServiceRegistration {
    registration_id: String,
    service_id: String,
    provider_id: String,
    adapter_id: String,
    scope_digest: String,
    request_digest: String,
    state: DataForSeoRegistrationState,
    revoked_at: Option<DateTime<Utc>>,
    revocation_reason_digest: Option<String>,
}

impl DataForSeoServiceRegistration {
    pub fn registration_id(&self) -> &str {
        &self.registration_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn state(&self) -> DataForSeoRegistrationState {
        self.state
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn revocation_reason_digest(&self) -> Option<&str> {
        self.revocation_reason_digest.as_deref()
    }
}

pub struct DataForSeoLabsService<T: DataForSeoLabsTransport> {
    definition: DataForSeoServiceDefinition,
    registration: DataForSeoServiceRegistration,
    scope: ConnectorScope,
    request: DataForSeoKeywordRequest,
    secret: SecretReference,
    lease: CredentialLease,
    worker: ConnectorWorker<DataForSeoLabsAdapter<T>>,
    adapter_state: Arc<Mutex<AdapterState>>,
    session: Option<AuthSession>,
    probe: Option<ProbeResult>,
    live_probe: Option<LiveProbeFence>,
    ledger: DataForSeoReplayLedger,
}

impl<T: DataForSeoLabsTransport> fmt::Debug for DataForSeoLabsService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoLabsService")
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request.request_digest())
            .field("worker", &self.worker)
            .field("ledger_page_count", &self.ledger.page_count())
            .finish_non_exhaustive()
    }
}

impl<T: DataForSeoLabsTransport> DataForSeoLabsService<T> {
    pub fn new(
        secret: SecretReference,
        request: DataForSeoKeywordRequest,
        transport: T,
        policy: DataForSeoTimeoutRetryPolicy,
        now: DateTime<Utc>,
        ledger: DataForSeoReplayLedger,
    ) -> Result<Self, DataForSeoError> {
        let adapter = DataForSeoLabsAdapter::new(transport, policy)?;
        Self::new_with_adapter(secret, request, adapter, now, ledger)
    }

    fn new_with_adapter(
        secret: SecretReference,
        request: DataForSeoKeywordRequest,
        adapter: DataForSeoLabsAdapter<T>,
        now: DateTime<Utc>,
        ledger: DataForSeoReplayLedger,
    ) -> Result<Self, DataForSeoError> {
        if secret.scope() != request.scope() {
            return Err(DataForSeoError::ScopeMismatch);
        }
        let scope = request.scope().clone();
        let adapter_state = adapter.state_handle();
        let registry = dataforseo_registry()?;
        let worker_id = format!("worker-dataforseo-{}", &scope.digest()[..20]);
        let lease_expires_at = now + Duration::minutes(10);
        let worker = ConnectorWorker::new(
            worker_id,
            adapter,
            registry,
            scope.clone(),
            now,
            lease_expires_at,
        )
        .map_err(DataForSeoError::Connector)?;
        let adapter_identity = ProviderAdapterIdentity::new(
            DATAFORSEO_LABS_ADAPTER_ID,
            DATAFORSEO_LABS_ADAPTER_VERSION,
        )
        .map_err(ConnectorError::from)?;
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter_identity,
            format!("lease-dataforseo-{}", &scope.digest()[..20]),
            1,
            now,
            now + Duration::minutes(10),
        )
        .map_err(DataForSeoError::Connector)?;
        let definition = DataForSeoServiceDefinition::new();
        let request_digest = request.request_digest();
        let registration_digest =
            canonical_digest(&[scope.digest().as_str(), request_digest.as_str()]);
        let registration = DataForSeoServiceRegistration {
            registration_id: format!("dataforseo-registration-{registration_digest}"),
            service_id: definition.service_id().to_owned(),
            provider_id: definition.provider_id().to_owned(),
            adapter_id: definition.adapter_id().to_owned(),
            scope_digest: scope.digest(),
            request_digest,
            state: DataForSeoRegistrationState::Unmounted,
            revoked_at: None,
            revocation_reason_digest: None,
        };
        Ok(Self {
            definition,
            registration,
            scope,
            request,
            secret,
            lease,
            worker,
            adapter_state,
            session: None,
            probe: None,
            live_probe: None,
            ledger,
        })
    }

    pub fn definition(&self) -> &DataForSeoServiceDefinition {
        &self.definition
    }

    pub fn registration(&self) -> &DataForSeoServiceRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn request(&self) -> &DataForSeoKeywordRequest {
        &self.request
    }

    pub fn ledger(&self) -> DataForSeoReplayLedger {
        self.ledger.clone()
    }

    pub fn mount(&mut self, now: DateTime<Utc>) -> Result<(), DataForSeoError> {
        match self.registration.state {
            DataForSeoRegistrationState::Mounted => return Ok(()),
            DataForSeoRegistrationState::Revoked => return Err(DataForSeoError::Revoked),
            DataForSeoRegistrationState::Unmounted => {}
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, now, now + Duration::minutes(10))
                .map_err(DataForSeoError::Connector)?;
        }
        let dispatch = self.worker.dispatch_fence();
        let session = self
            .worker
            .begin_auth(BeginAuthRequest {
                dispatch: dispatch.clone(),
                scope: self.scope.clone(),
                secret_reference: self.secret.clone(),
                credential_lease: self.lease.clone(),
                auth_revision: 1,
                issued_at: now,
                expires_at: now + Duration::minutes(5),
            })
            .map_err(DataForSeoError::Connector)?;
        let probe = self
            .worker
            .probe(ProbeRequest {
                dispatch: dispatch.clone(),
                scope: self.scope.clone(),
                secret_reference: self.secret.clone(),
                credential_lease: self.lease.clone(),
                session: session.clone(),
                probe_revision: 1,
                result_id: format!("probe-result-dataforseo-{}", &self.scope.digest()[..20]),
                at: now,
            })
            .map_err(DataForSeoError::Connector)?;
        let live_probe = self
            .worker
            .authorize_probe(&probe, now)
            .map_err(DataForSeoError::Connector)?;
        self.session = Some(session);
        self.probe = Some(probe);
        self.live_probe = Some(live_probe);
        self.registration.state = DataForSeoRegistrationState::Mounted;
        Ok(())
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<(), DataForSeoError> {
        if self.registration.state == DataForSeoRegistrationState::Revoked {
            return Err(DataForSeoError::Revoked);
        }
        if self.registration.state == DataForSeoRegistrationState::Mounted {
            let dispatch = self.worker.dispatch_fence();
            self.worker
                .cancel(&dispatch, at)
                .map_err(DataForSeoError::Connector)?;
            self.session = None;
            self.probe = None;
            self.live_probe = None;
            let mut state = self
                .adapter_state
                .lock()
                .map_err(|_| DataForSeoError::StateUnavailable)?;
            state.account_probe = None;
            state.labs_status = None;
            state.bound_pages.clear();
            state.signals.clear();
            self.registration.state = DataForSeoRegistrationState::Unmounted;
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason_digest: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<(), DataForSeoError> {
        let reason_digest = reason_digest.into();
        if !is_sha256(&reason_digest) {
            return Err(DataForSeoError::InvalidRequest);
        }
        if self.registration.state == DataForSeoRegistrationState::Revoked {
            return Err(DataForSeoError::Revoked);
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, at, at + Duration::minutes(10))
                .map_err(DataForSeoError::Connector)?;
        }
        let dispatch = self.worker.dispatch_fence();
        self.worker
            .revoke(RevokeRequest {
                dispatch,
                scope: self.scope.clone(),
                reason_digest: reason_digest.clone(),
                at,
            })
            .map_err(DataForSeoError::Connector)?;
        let _ = self.secret.revoke(at);
        self.registration.state = DataForSeoRegistrationState::Revoked;
        self.registration.revoked_at = Some(at);
        self.registration.revocation_reason_digest = Some(reason_digest);
        self.session = None;
        self.probe = None;
        self.live_probe = None;
        Ok(())
    }

    pub fn read(
        &mut self,
        cursor: Option<&DataForSeoCursor>,
        at: DateTime<Utc>,
        budget: DispatchBudget,
    ) -> Result<DataForSeoGrowthSignal, DataForSeoError> {
        if self.registration.state != DataForSeoRegistrationState::Mounted {
            return Err(match self.registration.state {
                DataForSeoRegistrationState::Revoked => DataForSeoError::Revoked,
                DataForSeoRegistrationState::Unmounted | DataForSeoRegistrationState::Mounted => {
                    DataForSeoError::NotMounted
                }
            });
        }
        let request_digest = self.request.request_digest();
        let sequence = cursor.map_or(1, DataForSeoCursor::sequence);
        if let Some(cached) = self.ledger.replay(&request_digest, sequence) {
            return Ok(cached);
        }
        let source_revision = self
            .adapter_state
            .lock()
            .map_err(|_| DataForSeoError::StateUnavailable)?
            .labs_status
            .as_ref()
            .map(DataForSeoLabsStatus::source_revision)
            .ok_or(DataForSeoError::ProviderPending)?;
        if let Some(cursor) = cursor {
            cursor.validate(
                &self.scope,
                &request_digest,
                self.request.limit(),
                source_revision,
            )?;
        }
        bind_page_in_state(&self.adapter_state, self.request.clone(), cursor.cloned())?;
        let dispatch = self.worker.dispatch_fence();
        let live_probe = self
            .live_probe
            .clone()
            .ok_or(DataForSeoError::ProviderPending)?;
        let observation = self
            .worker
            .read(ReadRequest {
                dispatch,
                scope: self.scope.clone(),
                live_probe,
                capability: ProviderCapabilityKey::new(
                    DATAFORSEO_PROVIDER_ID,
                    DATAFORSEO_LABS_READ_CAPABILITY,
                )
                .map_err(ConnectorError::from)?,
                query_digest: request_digest,
                cursor: cursor
                    .map(|cursor| cursor.sdk_cursor(&self.scope))
                    .transpose()?,
                page_size: self.request.limit(),
                at,
                budget,
            })
            .map_err(DataForSeoError::Connector)?;
        let signal = take_signal_in_state(&self.adapter_state, observation.observation_id())?;
        self.ledger.record(signal.clone());
        Ok(signal)
    }
}

fn bind_page_in_state(
    state: &Arc<Mutex<AdapterState>>,
    request: DataForSeoKeywordRequest,
    cursor: Option<DataForSeoCursor>,
) -> Result<(), DataForSeoError> {
    request.validate()?;
    let request_digest = request.request_digest();
    let sequence = cursor.as_ref().map_or(0, DataForSeoCursor::sequence);
    let mut state = state
        .lock()
        .map_err(|_| DataForSeoError::StateUnavailable)?;
    if state.revoked {
        return Err(DataForSeoError::Revoked);
    }
    state
        .bound_pages
        .insert((request_digest, sequence), BoundPage { request, cursor });
    Ok(())
}

fn take_signal_in_state(
    state: &Arc<Mutex<AdapterState>>,
    observation_id: &str,
) -> Result<DataForSeoGrowthSignal, DataForSeoError> {
    state
        .lock()
        .map_err(|_| DataForSeoError::StateUnavailable)?
        .signals
        .remove(observation_id)
        .ok_or(DataForSeoError::StateUnavailable)
}

fn replayed_signal(signal: &DataForSeoGrowthSignal) -> DataForSeoGrowthSignal {
    let mut replay = signal.clone();
    replay.replayed = true;
    replay.charged = false;
    replay.usage.provider_cost_usd = Decimal::ZERO;
    replay.usage.charged = false;
    replay.usage.attempts = 0;
    replay
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoLabsWorld {
    PaginatedResults,
    EmptyResult,
    InvalidPageToken,
    QuotaExhausted,
    StaleResult,
    RetryOnce,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoRequestRecord {
    method: DataForSeoHttpMethod,
    path: String,
    body_digest: Option<String>,
}

impl DataForSeoRequestRecord {
    pub const fn method(&self) -> DataForSeoHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> Option<&str> {
        self.body_digest.as_deref()
    }
}

/// Deterministic provider world used by contract tests and local harnesses.
/// It is explicitly controlled-provider evidence and cannot pass the SDK
/// production-only authorize_probe fence.
#[derive(Clone, Debug)]
pub struct FakeDataForSeoLabsTransport {
    scenario: DataForSeoLabsWorld,
    requests: Vec<DataForSeoRequestRecord>,
    billable_calls: u64,
    transient_failures_left: u8,
}

impl FakeDataForSeoLabsTransport {
    pub fn new(scenario: DataForSeoLabsWorld) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
            billable_calls: 0,
            transient_failures_left: u8::from(scenario == DataForSeoLabsWorld::RetryOnce),
        }
    }

    pub fn scenario(&self) -> DataForSeoLabsWorld {
        self.scenario
    }

    pub fn requests(&self) -> &[DataForSeoRequestRecord] {
        &self.requests
    }

    pub const fn billable_calls(&self) -> u64 {
        self.billable_calls
    }
}

impl DataForSeoLabsTransport for FakeDataForSeoLabsTransport {
    fn execute(
        &mut self,
        request: DataForSeoHttpRequest,
    ) -> Result<DataForSeoHttpResponse, DataForSeoError> {
        self.requests.push(DataForSeoRequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest: request.body_digest(),
        });
        if self.transient_failures_left > 0 {
            self.transient_failures_left -= 1;
            return DataForSeoHttpResponse::new(
                503,
                BTreeMap::new(),
                json!({"status_code": 50000, "status_message": "retry"}),
            );
        }
        match (request.method, request.path.as_str()) {
            (DataForSeoHttpMethod::Get, DATAFORSEO_USER_DATA_PATH) => fake_user_data_response(),
            (DataForSeoHttpMethod::Get, DATAFORSEO_LABS_STATUS_PATH) => {
                fake_status_response(self.scenario)
            }
            (DataForSeoHttpMethod::Post, DATAFORSEO_LABS_KEYWORDS_FOR_SITE_PATH) => {
                self.billable_calls = self.billable_calls.saturating_add(1);
                let body = request
                    .body
                    .as_ref()
                    .ok_or(DataForSeoError::InvalidRequest)?;
                if self.scenario == DataForSeoLabsWorld::QuotaExhausted {
                    return DataForSeoHttpResponse::new(
                        200,
                        BTreeMap::new(),
                        json!({
                            "status_code": 40200,
                            "status_message": "quota",
                            "cost": 0,
                            "tasks": []
                        }),
                    );
                }
                if self.scenario == DataForSeoLabsWorld::InvalidPageToken
                    && body.get("offset_token").is_some()
                {
                    return DataForSeoHttpResponse::new(
                        200,
                        BTreeMap::new(),
                        json!({
                            "status_code": 20000,
                            "version": "0.1.fixture",
                            "cost": 0.01,
                            "tasks": [{
                                "id": "11111111-1111-4111-8111-111111111111",
                                "status_code": 40501,
                                "cost": 0.01,
                                "result": []
                            }]
                        }),
                    );
                }
                let offset_token = body.get("offset_token").and_then(Value::as_str);
                fake_keyword_response(self.scenario, offset_token)
            }
            _ => Err(DataForSeoError::InvalidEndpoint),
        }
    }
}

fn fake_headers(remaining: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("x-ratelimit-limit".to_owned(), "2000".to_owned()),
        ("x-ratelimit-remaining".to_owned(), remaining.to_string()),
    ])
}

fn fake_user_data_response() -> Result<DataForSeoHttpResponse, DataForSeoError> {
    DataForSeoHttpResponse::new(
        200,
        fake_headers(1999),
        json!({
            "version": "0.1.fixture",
            "status_code": 20000,
            "cost": 0,
            "tasks": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "status_code": 20000,
                "cost": 0,
                "result": [{
                    "login": "controlled@example.invalid",
                    "timezone": "UTC"
                }]
            }]
        }),
    )
}

fn fake_status_response(
    scenario: DataForSeoLabsWorld,
) -> Result<DataForSeoHttpResponse, DataForSeoError> {
    let date = if scenario == DataForSeoLabsWorld::StaleResult {
        "2020-01-01"
    } else {
        "2026-08-14"
    };
    DataForSeoHttpResponse::new(
        200,
        fake_headers(1998),
        json!({
            "version": "0.1.fixture",
            "status_code": 20000,
            "cost": 0,
            "tasks": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "status_code": 20000,
                "cost": 0,
                "result": [{
                    "google": {"date_update": date},
                    "bing": {"date_update": date},
                    "amazon": {"date_update": date}
                }]
            }]
        }),
    )
}

fn fake_keyword_response(
    scenario: DataForSeoLabsWorld,
    offset_token: Option<&str>,
) -> Result<DataForSeoHttpResponse, DataForSeoError> {
    let second_page = offset_token.is_some();
    let items = if scenario == DataForSeoLabsWorld::EmptyResult {
        Vec::new()
    } else if second_page {
        vec![fake_keyword_item("second fixture keyword", 2_400)]
    } else {
        vec![
            fake_keyword_item("fixture growth keyword", 1_200),
            fake_keyword_item("fixture demand signal", 800),
        ]
    };
    let next_token = if matches!(
        scenario,
        DataForSeoLabsWorld::PaginatedResults | DataForSeoLabsWorld::InvalidPageToken
    ) && !second_page
    {
        Some("fixture-offset-token-2")
    } else {
        None
    };
    let result = json!({
        "target": "example.com",
        "location_code": 2840,
        "language_code": "en",
        "total_count": if scenario == DataForSeoLabsWorld::EmptyResult { 0 } else { 3 },
        "items_count": items.len(),
        "offset": if second_page { 2 } else { 0 },
        "offset_token": next_token,
        "items": items
    });
    DataForSeoHttpResponse::new(
        200,
        fake_headers(1997),
        json!({
            "version": "0.1.fixture",
            "status_code": 20000,
            "cost": 0.01,
            "tasks": [{
                "id": if second_page {
                    "22222222-2222-4222-8222-222222222222"
                } else {
                    "11111111-1111-4111-8111-111111111111"
                },
                "status_code": 20000,
                "cost": 0.01,
                "result": [result]
            }]
        }),
    )
}

fn fake_keyword_item(keyword: &str, search_volume: u64) -> Value {
    json!({
        "keyword": keyword,
        "location_code": 2840,
        "language_code": "en",
        "keyword_info": {
            "search_volume": search_volume,
            "competition": 0.42,
            "competition_level": "MEDIUM",
            "cpc": 1.25,
            "categories": ["fixture.category"],
            "last_updated_time": "2026-08-01 00:00:00 +00:00",
            "monthly_searches": [{
                "year": 2026,
                "month": 8,
                "search_volume": search_volume
            }],
            "search_volume_trend": {
                "monthly": 4,
                "quarterly": 8,
                "yearly": 12
            }
        }
    })
}
