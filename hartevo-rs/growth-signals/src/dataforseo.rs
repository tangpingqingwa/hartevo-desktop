//! DataForSEO v3 read-only SERP task adapter.
//!
//! The public surface keeps Basic-auth credentials behind an opaque
//! `SecretReference`. The HTTP transport receives resolved credentials only
//! at construction, and request/response debug output contains digests rather
//! than query or credential material.

use std::{collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    ConnectorDescriptor, ConnectorError, ConnectorScope, Cursor, ProviderProvenanceClass,
    ReadObservation, SecretReference,
};
use reqwest::blocking::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::{
    EvidenceClassification, Freshness, ProviderReceiptReference, ReadScope, canonical_digest,
    response_digest,
};

pub const DATAFORSEO_PROVIDER_ID: &str = "dataforseo";
pub const DATAFORSEO_API_BASE_URL: &str = "https://api.dataforseo.com/";
pub const DATAFORSEO_STANDARD_RESULT_MAX_AGE: Duration = Duration::days(30);
pub const DATAFORSEO_MAX_DEPTH: u16 = 700;
pub const DATAFORSEO_MAX_PAGE_SIZE: usize = 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoMode {
    Live,
    Standard,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoDevice {
    Desktop,
    Mobile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCallback {
    task_id: DataForSeoTaskId,
    mode: DataForSeoCallbackMode,
    body: Option<Value>,
}

impl DataForSeoCallback {
    pub fn pingback(task_id: DataForSeoTaskId) -> Self {
        Self {
            task_id,
            mode: DataForSeoCallbackMode::Pingback,
            body: None,
        }
    }

    pub fn postback(task_id: DataForSeoTaskId, body: Value) -> Self {
        Self {
            task_id,
            mode: DataForSeoCallbackMode::Postback,
            body: Some(body),
        }
    }

    pub const fn task_id(&self) -> &DataForSeoTaskId {
        &self.task_id
    }

    pub const fn mode(&self) -> DataForSeoCallbackMode {
        self.mode
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoCallbackMode {
    Pingback,
    Postback,
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoSearchRequest {
    scope: ReadScope,
    keyword: String,
    location_code: u32,
    language_code: String,
    device: DataForSeoDevice,
    depth: u16,
    mode: DataForSeoMode,
    callback: Option<DataForSeoCallbackRequest>,
    estimated_cost_usd: Decimal,
    cost_limit_usd: Option<Decimal>,
    max_age_seconds: u64,
}

impl DataForSeoSearchRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ReadScope,
        keyword: impl Into<String>,
        location_code: u32,
        device: DataForSeoDevice,
        depth: u16,
        mode: DataForSeoMode,
        estimated_cost_usd: Decimal,
        cost_limit_usd: Option<Decimal>,
    ) -> Result<Self, DataForSeoError> {
        let keyword = keyword.into();
        let language_code = scope.language().as_str().to_owned();
        if keyword.trim().is_empty()
            || keyword.len() > 700
            || location_code == 0
            || depth == 0
            || depth > DATAFORSEO_MAX_DEPTH
            || estimated_cost_usd.is_sign_negative()
            || cost_limit_usd.is_some_and(|limit| limit.is_sign_negative())
        {
            return Err(DataForSeoError::InvalidRequest);
        }
        if cost_limit_usd.is_some_and(|limit| estimated_cost_usd > limit) {
            return Err(DataForSeoError::CostLimitExceeded {
                estimated: estimated_cost_usd,
                limit: cost_limit_usd.expect("limit is present"),
            });
        }
        Ok(Self {
            scope,
            keyword,
            location_code,
            language_code,
            device,
            depth,
            mode,
            callback: None,
            estimated_cost_usd,
            cost_limit_usd,
            max_age_seconds: match mode {
                DataForSeoMode::Live => 3_600,
                DataForSeoMode::Standard => {
                    u64::try_from(DATAFORSEO_STANDARD_RESULT_MAX_AGE.num_seconds())
                        .expect("DataForSEO standard freshness is positive")
                }
            },
        })
    }

    #[must_use]
    pub fn with_callback(mut self, callback: DataForSeoCallbackRequest) -> Self {
        self.callback = Some(callback);
        self
    }

    pub const fn scope(&self) -> &ReadScope {
        &self.scope
    }

    pub fn keyword(&self) -> &str {
        &self.keyword
    }

    pub const fn location_code(&self) -> u32 {
        self.location_code
    }

    pub fn language_code(&self) -> &str {
        &self.language_code
    }

    pub const fn mode(&self) -> DataForSeoMode {
        self.mode
    }

    pub fn cost_limit_usd(&self) -> Option<Decimal> {
        self.cost_limit_usd
    }

    pub fn request_digest(&self) -> String {
        canonical_digest(self)
    }

    pub fn estimate_only_evidence(&self) -> DataForSeoEstimateEvidence {
        DataForSeoEstimateEvidence {
            scope: self.scope.clone(),
            request_digest: self.request_digest(),
            estimated_cost_usd: self.estimated_cost_usd,
            classification: EvidenceClassification::ProviderEstimate,
            first_party: false,
        }
    }

    fn body(&self) -> Value {
        let mut body = json!({
            "keyword": self.keyword,
            "location_code": self.location_code,
            "language_code": self.language_code,
            "device": match self.device {
                DataForSeoDevice::Desktop => "desktop",
                DataForSeoDevice::Mobile => "mobile",
            },
            "depth": self.depth,
        });
        if let Some(callback) = &self.callback {
            match callback.mode {
                DataForSeoCallbackMode::Pingback => {
                    body["pingback_url"] = Value::String(callback.url.clone());
                }
                DataForSeoCallbackMode::Postback => {
                    body["postback_url"] = Value::String(callback.url.clone());
                    body["postback_data"] = Value::String("advanced".into());
                }
            }
        }
        body
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCallbackRequest {
    mode: DataForSeoCallbackMode,
    url: String,
}

impl DataForSeoCallbackRequest {
    pub fn new(
        mode: DataForSeoCallbackMode,
        url: impl Into<String>,
    ) -> Result<Self, DataForSeoError> {
        let url = url.into();
        let parsed = Url::parse(&url).map_err(|_| DataForSeoError::InvalidRequest)?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(DataForSeoError::InvalidRequest);
        }
        Ok(Self { mode, url })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoEstimateEvidence {
    scope: ReadScope,
    request_digest: String,
    estimated_cost_usd: Decimal,
    classification: EvidenceClassification,
    first_party: bool,
}

impl DataForSeoEstimateEvidence {
    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub fn estimated_cost_usd(&self) -> Decimal {
        self.estimated_cost_usd
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoRateLimit {
    limit_per_minute: Option<u64>,
    remaining: Option<u64>,
}

impl DataForSeoRateLimit {
    fn from_headers(headers: &BTreeMap<String, String>) -> Self {
        Self {
            limit_per_minute: header_u64(headers, "x-ratelimit-limit"),
            remaining: header_u64(headers, "x-ratelimit-remaining"),
        }
    }

    pub const fn limit_per_minute(&self) -> Option<u64> {
        self.limit_per_minute
    }

    pub const fn remaining(&self) -> Option<u64> {
        self.remaining
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoSerpItem {
    rank_absolute: Option<u32>,
    item_type: Option<String>,
    title: Option<String>,
    url: Option<String>,
}

impl DataForSeoSerpItem {
    fn from_value(value: &Value) -> Self {
        Self {
            rank_absolute: value
                .get("rank_absolute")
                .and_then(Value::as_u64)
                .and_then(|rank| u32::try_from(rank).ok()),
            item_type: value.get("type").and_then(Value::as_str).map(str::to_owned),
            title: value
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_owned),
            url: value.get("url").and_then(Value::as_str).map(str::to_owned),
        }
    }

    pub fn rank_absolute(&self) -> Option<u32> {
        self.rank_absolute
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoSearchObservation {
    scope: ReadScope,
    keyword: String,
    mode: DataForSeoMode,
    task_id: Option<DataForSeoTaskId>,
    items: Vec<DataForSeoSerpItem>,
    cost_usd: Decimal,
    rate_limit: DataForSeoRateLimit,
    freshness: Freshness,
    classification: EvidenceClassification,
    first_party: bool,
    receipt_reference: ProviderReceiptReference,
    response_digest: String,
    raw_evidence_digest: String,
    source_revision: u64,
    replayed: bool,
}

impl DataForSeoSearchObservation {
    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub fn items(&self) -> &[DataForSeoSerpItem] {
        &self.items
    }

    pub const fn scope(&self) -> &ReadScope {
        &self.scope
    }

    pub fn keyword(&self) -> &str {
        &self.keyword
    }

    pub fn cost_usd(&self) -> Decimal {
        self.cost_usd
    }

    pub const fn rate_limit(&self) -> &DataForSeoRateLimit {
        &self.rate_limit
    }

    pub const fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    pub const fn task_id(&self) -> Option<&DataForSeoTaskId> {
        self.task_id.as_ref()
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub const fn receipt_reference(&self) -> &ProviderReceiptReference {
        &self.receipt_reference
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }
}

/// A provider-specific durable page cursor backed by the merged Connector SDK
/// cursor. The offset is intentionally kept next to the SDK cursor because
/// DataForSEO returns a bounded SERP result, not a provider page token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoPageCursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    token_digest: String,
    offset: usize,
    page_size: usize,
    source_revision: u64,
}

impl DataForSeoPageCursor {
    fn new(
        scope: &ConnectorScope,
        request_digest: &str,
        sequence: u64,
        offset: usize,
        page_size: usize,
        source_revision: u64,
    ) -> Result<Self, DataForSeoError> {
        let token_digest = canonical_digest(&(request_digest, offset, page_size, source_revision));
        let sdk_cursor = crate::sdk::cursor(scope, request_digest, sequence, &token_digest)
            .map_err(DataForSeoError::Connector)?;
        Ok(Self {
            scope_digest: sdk_cursor.scope_digest().to_owned(),
            request_digest: sdk_cursor.request_digest().to_owned(),
            sequence: sdk_cursor.sequence(),
            token_digest: sdk_cursor.token_digest().to_owned(),
            offset,
            page_size,
            source_revision,
        })
    }

    pub fn sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, DataForSeoError> {
        if self.scope_digest != scope.digest() {
            return Err(DataForSeoError::InvalidCursor);
        }
        crate::sdk::cursor(
            scope,
            &self.request_digest,
            self.sequence,
            &self.token_digest,
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

    pub const fn offset(&self) -> usize {
        self.offset
    }

    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    fn validate(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        page_size: usize,
        source_revision: u64,
    ) -> Result<(), DataForSeoError> {
        let expected_token = canonical_digest(&(
            request_digest,
            self.offset,
            self.page_size,
            self.source_revision,
        ));
        if self.scope_digest != scope.digest()
            || self.request_digest != request_digest
            || self.token_digest != expected_token
            || self.sequence == 0
            || self.page_size != page_size
            || self.source_revision != source_revision
        {
            return Err(DataForSeoError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoSearchPage {
    observation: DataForSeoSearchObservation,
    cursor: Option<DataForSeoPageCursor>,
    next_cursor: Option<DataForSeoPageCursor>,
    page_sequence: u64,
    items: Vec<DataForSeoSerpItem>,
    charged: bool,
}

impl DataForSeoSearchPage {
    pub const fn observation(&self) -> &DataForSeoSearchObservation {
        &self.observation
    }

    pub fn items(&self) -> &[DataForSeoSerpItem] {
        &self.items
    }

    pub const fn cursor(&self) -> Option<&DataForSeoPageCursor> {
        self.cursor.as_ref()
    }

    pub const fn next_cursor(&self) -> Option<&DataForSeoPageCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.observation.replayed()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoTaskReceipt {
    task_id: DataForSeoTaskId,
    request_digest: String,
    endpoint: String,
    submitted_at: DateTime<Utc>,
    cost_usd: Decimal,
    rate_limit: DataForSeoRateLimit,
    raw_evidence_digest: String,
    callback_mode: Option<DataForSeoCallbackMode>,
    charged: bool,
}

impl DataForSeoTaskReceipt {
    pub const fn task_id(&self) -> &DataForSeoTaskId {
        &self.task_id
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub const fn submitted_at(&self) -> DateTime<Utc> {
        self.submitted_at
    }

    pub fn cost_usd(&self) -> Decimal {
        self.cost_usd
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn rate_limit(&self) -> &DataForSeoRateLimit {
        &self.rate_limit
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoTaskSubmission {
    receipt: DataForSeoTaskReceipt,
    replayed: bool,
}

impl DataForSeoTaskSubmission {
    pub const fn receipt(&self) -> &DataForSeoTaskReceipt {
        &self.receipt
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataForSeoTaskState {
    Pending,
    Ready,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoPendingTask {
    task_id: DataForSeoTaskId,
    receipt: DataForSeoTaskReceipt,
    replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DataForSeoTaskPoll {
    Pending(DataForSeoPendingTask),
    Ready(Box<DataForSeoSearchObservation>),
}

impl DataForSeoTaskPoll {
    pub const fn state(&self) -> DataForSeoTaskState {
        match self {
            Self::Pending(_) => DataForSeoTaskState::Pending,
            Self::Ready(_) => DataForSeoTaskState::Ready,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoReplayLedger {
    submissions: BTreeMap<String, DataForSeoTaskReceipt>,
    observations: BTreeMap<String, DataForSeoSearchObservation>,
    request_observations: BTreeMap<String, DataForSeoSearchObservation>,
}

impl DataForSeoReplayLedger {
    pub fn submission_count(&self) -> usize {
        self.submissions.len()
    }

    pub fn observation_count(&self) -> usize {
        self.request_observations.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DataForSeoError {
    #[error("DataForSEO request is invalid")]
    InvalidRequest,
    #[error("DataForSEO task id is invalid")]
    InvalidTaskId,
    #[error("DataForSEO credential scope is invalid")]
    InvalidSecretScope,
    #[error("DataForSEO provider returned an invalid response")]
    MalformedResponse,
    #[error("DataForSEO provider returned HTTP {http_status} and code {provider_code}")]
    ProviderStatus {
        http_status: u16,
        provider_code: u32,
    },
    #[error("DataForSEO task is not ready")]
    TaskNotReady,
    #[error("DataForSEO result is stale")]
    StaleResult,
    #[error("DataForSEO cost limit exceeded: estimated {estimated}, limit {limit}")]
    CostLimitExceeded { estimated: Decimal, limit: Decimal },
    #[error("DataForSEO transport failed")]
    Transport,
    #[error("DataForSEO page cursor is invalid")]
    InvalidCursor,
    #[error("Connector SDK rejected DataForSEO metadata: {0}")]
    Connector(ConnectorError),
}

pub trait DataForSeoTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: DataForSeoHttpRequest,
    ) -> Result<DataForSeoHttpResponse, DataForSeoError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataForSeoHttpMethod {
    Get,
    Post,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoHttpRequest {
    method: DataForSeoHttpMethod,
    path: String,
    body: Option<Value>,
}

impl DataForSeoHttpRequest {
    fn new(method: DataForSeoHttpMethod, path: impl Into<String>, body: Option<Value>) -> Self {
        Self {
            method,
            path: path.into(),
            body,
        }
    }

    pub fn method(&self) -> DataForSeoHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> Option<String> {
        self.body.as_ref().map(canonical_digest)
    }
}

impl fmt::Debug for DataForSeoHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("bodyDigest", &self.body_digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
    raw_evidence_digest: String,
}

impl DataForSeoHttpResponse {
    pub fn new(status: u16, headers: BTreeMap<String, String>, body: Value) -> Self {
        let raw_evidence_digest = response_digest(&body);
        Self::with_raw_evidence_digest(status, headers, body, raw_evidence_digest)
    }

    fn with_raw_evidence_digest(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
        raw_evidence_digest: String,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            raw_evidence_digest,
        }
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }
}

impl fmt::Debug for DataForSeoHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("rawEvidenceDigest", &self.raw_evidence_digest)
            .finish_non_exhaustive()
    }
}

pub struct DataForSeoHttpTransport {
    client: Client,
    base_url: Url,
    login: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl fmt::Debug for DataForSeoHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoHttpTransport")
            .field("base_url", &self.base_url)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl DataForSeoHttpTransport {
    pub fn new(
        base_url: impl AsRef<str>,
        login: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, DataForSeoError> {
        let base_url = Url::parse(base_url.as_ref()).map_err(|_| DataForSeoError::Transport)?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(DataForSeoError::Transport);
        }
        Ok(Self {
            client: Client::builder()
                .build()
                .map_err(|_| DataForSeoError::Transport)?,
            base_url,
            login: Zeroizing::new(login.into()),
            password: Zeroizing::new(password.into()),
        })
    }

    pub fn production(
        login: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, DataForSeoError> {
        Self::new(DATAFORSEO_API_BASE_URL, login, password)
    }
}

impl DataForSeoTransport for DataForSeoHttpTransport {
    fn execute(
        &mut self,
        request: DataForSeoHttpRequest,
    ) -> Result<DataForSeoHttpResponse, DataForSeoError> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| DataForSeoError::Transport)?;
        let method = match request.method {
            DataForSeoHttpMethod::Get => reqwest::Method::GET,
            DataForSeoHttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self
            .client
            .request(method, url)
            .basic_auth(self.login.as_str(), Some(self.password.as_str()));
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }
        let response = builder.send().map_err(|_| DataForSeoError::Transport)?;
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
        let raw_evidence_digest = format!("{:x}", Sha256::digest(&bytes));
        let body = serde_json::from_slice::<Value>(&bytes)
            .map_err(|_| DataForSeoError::MalformedResponse)?;
        Ok(DataForSeoHttpResponse::with_raw_evidence_digest(
            status,
            headers,
            body,
            raw_evidence_digest,
        ))
    }
}

pub struct DataForSeoClient<T> {
    secret_reference: SecretReference,
    transport: T,
    replay: DataForSeoReplayLedger,
}

impl<T: DataForSeoTransport> fmt::Debug for DataForSeoClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoClient")
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("replay", &self.replay)
            .finish()
    }
}

impl<T: DataForSeoTransport> DataForSeoClient<T> {
    pub fn new(secret_reference: SecretReference, transport: T) -> Result<Self, DataForSeoError> {
        if secret_reference.scope().provider_id() != DATAFORSEO_PROVIDER_ID {
            return Err(DataForSeoError::InvalidSecretScope);
        }
        Ok(Self {
            secret_reference,
            transport,
            replay: DataForSeoReplayLedger::default(),
        })
    }

    pub fn secret_reference_id(&self) -> &str {
        self.secret_reference.reference_id()
    }

    pub const fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn connector_descriptor() -> Result<ConnectorDescriptor, ConnectorError> {
        crate::sdk::descriptor_for(DATAFORSEO_PROVIDER_ID, "hartevo.dataforseo")
    }

    pub fn sdk_read_observation(
        &self,
        observation: &DataForSeoSearchObservation,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, ConnectorError> {
        let descriptor = Self::connector_descriptor()?;
        let request_digest = observation.receipt_reference().request_digest();
        let response_digest = observation.response_digest().to_owned();
        ReadObservation::new(
            format!("read-observation-{request_digest}"),
            self.secret_reference.scope().clone(),
            crate::sdk::capability(DATAFORSEO_PROVIDER_ID, "search.measure")?,
            descriptor.identity().clone(),
            request_digest.to_owned(),
            observation.raw_evidence_digest().to_owned(),
            response_digest,
            provenance,
            crate::sdk::freshness(
                observation.freshness().observed_at(),
                observation.freshness().valid_until(),
                observation.source_revision(),
            )?,
            1,
            u32::try_from(observation.items().len()).unwrap_or(u32::MAX),
            None,
        )
    }

    pub fn sdk_read_page_observation(
        &self,
        page: &DataForSeoSearchPage,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, ConnectorError> {
        let descriptor = Self::connector_descriptor()?;
        let observation = page.observation();
        let request_digest = observation.receipt_reference().request_digest();
        ReadObservation::new(
            format!(
                "read-observation-{request_digest}-page-{}",
                page.page_sequence()
            ),
            self.secret_reference.scope().clone(),
            crate::sdk::capability(DATAFORSEO_PROVIDER_ID, "search.measure")?,
            descriptor.identity().clone(),
            request_digest.to_owned(),
            observation.raw_evidence_digest().to_owned(),
            observation.response_digest().to_owned(),
            provenance,
            crate::sdk::freshness(
                observation.freshness().observed_at(),
                observation.freshness().valid_until(),
                observation.source_revision(),
            )?,
            page.page_sequence(),
            u32::try_from(page.items().len()).unwrap_or(u32::MAX),
            page.next_cursor()
                .map(|cursor| {
                    crate::sdk::cursor(
                        self.secret_reference.scope(),
                        cursor.request_digest(),
                        cursor.sequence(),
                        cursor.token_digest(),
                    )
                })
                .transpose()?,
        )
    }

    pub const fn replay_ledger(&self) -> &DataForSeoReplayLedger {
        &self.replay
    }

    pub fn read_live(
        &mut self,
        request: &DataForSeoSearchRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<DataForSeoSearchObservation, DataForSeoError> {
        if request.mode != DataForSeoMode::Live {
            return Err(DataForSeoError::InvalidRequest);
        }
        Self::ensure_estimate_within_budget(request)?;
        let path = "/v3/serp/google/organic/live/regular";
        let request_digest = request.request_digest();
        if let Some(observation) = self.replay.request_observations.get(&request_digest) {
            if !observation.freshness.is_fresh_at(observed_at) {
                return Err(DataForSeoError::StaleResult);
            }
            let mut replayed = observation.clone();
            replayed.replayed = true;
            return Ok(replayed);
        }
        let response = self.transport.execute(DataForSeoHttpRequest::new(
            DataForSeoHttpMethod::Post,
            path,
            Some(Value::Array(vec![request.body()])),
        ))?;
        let observation = Self::parse_observation(
            request,
            &response,
            observed_at,
            path,
            request_digest.clone(),
            None,
            false,
        )?;
        self.replay
            .request_observations
            .insert(request_digest, observation.clone());
        Ok(observation)
    }

    pub fn read_live_page(
        &mut self,
        request: &DataForSeoSearchRequest,
        page_size: usize,
        cursor: Option<&DataForSeoPageCursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<DataForSeoSearchPage, DataForSeoError> {
        if request.mode != DataForSeoMode::Live
            || page_size == 0
            || page_size > DATAFORSEO_MAX_PAGE_SIZE
        {
            return Err(DataForSeoError::InvalidRequest);
        }
        let observation = self.read_live(request, observed_at)?;
        let request_digest = request.request_digest();
        let (offset, page_sequence) = if let Some(cursor) = cursor {
            cursor.validate(
                self.secret_reference.scope(),
                &request_digest,
                page_size,
                observation.source_revision(),
            )?;
            (cursor.offset, cursor.sequence)
        } else {
            (0, 1)
        };
        if cursor.is_some() && offset >= observation.items.len() {
            return Err(DataForSeoError::InvalidCursor);
        }
        let end = offset
            .saturating_add(page_size)
            .min(observation.items.len());
        let items = observation.items[offset..end].to_vec();
        let next_cursor = if end < observation.items.len() {
            Some(DataForSeoPageCursor::new(
                self.secret_reference.scope(),
                &request_digest,
                page_sequence.saturating_add(1),
                end,
                page_size,
                observation.source_revision(),
            )?)
        } else {
            None
        };
        Ok(DataForSeoSearchPage {
            charged: !observation.replayed && offset == 0,
            observation,
            cursor: cursor.cloned(),
            next_cursor,
            page_sequence,
            items,
        })
    }

    pub fn begin_standard(
        &mut self,
        request: &DataForSeoSearchRequest,
        submitted_at: DateTime<Utc>,
    ) -> Result<DataForSeoTaskSubmission, DataForSeoError> {
        if request.mode != DataForSeoMode::Standard {
            return Err(DataForSeoError::InvalidRequest);
        }
        Self::ensure_estimate_within_budget(request)?;
        let request_digest = request.request_digest();
        if let Some(receipt) = self.replay.submissions.get(&request_digest) {
            return Ok(DataForSeoTaskSubmission {
                receipt: receipt.clone(),
                replayed: true,
            });
        }
        let path = "/v3/serp/google/organic/task_post";
        let response = self.transport.execute(DataForSeoHttpRequest::new(
            DataForSeoHttpMethod::Post,
            path,
            Some(Value::Array(vec![request.body()])),
        ))?;
        let (task, rate) = parse_task(&response)?;
        let task_id = task_id_from(&task)?;
        let callback_mode = request.callback.as_ref().map(|callback| callback.mode);
        let receipt = DataForSeoTaskReceipt {
            task_id,
            request_digest,
            endpoint: path.into(),
            submitted_at,
            cost_usd: decimal_field(&task, "cost")?,
            rate_limit: rate,
            raw_evidence_digest: response.raw_evidence_digest().to_owned(),
            callback_mode,
            charged: true,
        };
        self.replay
            .submissions
            .insert(receipt.request_digest.clone(), receipt.clone());
        Ok(DataForSeoTaskSubmission {
            receipt,
            replayed: false,
        })
    }

    pub fn poll_standard(
        &mut self,
        request: &DataForSeoSearchRequest,
        submission: &DataForSeoTaskSubmission,
        observed_at: DateTime<Utc>,
    ) -> Result<DataForSeoTaskPoll, DataForSeoError> {
        if request.mode != DataForSeoMode::Standard
            || submission.receipt.request_digest != request.request_digest()
        {
            return Err(DataForSeoError::InvalidRequest);
        }
        let task_id = &submission.receipt.task_id;
        if let Some(observation) = self.replay.observations.get(task_id.as_str()) {
            if !observation.freshness.is_fresh_at(observed_at) {
                return Err(DataForSeoError::StaleResult);
            }
            let mut replayed = observation.clone();
            replayed.replayed = true;
            return Ok(DataForSeoTaskPoll::Ready(Box::new(replayed)));
        }
        let path = format!("/v3/serp/google/organic/task_get/regular/{task_id}");
        let response = self.transport.execute(DataForSeoHttpRequest::new(
            DataForSeoHttpMethod::Get,
            path.clone(),
            None,
        ))?;
        if task_is_pending(&response.body)? {
            return Ok(DataForSeoTaskPoll::Pending(DataForSeoPendingTask {
                task_id: task_id.clone(),
                receipt: submission.receipt.clone(),
                replayed: false,
            }));
        }
        let observation = Self::parse_observation(
            request,
            &response,
            observed_at,
            &path,
            request.request_digest(),
            Some(task_id.clone()),
            false,
        )?;
        self.replay
            .observations
            .insert(task_id.as_str().to_owned(), observation.clone());
        self.replay
            .request_observations
            .insert(request.request_digest(), observation.clone());
        Ok(DataForSeoTaskPoll::Ready(Box::new(observation)))
    }

    pub fn accept_callback(
        &mut self,
        request: &DataForSeoSearchRequest,
        callback: DataForSeoCallback,
        observed_at: DateTime<Utc>,
    ) -> Result<DataForSeoTaskPoll, DataForSeoError> {
        if request.mode != DataForSeoMode::Standard {
            return Err(DataForSeoError::InvalidRequest);
        }
        let submission = self
            .replay
            .submissions
            .get(&request.request_digest())
            .cloned()
            .ok_or(DataForSeoError::InvalidRequest)?;
        if submission.task_id != callback.task_id {
            return Err(DataForSeoError::InvalidRequest);
        }
        if callback.mode == DataForSeoCallbackMode::Postback
            && let Some(observation) = self
                .replay
                .request_observations
                .get(&request.request_digest())
        {
            if !observation.freshness.is_fresh_at(observed_at) {
                return Err(DataForSeoError::StaleResult);
            }
            let mut replayed = observation.clone();
            replayed.replayed = true;
            return Ok(DataForSeoTaskPoll::Ready(Box::new(replayed)));
        }
        match callback.mode {
            DataForSeoCallbackMode::Pingback => {
                Ok(DataForSeoTaskPoll::Pending(DataForSeoPendingTask {
                    task_id: submission.task_id.clone(),
                    receipt: submission,
                    replayed: false,
                }))
            }
            DataForSeoCallbackMode::Postback => {
                let response = DataForSeoHttpResponse::new(
                    200,
                    BTreeMap::new(),
                    callback.body.ok_or(DataForSeoError::MalformedResponse)?,
                );
                let observation = Self::parse_observation(
                    request,
                    &response,
                    observed_at,
                    "/callback/postback",
                    request.request_digest(),
                    Some(callback.task_id),
                    false,
                )?;
                self.replay.observations.insert(
                    observation
                        .task_id
                        .as_ref()
                        .expect("postback task id")
                        .as_str()
                        .to_owned(),
                    observation.clone(),
                );
                self.replay
                    .request_observations
                    .insert(request.request_digest(), observation.clone());
                Ok(DataForSeoTaskPoll::Ready(Box::new(observation)))
            }
        }
    }

    fn ensure_estimate_within_budget(
        request: &DataForSeoSearchRequest,
    ) -> Result<(), DataForSeoError> {
        if let Some(limit) = request.cost_limit_usd
            && request.estimated_cost_usd > limit
        {
            return Err(DataForSeoError::CostLimitExceeded {
                estimated: request.estimated_cost_usd,
                limit,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_observation(
        request: &DataForSeoSearchRequest,
        response: &DataForSeoHttpResponse,
        observed_at: DateTime<Utc>,
        endpoint: &str,
        request_digest: String,
        task_id: Option<DataForSeoTaskId>,
        replayed: bool,
    ) -> Result<DataForSeoSearchObservation, DataForSeoError> {
        let (task, rate) = parse_task(response)?;
        let cost_usd = decimal_field(&task, "cost")?;
        if let Some(limit) = request.cost_limit_usd
            && cost_usd > limit
        {
            return Err(DataForSeoError::CostLimitExceeded {
                estimated: cost_usd,
                limit,
            });
        }
        let completed_at = task
            .get("completed_at")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<DateTime<Utc>>().ok())
            .unwrap_or(observed_at);
        let max_age_seconds =
            i64::try_from(request.max_age_seconds).map_err(|_| DataForSeoError::InvalidRequest)?;
        let valid_until = completed_at + Duration::seconds(max_age_seconds);
        if observed_at >= valid_until {
            return Err(DataForSeoError::StaleResult);
        }
        let freshness = Freshness::new(completed_at, valid_until)
            .map_err(|_| DataForSeoError::MalformedResponse)?;
        let response_digest = response_digest(&task);
        let raw_evidence_digest = response.raw_evidence_digest().to_owned();
        let source_revision = source_revision_for(&raw_evidence_digest);
        let mut items = Vec::new();
        if let Some(results) = task.get("result").and_then(Value::as_array) {
            for result in results {
                if let Some(result_items) = result.get("items").and_then(Value::as_array) {
                    items.extend(result_items.iter().map(DataForSeoSerpItem::from_value));
                } else if result.get("url").is_some() {
                    items.push(DataForSeoSerpItem::from_value(result));
                }
            }
        }
        Ok(DataForSeoSearchObservation {
            scope: request.scope.clone(),
            keyword: request.keyword.clone(),
            mode: request.mode,
            task_id: task_id.or_else(|| task_id_from(&task).ok()),
            items,
            cost_usd,
            rate_limit: rate,
            freshness,
            classification: EvidenceClassification::ProviderEstimate,
            first_party: false,
            receipt_reference: ProviderReceiptReference::new(
                DATAFORSEO_PROVIDER_ID,
                "read",
                endpoint,
                request_digest,
                response_digest.clone(),
                None,
                task_id_from(&task).ok().map(|id| id.as_str().to_owned()),
            ),
            response_digest,
            raw_evidence_digest,
            source_revision,
            replayed,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataForSeoWorldScenario {
    Results,
    PaginatedResults,
    EmptyResult,
    DelayedTask,
    StaleResult,
    CostLimit,
    RateLimited,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct FakeDataForSeoTransport {
    scenario: DataForSeoWorldScenario,
    requests: Vec<DataForSeoRequestRecord>,
    task_polls: u32,
}

impl FakeDataForSeoTransport {
    pub fn new(scenario: DataForSeoWorldScenario) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
            task_polls: 0,
        }
    }

    pub fn requests(&self) -> &[DataForSeoRequestRecord] {
        &self.requests
    }
}

impl DataForSeoTransport for FakeDataForSeoTransport {
    fn execute(
        &mut self,
        request: DataForSeoHttpRequest,
    ) -> Result<DataForSeoHttpResponse, DataForSeoError> {
        let body_digest = request.body_digest();
        self.requests.push(DataForSeoRequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest,
        });
        let headers = if self.scenario == DataForSeoWorldScenario::RateLimited {
            BTreeMap::from([
                ("x-ratelimit-limit".into(), "60".into()),
                ("x-ratelimit-remaining".into(), "0".into()),
            ])
        } else {
            BTreeMap::from([
                ("x-ratelimit-limit".into(), "60".into()),
                ("x-ratelimit-remaining".into(), "59".into()),
            ])
        };
        if self.scenario == DataForSeoWorldScenario::RateLimited {
            return Err(DataForSeoError::ProviderStatus {
                http_status: 429,
                provider_code: 42900,
            });
        }
        let task_id = "00000000-0000-0000-0000-000000000001";
        let cost = if self.scenario == DataForSeoWorldScenario::CostLimit {
            0.30
        } else {
            0.10
        };
        let completed_at = if self.scenario == DataForSeoWorldScenario::StaleResult {
            "2026-07-01T00:00:00Z"
        } else {
            "2026-08-13T00:00:00Z"
        };
        let response = if request.path.ends_with("task_post") {
            json!({
                "status_code": 20000,
                "tasks": [{"id": task_id, "status_code": 20100, "cost": cost}]
            })
        } else if request.path.contains("task_get") {
            self.task_polls += 1;
            if self.scenario == DataForSeoWorldScenario::DelayedTask && self.task_polls == 1 {
                json!({
                    "status_code": 20000,
                    "tasks": [{"id": task_id, "status_code": 40602, "cost": cost, "result": null}]
                })
            } else {
                json!({
                    "status_code": 20000,
                    "tasks": [{
                        "id": task_id,
                        "status_code": 20000,
                        "cost": cost,
                        "completed_at": completed_at,
                        "result": fake_result(self.scenario)
                    }]
                })
            }
        } else {
            json!({
                "status_code": 20000,
                "tasks": [{
                    "id": task_id,
                    "status_code": 20000,
                    "cost": cost,
                    "completed_at": completed_at,
                    "result": fake_result(self.scenario)
                }]
            })
        };
        Ok(DataForSeoHttpResponse::new(200, headers, response))
    }
}

fn parse_task(
    response: &DataForSeoHttpResponse,
) -> Result<(Value, DataForSeoRateLimit), DataForSeoError> {
    let rate = DataForSeoRateLimit::from_headers(&response.headers);
    let provider_code = response
        .body
        .get("status_code")
        .and_then(Value::as_u64)
        .and_then(|code| u32::try_from(code).ok())
        .ok_or(DataForSeoError::MalformedResponse)?;
    if response.status >= 400 || provider_code >= 40000 {
        return Err(DataForSeoError::ProviderStatus {
            http_status: response.status,
            provider_code,
        });
    }
    let task = response
        .body
        .get("tasks")
        .and_then(Value::as_array)
        .and_then(|tasks| tasks.first())
        .cloned()
        .ok_or(DataForSeoError::MalformedResponse)?;
    let task_code = task
        .get("status_code")
        .and_then(Value::as_u64)
        .and_then(|code| u32::try_from(code).ok())
        .ok_or(DataForSeoError::MalformedResponse)?;
    if task_code >= 40000 && task_code != 40602 {
        return Err(DataForSeoError::ProviderStatus {
            http_status: response.status,
            provider_code: task_code,
        });
    }
    Ok((task, rate))
}

fn task_is_pending(body: &Value) -> Result<bool, DataForSeoError> {
    let task = body
        .get("tasks")
        .and_then(Value::as_array)
        .and_then(|tasks| tasks.first())
        .ok_or(DataForSeoError::MalformedResponse)?;
    Ok(task
        .get("status_code")
        .and_then(Value::as_u64)
        .is_some_and(|code| code == 40602 || task.get("result").is_some_and(Value::is_null)))
}

fn task_id_from(task: &Value) -> Result<DataForSeoTaskId, DataForSeoError> {
    DataForSeoTaskId::new(
        task.get("id")
            .and_then(Value::as_str)
            .ok_or(DataForSeoError::MalformedResponse)?,
    )
}

fn decimal_field(task: &Value, field: &str) -> Result<Decimal, DataForSeoError> {
    let value = task.get(field).ok_or(DataForSeoError::MalformedResponse)?;
    Decimal::from_str(&value.to_string()).map_err(|_| DataForSeoError::MalformedResponse)
}

fn header_u64(headers: &BTreeMap<String, String>, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|value| value.parse::<u64>().ok())
}

fn fake_result(scenario: DataForSeoWorldScenario) -> Value {
    if scenario == DataForSeoWorldScenario::EmptyResult {
        json!([])
    } else if scenario == DataForSeoWorldScenario::PaginatedResults {
        json!([{"items":[
            {"type":"organic","rank_absolute":1,"title":"Example one","url":"https://example.com/one"},
            {"type":"organic","rank_absolute":2,"title":"Example two","url":"https://example.com/two"},
            {"type":"organic","rank_absolute":3,"title":"Example three","url":"https://example.com/three"}
        ]}])
    } else {
        json!([{"items":[{"type":"organic","rank_absolute":1,"title":"Example","url":"https://example.com/"}]}])
    }
}

fn source_revision_for(raw_evidence_digest: &str) -> u64 {
    // DataForSEO does not expose a revision token for a SERP payload. Binding
    // the SDK freshness revision to the first digest word makes the revision
    // deterministic and changes it whenever the captured evidence changes.
    u64::from_str_radix(
        raw_evidence_digest.get(..16).unwrap_or(raw_evidence_digest),
        16,
    )
    .unwrap_or(1)
    .max(1)
}

pub fn dataforseo_scope(reference: &SecretReference) -> Result<&ConnectorScope, DataForSeoError> {
    if reference.scope().provider_id() != DATAFORSEO_PROVIDER_ID {
        return Err(DataForSeoError::InvalidSecretScope);
    }
    Ok(reference.scope())
}

pub fn dataforseo_password_digest(password: &str) -> String {
    format!("{:x}", Sha256::digest(password.as_bytes()))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_connector_sdk::ConnectorScope;
    use hartevo_domain_kernel::{ProjectId, TenantId};
    use rust_decimal::Decimal;

    use super::*;
    use crate::common::{CalendarDateRange, LanguageCode, MarketCode, parse_date};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time")
    }

    fn scope() -> ReadScope {
        ReadScope::new(
            TenantId::from("tenant-signal"),
            ProjectId::from("project-signal"),
            MarketCode::new("DE").expect("market"),
            LanguageCode::new("de").expect("language"),
            CalendarDateRange::new(
                parse_date("2026-08-01").expect("date"),
                parse_date("2026-08-07").expect("date"),
            )
            .expect("window"),
        )
    }

    fn secret() -> SecretReference {
        SecretReference::new(
            "secret-ref-dataforseo",
            ConnectorScope::new(
                "tenant-signal",
                "project-signal",
                DATAFORSEO_PROVIDER_ID,
                "dataforseo-account",
                ["serp.read".into()],
            )
            .expect("scope"),
            1,
        )
        .expect("secret")
    }

    fn request(mode: DataForSeoMode) -> DataForSeoSearchRequest {
        DataForSeoSearchRequest::new(
            scope(),
            "kaffee filter",
            2276,
            DataForSeoDevice::Desktop,
            10,
            mode,
            Decimal::new(10, 2),
            Some(Decimal::new(20, 2)),
        )
        .expect("request")
    }

    #[test]
    fn live_results_are_estimates_and_capture_rate_headers_and_cost() {
        let transport = FakeDataForSeoTransport::new(DataForSeoWorldScenario::Results);
        let mut client = DataForSeoClient::new(secret(), transport).expect("client");
        let observation = client
            .read_live(&request(DataForSeoMode::Live), now())
            .expect("read");
        assert_eq!(
            observation.classification(),
            EvidenceClassification::ProviderEstimate
        );
        assert!(!observation.first_party());
        assert_eq!(observation.cost_usd(), Decimal::new(10, 2));
        assert_eq!(observation.rate_limit().remaining(), Some(59));
        assert_eq!(observation.items().len(), 1);
        assert_eq!(
            observation.receipt_reference().provider_id(),
            DATAFORSEO_PROVIDER_ID
        );
    }

    #[test]
    fn repeated_live_request_replays_without_a_second_billable_dispatch() {
        let transport = FakeDataForSeoTransport::new(DataForSeoWorldScenario::Results);
        let mut client = DataForSeoClient::new(secret(), transport).expect("client");
        let request = request(DataForSeoMode::Live);
        let first = client.read_live(&request, now()).expect("first read");
        let replayed = client.read_live(&request, now()).expect("replay");
        assert!(!first.replayed());
        assert!(replayed.replayed());
        assert_eq!(client.replay_ledger().observation_count(), 1);
    }

    #[test]
    fn page_cursor_round_trips_and_replays_the_billable_observation() {
        let transport = FakeDataForSeoTransport::new(DataForSeoWorldScenario::PaginatedResults);
        let mut client = DataForSeoClient::new(secret(), transport).expect("client");
        let request = request(DataForSeoMode::Live);
        let first = client
            .read_live_page(&request, 2, None, now())
            .expect("first page");
        let cursor = first.next_cursor().expect("next cursor").clone();
        let encoded = serde_json::to_string(&cursor).expect("cursor JSON");
        let restored: DataForSeoPageCursor =
            serde_json::from_str(&encoded).expect("durable cursor");
        let second = client
            .read_live_page(&request, 2, Some(&restored), now())
            .expect("second page");
        assert_eq!(second.page_sequence(), 2);
        assert_eq!(second.items().len(), 1);
        assert!(second.replayed());
        assert!(!second.charged());
        assert_eq!(client.replay_ledger().observation_count(), 1);
        assert_eq!(restored.offset(), 2);
        assert_eq!(
            restored
                .sdk_cursor(client.secret_reference().scope())
                .expect("SDK cursor")
                .sequence(),
            2
        );
        assert_ne!(
            first.observation().response_digest(),
            first.observation().raw_evidence_digest()
        );
    }

    #[test]
    fn standard_task_supports_delay_polling_and_durable_replay() {
        let transport = FakeDataForSeoTransport::new(DataForSeoWorldScenario::DelayedTask);
        let mut client = DataForSeoClient::new(secret(), transport).expect("client");
        let request = request(DataForSeoMode::Standard);
        let submission = client.begin_standard(&request, now()).expect("submit");
        assert!(!submission.replayed());
        assert_eq!(submission.receipt().rate_limit().remaining(), Some(59));
        assert!(matches!(
            client
                .poll_standard(&request, &submission, now())
                .expect("poll"),
            DataForSeoTaskPoll::Pending(_)
        ));
        let ready = client
            .poll_standard(&request, &submission, now())
            .expect("poll");
        assert_eq!(ready.state(), DataForSeoTaskState::Ready);
        let replayed = client
            .poll_standard(&request, &submission, now())
            .expect("replay");
        assert!(
            matches!(replayed, DataForSeoTaskPoll::Ready(ref observation) if observation.replayed())
        );
        assert_eq!(client.replay_ledger().submission_count(), 1);
        assert_eq!(client.replay_ledger().observation_count(), 1);
    }

    #[test]
    fn pingback_is_a_completion_signal_and_postback_is_typed() {
        let transport = FakeDataForSeoTransport::new(DataForSeoWorldScenario::Results);
        let mut client = DataForSeoClient::new(secret(), transport).expect("client");
        let request = request(DataForSeoMode::Standard);
        let submission = client.begin_standard(&request, now()).expect("submit");
        let pingback = DataForSeoCallback::pingback(submission.receipt().task_id.clone());
        assert!(matches!(
            client
                .accept_callback(&request, pingback, now())
                .expect("pingback"),
            DataForSeoTaskPoll::Pending(_)
        ));
        let postback_body = json!({
            "status_code": 20000,
            "tasks": [{"id": submission.receipt().task_id.as_str(), "status_code": 20000, "cost": 0.10, "completed_at":"2026-08-13T00:00:00Z", "result":[{"items":[]}]}]
        });
        assert!(matches!(
            client
                .accept_callback(
                    &request,
                    DataForSeoCallback::postback(
                        submission.receipt().task_id.clone(),
                        postback_body
                    ),
                    now()
                )
                .expect("postback"),
            DataForSeoTaskPoll::Ready(_)
        ));
    }

    #[test]
    fn stale_and_estimated_cost_limit_fail_before_first_party_claim() {
        let stale_transport = FakeDataForSeoTransport::new(DataForSeoWorldScenario::StaleResult);
        let mut stale = DataForSeoClient::new(secret(), stale_transport).expect("client");
        let mut stale_request = request(DataForSeoMode::Live);
        stale_request.max_age_seconds = 60;
        assert_eq!(
            stale.read_live(&stale_request, now()),
            Err(DataForSeoError::StaleResult)
        );

        let expensive = DataForSeoSearchRequest::new(
            scope(),
            "term",
            2276,
            DataForSeoDevice::Desktop,
            10,
            DataForSeoMode::Live,
            Decimal::new(30, 2),
            Some(Decimal::new(20, 2)),
        );
        assert!(matches!(
            expensive,
            Err(DataForSeoError::CostLimitExceeded { .. })
        ));
        assert_eq!(
            request(DataForSeoMode::Live)
                .estimate_only_evidence()
                .classification(),
            EvidenceClassification::ProviderEstimate
        );
    }

    #[test]
    fn wrong_provider_secret_is_rejected_without_dispatch() {
        let reference = SecretReference::new(
            "secret-ref-other",
            ConnectorScope::new(
                "tenant-signal",
                "project-signal",
                "google-ads",
                "ads-account",
                ["https://www.googleapis.com/auth/adwords".into()],
            )
            .expect("scope"),
            1,
        )
        .expect("secret");
        assert!(matches!(
            DataForSeoClient::new(
                reference,
                FakeDataForSeoTransport::new(DataForSeoWorldScenario::Results)
            ),
            Err(DataForSeoError::InvalidSecretScope)
        ));
    }
}
