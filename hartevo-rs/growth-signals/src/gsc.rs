//! Google Search Console Search Analytics read adapter.
//!
//! The adapter owns only GSC request/response models and the HTTPS transport.
//! OAuth identity, scope fencing, cursor validation, worker lifecycle and
//! revocation are delegated to the Connector SDK.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration as StdDuration,
};

use chrono::{DateTime, Duration, NaiveDate, Utc};
use hartevo_connector_sdk::{
    AuthSession, BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorDescriptor,
    ConnectorError, ConnectorScope, ConnectorWorker, CredentialLease, Cursor, DispatchBudget,
    ExecuteRequest, FreshnessWindow, LiveProbeFence, PrepareEffectRequest, PreparedEffect,
    ProbeObservation, ProbeRequest, ProbeResult, ProviderAdapterIdentity, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderProvenanceClass, ReadObservation, ReadRequest, ReceiptCandidate,
    ReconcileRequest, ReconciliationObservation, RefreshAuthRequest, RevokeRequest,
    SecretReference, VerificationObservation, VerifyRequest, WebhookObservation, WebhookRequest,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    GSC_ADAPTER_ID, GSC_ADAPTER_VERSION, GSC_API_BASE_URL, GSC_API_VERSION, GSC_PROVIDER_ID,
    GSC_READ_CAPABILITY, GSC_READ_CONTRACT_JSON, GSC_SITES_PATH,
    SearchAnalyticsEvidenceClassification, SearchAnalyticsFreshness, SearchAnalyticsQuotaReceipt,
    SearchAnalyticsReadReceipt,
};

const MAX_PAGE_SIZE: u32 = 1_000;
const MAX_PROPERTY_LENGTH: usize = 2_048;
const MAX_DIMENSIONS: usize = 4;
const RESULT_TTL_SECONDS: i64 = 900;
const PROBE_TTL_SECONDS: i64 = 90;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscTimeWindow {
    start: NaiveDate,
    end: NaiveDate,
}

impl GscTimeWindow {
    pub fn new(start: NaiveDate, end: NaiveDate) -> Result<Self, GscError> {
        if start > end {
            return Err(GscError::InvalidRequest);
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscSearchRequest {
    scope: ConnectorScope,
    property: String,
    dimensions: Vec<String>,
    search_type: String,
    time_window: GscTimeWindow,
    row_limit: u32,
}

impl GscSearchRequest {
    pub fn new(
        scope: ConnectorScope,
        property: impl Into<String>,
        dimensions: Vec<String>,
        time_window: GscTimeWindow,
        row_limit: u32,
    ) -> Result<Self, GscError> {
        let request = Self {
            scope,
            property: property.into().trim().to_owned(),
            dimensions: dimensions
                .into_iter()
                .map(|dimension| dimension.trim().to_owned())
                .collect(),
            search_type: "web".to_owned(),
            time_window,
            row_limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn property(&self) -> &str {
        &self.property
    }

    pub fn dimensions(&self) -> &[String] {
        &self.dimensions
    }

    pub fn search_type(&self) -> &str {
        &self.search_type
    }

    pub const fn time_window(&self) -> &GscTimeWindow {
        &self.time_window
    }

    pub const fn row_limit(&self) -> u32 {
        self.row_limit
    }

    pub fn request_digest(&self) -> String {
        digest_json(self).unwrap_or_else(|_| sha256_bytes(self.property.as_bytes()))
    }

    fn provider_body(&self, cursor: Option<&GscCursor>) -> Value {
        let start_row = cursor.map_or(0, GscCursor::start_row);
        json!({
            "startDate": self.time_window.start.to_string(),
            "endDate": self.time_window.end.to_string(),
            "dimensions": self.dimensions,
            "type": self.search_type,
            "rowLimit": self.row_limit,
            "startRow": start_row,
        })
    }

    fn validate(&self) -> Result<(), GscError> {
        if self.scope.provider_id() != GSC_PROVIDER_ID
            || self.scope.scopes().is_empty()
            || !valid_property(&self.property)
            || self.dimensions.is_empty()
            || self.dimensions.len() > MAX_DIMENSIONS
            || self
                .dimensions
                .iter()
                .any(|dimension| !valid_dimension(dimension))
            || self.search_type != "web"
            || !(1..=MAX_PAGE_SIZE).contains(&self.row_limit)
        {
            return Err(GscError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscCursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    token_digest: String,
    start_row: u32,
    row_limit: u32,
    source_revision: u64,
}

impl fmt::Debug for GscCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscCursor")
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("sequence", &self.sequence)
            .field("token_digest", &self.token_digest)
            .field("start_row", &self.start_row)
            .field("row_limit", &self.row_limit)
            .field("source_revision", &self.source_revision)
            .finish()
    }
}

impl GscCursor {
    fn new(
        scope: &ConnectorScope,
        request_digest: &str,
        sequence: u64,
        start_row: u32,
        row_limit: u32,
        source_revision: u64,
    ) -> Result<Self, GscError> {
        if sequence == 0 || source_revision == 0 || !(1..=MAX_PAGE_SIZE).contains(&row_limit) {
            return Err(GscError::InvalidCursor);
        }
        let token_digest = canonical_digest(&[
            request_digest,
            &sequence.to_string(),
            &start_row.to_string(),
            &row_limit.to_string(),
            &source_revision.to_string(),
        ]);
        Ok(Self {
            scope_digest: scope.digest(),
            request_digest: request_digest.to_owned(),
            sequence,
            token_digest,
            start_row,
            row_limit,
            source_revision,
        })
    }

    pub fn sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, GscError> {
        if self.scope_digest != scope.digest() {
            return Err(GscError::ScopeMismatch);
        }
        Cursor::new(
            scope,
            self.request_digest.clone(),
            self.sequence,
            self.token_digest.clone(),
        )
        .map_err(GscError::Connector)
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

    pub const fn start_row(&self) -> u32 {
        self.start_row
    }

    pub const fn row_limit(&self) -> u32 {
        self.row_limit
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    fn validate(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        row_limit: u32,
        source_revision: u64,
    ) -> Result<(), GscError> {
        let expected = canonical_digest(&[
            request_digest,
            &self.sequence.to_string(),
            &self.start_row.to_string(),
            &self.row_limit.to_string(),
            &self.source_revision.to_string(),
        ]);
        if self.scope_digest != scope.digest()
            || self.request_digest != request_digest
            || self.token_digest != expected
            || self.row_limit != row_limit
            || self.source_revision != source_revision
        {
            return Err(GscError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscSearchRow {
    keys: Vec<String>,
    clicks: Option<f64>,
    impressions: Option<f64>,
    ctr: Option<f64>,
    position: Option<f64>,
}

impl GscSearchRow {
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    pub const fn clicks(&self) -> Option<f64> {
        self.clicks
    }

    pub const fn impressions(&self) -> Option<f64> {
        self.impressions
    }

    pub const fn ctr(&self) -> Option<f64> {
        self.ctr
    }

    pub const fn position(&self) -> Option<f64> {
        self.position
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscSearchPage {
    property: String,
    start_row: u32,
    row_limit: u32,
    rows: Vec<GscSearchRow>,
    has_more: bool,
    partial_access: bool,
}

impl GscSearchPage {
    pub fn property(&self) -> &str {
        &self.property
    }

    pub const fn start_row(&self) -> u32 {
        self.start_row
    }

    pub const fn row_limit(&self) -> u32 {
        self.row_limit
    }

    pub fn rows(&self) -> &[GscSearchRow] {
        &self.rows
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub const fn partial_access(&self) -> bool {
        self.partial_access
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscAccountProbe {
    scope: ConnectorScope,
    property: String,
    status: hartevo_connector_sdk::ProbeStatus,
    provenance_class: ProviderProvenanceClass,
    property_access: bool,
    partial_access: bool,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    source_revision: u64,
    evidence_digest: String,
    raw_evidence_digest: String,
    quota: SearchAnalyticsQuotaReceipt,
}

impl GscAccountProbe {
    pub const fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn property(&self) -> &str {
        &self.property
    }

    pub const fn status(&self) -> hartevo_connector_sdk::ProbeStatus {
        self.status
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub const fn property_access(&self) -> bool {
        self.property_access
    }

    pub const fn partial_access(&self) -> bool {
        self.partial_access
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn quota(&self) -> &SearchAnalyticsQuotaReceipt {
        &self.quota
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
pub struct GscReadObservation {
    observation_id: String,
    scope: ConnectorScope,
    capability: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    request_digest: String,
    response_digest: String,
    content_digest: String,
    provenance_class: ProviderProvenanceClass,
    freshness: SearchAnalyticsFreshness,
    page_sequence: u64,
    item_count: u32,
    next_cursor: Option<GscCursor>,
}

impl GscReadObservation {
    fn from_sdk(observation: &ReadObservation, next_cursor: Option<GscCursor>) -> Self {
        Self {
            observation_id: observation.observation_id().to_owned(),
            scope: observation.scope().clone(),
            capability: observation.capability().clone(),
            adapter: observation.adapter().clone(),
            request_digest: observation.request_digest().to_owned(),
            response_digest: observation.response_digest().to_owned(),
            content_digest: observation.content_digest().to_owned(),
            provenance_class: observation.provenance_class(),
            freshness: SearchAnalyticsFreshness {
                observed_at: observation.freshness().observed_at(),
                valid_until: observation.freshness().valid_until(),
                source_revision: observation.freshness().source_revision(),
            },
            page_sequence: observation.page_sequence(),
            item_count: observation.item_count(),
            next_cursor,
        }
    }

    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    pub const fn scope(&self) -> &ConnectorScope {
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

    pub const fn freshness(&self) -> &SearchAnalyticsFreshness {
        &self.freshness
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub const fn next_cursor(&self) -> Option<&GscCursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscGrowthSignal {
    scope: ConnectorScope,
    request: GscSearchRequest,
    property: String,
    source_uri: String,
    observed_at: DateTime<Utc>,
    freshness: SearchAnalyticsFreshness,
    source_revision: u64,
    raw_evidence_digest: String,
    content_digest: String,
    classification: SearchAnalyticsEvidenceClassification,
    first_party: bool,
    account_probe: GscAccountProbe,
    page: GscSearchPage,
    read_observation: GscReadObservation,
    receipt: SearchAnalyticsReadReceipt,
    quota: SearchAnalyticsQuotaReceipt,
    next_cursor: Option<GscCursor>,
    charged: bool,
    replayed: bool,
}

impl GscGrowthSignal {
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn request(&self) -> &GscSearchRequest {
        &self.request
    }

    pub fn property(&self) -> &str {
        &self.property
    }

    pub fn source_uri(&self) -> &str {
        &self.source_uri
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn freshness(&self) -> &SearchAnalyticsFreshness {
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

    pub const fn classification(&self) -> SearchAnalyticsEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn account_probe(&self) -> &GscAccountProbe {
        &self.account_probe
    }

    pub const fn page(&self) -> &GscSearchPage {
        &self.page
    }

    pub const fn read_observation(&self) -> &GscReadObservation {
        &self.read_observation
    }

    pub const fn receipt(&self) -> &SearchAnalyticsReadReceipt {
        &self.receipt
    }

    pub const fn quota(&self) -> &SearchAnalyticsQuotaReceipt {
        &self.quota
    }

    pub const fn next_cursor(&self) -> Option<&GscCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn page_sequence(&self) -> u64 {
        self.read_observation.page_sequence()
    }

    pub const fn item_count(&self) -> u32 {
        self.read_observation.item_count()
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
pub enum GscHttpMethod {
    Get,
    Post,
}

#[derive(Clone, PartialEq)]
pub struct GscHttpRequest {
    method: GscHttpMethod,
    path: String,
    body: Option<Value>,
}

impl fmt::Debug for GscHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_digest", &self.body_digest())
            .finish_non_exhaustive()
    }
}

impl GscHttpRequest {
    fn get(path: impl Into<String>) -> Self {
        Self {
            method: GscHttpMethod::Get,
            path: path.into(),
            body: None,
        }
    }

    fn post(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: GscHttpMethod::Post,
            path: path.into(),
            body: Some(body),
        }
    }

    pub const fn method(&self) -> GscHttpMethod {
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
pub struct GscHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
    raw_evidence_digest: String,
}

impl GscHttpResponse {
    pub fn new(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
    ) -> Result<Self, GscError> {
        let bytes = serde_json::to_vec(&body).map_err(|_| GscError::InvalidProviderResponse)?;
        Ok(Self {
            status,
            headers,
            body,
            raw_evidence_digest: sha256_bytes(&bytes),
        })
    }

    fn with_raw_digest(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
        raw_evidence_digest: String,
    ) -> Result<Self, GscError> {
        if !is_sha256(&raw_evidence_digest) {
            return Err(GscError::InvalidProviderResponse);
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscTimeoutRetryPolicy {
    timeout_ms: u64,
    max_attempts: u8,
    backoff_ms: u64,
    max_backoff_ms: u64,
}

impl GscTimeoutRetryPolicy {
    pub fn new(
        timeout_ms: u64,
        max_attempts: u8,
        backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Result<Self, GscError> {
        if !(1..=30_000).contains(&timeout_ms)
            || !(1..=4).contains(&max_attempts)
            || backoff_ms > max_backoff_ms
            || max_backoff_ms > 10_000
        {
            return Err(GscError::InvalidRetryPolicy);
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

impl Default for GscTimeoutRetryPolicy {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            max_attempts: 3,
            backoff_ms: 100,
            max_backoff_ms: 1_000,
        }
    }
}

pub struct GscOAuthCredentials {
    access_token: Zeroizing<String>,
}

impl fmt::Debug for GscOAuthCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscOAuthCredentials")
            .field("present", &true)
            .finish()
    }
}

impl GscOAuthCredentials {
    pub fn new(access_token: impl Into<String>) -> Result<Self, GscError> {
        let access_token = access_token.into();
        if access_token.trim().is_empty() {
            return Err(GscError::MissingCredential);
        }
        Ok(Self {
            access_token: Zeroizing::new(access_token),
        })
    }
}

pub trait GscTransport: fmt::Debug + Send {
    fn execute(&mut self, request: GscHttpRequest) -> Result<GscHttpResponse, GscError>;

    fn revoke(&mut self) {}
}

pub struct GscHttpTransport {
    client: Client,
    base_url: Url,
    credentials: GscOAuthCredentials,
}

impl fmt::Debug for GscHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscHttpTransport")
            .field("base_url", &self.base_url)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl GscHttpTransport {
    pub fn new(credentials: GscOAuthCredentials, timeout: StdDuration) -> Result<Self, GscError> {
        let base_url = Url::parse(GSC_API_BASE_URL).map_err(|_| GscError::InvalidEndpoint)?;
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| GscError::Transport)?;
        Ok(Self {
            client,
            base_url,
            credentials,
        })
    }

    pub fn production(
        credentials: GscOAuthCredentials,
        policy: &GscTimeoutRetryPolicy,
    ) -> Result<Self, GscError> {
        Self::new(credentials, StdDuration::from_millis(policy.timeout_ms()))
    }
}

impl GscTransport for GscHttpTransport {
    fn execute(&mut self, request: GscHttpRequest) -> Result<GscHttpResponse, GscError> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| GscError::InvalidEndpoint)?;
        let builder = match request.method {
            GscHttpMethod::Get => self.client.get(url),
            GscHttpMethod::Post => self.client.post(url),
        }
        .bearer_auth(self.credentials.access_token.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/json");
        let response = match request.body {
            Some(body) => builder.json(&body).send(),
            None => builder.send(),
        }
        .map_err(|error| {
            if error.is_timeout() {
                GscError::Timeout
            } else {
                GscError::Transport
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
        let bytes = response.bytes().map_err(|_| GscError::Transport)?;
        let raw_digest = sha256_bytes(&bytes);
        let body = serde_json::from_slice::<Value>(&bytes)
            .map_err(|_| GscError::InvalidProviderResponse)?;
        GscHttpResponse::with_raw_digest(status, headers, body, raw_digest)
    }

    fn revoke(&mut self) {
        self.credentials.access_token.zeroize();
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GscError {
    #[error("GSC request is invalid")]
    InvalidRequest,
    #[error("GSC endpoint is invalid")]
    InvalidEndpoint,
    #[error("GSC OAuth credential is missing")]
    MissingCredential,
    #[error("GSC cursor is invalid")]
    InvalidCursor,
    #[error("GSC retry policy is invalid")]
    InvalidRetryPolicy,
    #[error("GSC provider response is invalid")]
    InvalidProviderResponse,
    #[error("GSC provider returned HTTP status {0}")]
    ProviderHttpStatus(u16),
    #[error("GSC property access is denied")]
    PropertyAccessDenied,
    #[error("GSC provider quota is exhausted")]
    QuotaExhausted,
    #[error("GSC provider transport failed")]
    Transport,
    #[error("GSC provider request timed out")]
    Timeout,
    #[error("GSC service is not mounted")]
    NotMounted,
    #[error("GSC service is revoked")]
    Revoked,
    #[error("GSC service scope does not match")]
    ScopeMismatch,
    #[error("GSC provider freshness changed while paging")]
    FreshnessDrift,
    #[error("GSC connector state is unavailable")]
    StateUnavailable,
    #[error("Connector SDK rejected the GSC operation: {0}")]
    Connector(ConnectorError),
}

impl From<ConnectorError> for GscError {
    fn from(error: ConnectorError) -> Self {
        Self::Connector(error)
    }
}

#[derive(Clone, Debug)]
struct BoundPage {
    request: GscSearchRequest,
    cursor: Option<GscCursor>,
}

#[derive(Default)]
struct AdapterState {
    revoked: bool,
    bound_request: Option<GscSearchRequest>,
    account_probe: Option<GscAccountProbe>,
    bound_pages: BTreeMap<(String, u64), BoundPage>,
    signals: BTreeMap<String, GscGrowthSignal>,
}

pub struct GscAdapter<T: GscTransport> {
    descriptor: ConnectorDescriptor,
    transport: T,
    policy: GscTimeoutRetryPolicy,
    provenance: ProviderProvenanceClass,
    state: Arc<Mutex<AdapterState>>,
}

impl<T: GscTransport> fmt::Debug for GscAdapter<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscAdapter")
            .field("descriptor", &self.descriptor)
            .field("policy", &self.policy)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<T: GscTransport> Drop for GscAdapter<T> {
    fn drop(&mut self) {
        self.transport.revoke();
        if let Ok(mut state) = self.state.lock() {
            state.revoked = true;
            state.bound_request = None;
            state.account_probe = None;
            state.bound_pages.clear();
            state.signals.clear();
        }
    }
}

impl<T: GscTransport> GscAdapter<T> {
    pub fn new(transport: T, policy: GscTimeoutRetryPolicy) -> Result<Self, GscError> {
        Self::new_with_provenance(
            transport,
            policy,
            ProviderProvenanceClass::ProductionProvider,
        )
    }

    pub fn controlled(transport: T, policy: GscTimeoutRetryPolicy) -> Result<Self, GscError> {
        Self::new_with_provenance(
            transport,
            policy,
            ProviderProvenanceClass::ControlledProvider,
        )
    }

    fn new_with_provenance(
        transport: T,
        policy: GscTimeoutRetryPolicy,
        provenance: ProviderProvenanceClass,
    ) -> Result<Self, GscError> {
        let registry = gsc_registry()?;
        let descriptor = ConnectorDescriptor::new(
            ProviderAdapterIdentity::new(GSC_ADAPTER_ID, GSC_ADAPTER_VERSION)
                .map_err(ConnectorError::from)?,
            registry.registrations().iter().cloned(),
        )
        .map_err(GscError::Connector)?;
        Ok(Self {
            descriptor,
            transport,
            policy,
            provenance,
            state: Arc::new(Mutex::new(AdapterState::default())),
        })
    }

    pub fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    pub fn policy(&self) -> &GscTimeoutRetryPolicy {
        &self.policy
    }

    fn state_handle(&self) -> Arc<Mutex<AdapterState>> {
        Arc::clone(&self.state)
    }

    pub fn bind_request(&mut self, request: GscSearchRequest) -> Result<(), GscError> {
        request.validate()?;
        let mut state = self.lock_state()?;
        if state.revoked {
            return Err(GscError::Revoked);
        }
        state.bound_request = Some(request);
        Ok(())
    }

    pub fn account_probe(&self) -> Result<Option<GscAccountProbe>, GscError> {
        Ok(self.lock_state()?.account_probe.clone())
    }

    pub fn take_signal(&self, observation_id: &str) -> Result<GscGrowthSignal, GscError> {
        self.lock_state()?
            .signals
            .remove(observation_id)
            .ok_or(GscError::StateUnavailable)
    }

    pub fn read_controlled(
        &mut self,
        request: GscSearchRequest,
        cursor: Option<GscCursor>,
        at: DateTime<Utc>,
    ) -> Result<GscGrowthSignal, GscError> {
        let request_scope = request.scope().clone();
        let row_limit = request.row_limit();
        let request_digest = request.request_digest();
        self.bind_request(request.clone())?;
        if self.account_probe()?.is_none() {
            self.probe_transport(
                &request_scope,
                at,
                ProviderProvenanceClass::ControlledProvider,
            )?;
        }
        let sequence = cursor.as_ref().map_or(0, GscCursor::sequence);
        self.bind_page(request, cursor)?;
        let budget = DispatchBudget::new(100, at + Duration::minutes(1), 100, 0)
            .map_err(GscError::Connector)?;
        let capability = ProviderCapabilityKey::new(GSC_PROVIDER_ID, GSC_READ_CAPABILITY)
            .map_err(ConnectorError::from)?;
        let observation = self.read_bound(
            &request_scope,
            &capability,
            &request_digest,
            row_limit,
            at,
            &budget,
            sequence,
            ProviderProvenanceClass::ControlledProvider,
        )?;
        self.take_signal(observation.observation_id())
    }

    fn bind_page(
        &mut self,
        request: GscSearchRequest,
        cursor: Option<GscCursor>,
    ) -> Result<(), GscError> {
        request.validate()?;
        let request_digest = request.request_digest();
        let source_revision = self
            .account_probe()?
            .ok_or(GscError::StateUnavailable)?
            .source_revision();
        if let Some(cursor) = &cursor {
            cursor.validate(
                request.scope(),
                &request_digest,
                request.row_limit(),
                source_revision,
            )?;
        }
        let sequence = cursor.as_ref().map_or(0, GscCursor::sequence);
        self.lock_state()?
            .bound_pages
            .insert((request_digest, sequence), BoundPage { request, cursor });
        Ok(())
    }

    fn probe_transport(
        &mut self,
        scope: &ConnectorScope,
        at: DateTime<Utc>,
        provenance: ProviderProvenanceClass,
    ) -> Result<ProbeObservation, GscError> {
        let request = self
            .lock_state()?
            .bound_request
            .clone()
            .ok_or(GscError::InvalidRequest)?;
        if request.scope() != scope || scope.provider_id() != GSC_PROVIDER_ID {
            return Err(GscError::ScopeMismatch);
        }
        if self.lock_state()?.revoked {
            return Err(GscError::Revoked);
        }
        let response = self.execute_with_retry(&GscHttpRequest::get(GSC_SITES_PATH))?;
        if !(200..300).contains(&response.status()) {
            return Err(if response.status() == 429 {
                GscError::QuotaExhausted
            } else {
                GscError::ProviderHttpStatus(response.status())
            });
        }
        let sites = response
            .body()
            .get("siteEntry")
            .and_then(Value::as_array)
            .ok_or(GscError::InvalidProviderResponse)?;
        let property_access = sites.iter().any(|site| {
            site.get("siteUrl")
                .and_then(Value::as_str)
                .is_some_and(|value| value == request.property())
        });
        if !property_access {
            return Err(GscError::PropertyAccessDenied);
        }
        let partial_access = response
            .body()
            .get("partialAccess")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let source_revision = revision_from_digest(response.raw_evidence_digest());
        let provider_request_id =
            provider_request_id(response.headers(), response.raw_evidence_digest());
        let quota = quota_receipt(response.headers(), &provider_request_id, false);
        let expires_at = at + Duration::seconds(PROBE_TTL_SECONDS);
        let probe = GscAccountProbe {
            scope: scope.clone(),
            property: request.property().to_owned(),
            status: hartevo_connector_sdk::ProbeStatus::Reachable,
            provenance_class: provenance,
            property_access,
            partial_access,
            observed_at: at,
            expires_at,
            source_revision,
            evidence_digest: response.raw_evidence_digest().to_owned(),
            raw_evidence_digest: response.raw_evidence_digest().to_owned(),
            quota,
        };
        let observation = probe.sdk_observation()?;
        self.lock_state()?.account_probe = Some(probe);
        Ok(observation)
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
    ) -> Result<ReadObservation, GscError> {
        let bound = self
            .lock_state()?
            .bound_pages
            .remove(&(query_digest.to_owned(), sequence))
            .ok_or(GscError::InvalidRequest)?;
        if bound.request.scope() != scope || bound.request.request_digest() != query_digest {
            return Err(GscError::ScopeMismatch);
        }
        let probe = self.account_probe()?.ok_or(GscError::StateUnavailable)?;
        if let Some(cursor) = &bound.cursor {
            cursor.validate(scope, query_digest, page_size, probe.source_revision())?;
        }
        let response = self.execute_with_retry(&GscHttpRequest::post(
            search_path(bound.request.property()),
            bound.request.provider_body(bound.cursor.as_ref()),
        ))?;
        if !(200..300).contains(&response.status()) {
            return Err(if response.status() == 429 {
                GscError::QuotaExhausted
            } else if response.status() == 403 {
                GscError::PropertyAccessDenied
            } else {
                GscError::ProviderHttpStatus(response.status())
            });
        }
        let start_row = bound.cursor.as_ref().map_or(0, GscCursor::start_row);
        let page = parse_page(&response, &bound.request, start_row)?;
        let row_count =
            u32::try_from(page.rows().len()).map_err(|_| GscError::InvalidProviderResponse)?;
        let next_cursor = if page.has_more() {
            Some(GscCursor::new(
                scope,
                query_digest,
                bound
                    .cursor
                    .as_ref()
                    .map_or(2, |cursor| cursor.sequence() + 1),
                page.start_row().saturating_add(row_count),
                bound.request.row_limit(),
                probe.source_revision(),
            )?)
        } else {
            None
        };
        let content_digest = digest_json(&page)?;
        let response_digest = response.raw_evidence_digest().to_owned();
        let observation_id = format!(
            "read-observation-{}",
            &response_digest[..24.min(response_digest.len())]
        );
        let sdk_freshness = FreshnessWindow::new(
            at,
            at + Duration::seconds(RESULT_TTL_SECONDS),
            probe.source_revision(),
        )
        .map_err(GscError::Connector)?;
        let sdk_next_cursor = next_cursor
            .as_ref()
            .map(|cursor| cursor.sdk_cursor(scope))
            .transpose()?;
        let observation = ReadObservation::new(
            observation_id.clone(),
            scope.clone(),
            capability.clone(),
            self.descriptor.identity().clone(),
            query_digest.to_owned(),
            response_digest.clone(),
            content_digest.clone(),
            provenance,
            sdk_freshness.clone(),
            bound.cursor.as_ref().map_or(1, GscCursor::sequence),
            row_count,
            sdk_next_cursor,
        )
        .map_err(GscError::Connector)?;
        let provider_request_id = provider_request_id(response.headers(), &response_digest);
        let quota = quota_receipt(response.headers(), &provider_request_id, false);
        let signal = GscGrowthSignal {
            scope: scope.clone(),
            request: bound.request.clone(),
            property: bound.request.property().to_owned(),
            source_uri: format!(
                "gsc://{}/{}?request={}",
                scope.account_id(),
                bound.request.property(),
                query_digest
            ),
            observed_at: at,
            freshness: SearchAnalyticsFreshness::new(
                sdk_freshness.observed_at(),
                sdk_freshness.valid_until(),
                sdk_freshness.source_revision(),
            )
            .map_err(GscError::Connector)?,
            source_revision: probe.source_revision(),
            raw_evidence_digest: response_digest.clone(),
            content_digest,
            classification: match provenance {
                ProviderProvenanceClass::ProductionProvider => {
                    SearchAnalyticsEvidenceClassification::FirstParty
                }
                _ => SearchAnalyticsEvidenceClassification::ControlledFixture,
            },
            first_party: provenance == ProviderProvenanceClass::ProductionProvider,
            account_probe: probe,
            page,
            read_observation: GscReadObservation::from_sdk(&observation, next_cursor.clone()),
            receipt: SearchAnalyticsReadReceipt::new(
                crate::SearchAnalyticsProvider::GoogleSearchConsole,
                search_path(bound.request.property()),
                GSC_API_VERSION,
                provider_request_id,
                at,
                response_digest.clone(),
                response.raw_evidence_digest(),
            ),
            quota,
            next_cursor,
            charged: false,
            replayed: false,
        };
        let _ = budget;
        self.lock_state()?.signals.insert(observation_id, signal);
        Ok(observation)
    }

    fn execute_with_retry(
        &mut self,
        request: &GscHttpRequest,
    ) -> Result<GscHttpResponse, GscError> {
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            match self.transport.execute(request.clone()) {
                Ok(response)
                    if retryable_status(response.status())
                        && attempt < self.policy.max_attempts() =>
                {
                    self.sleep_before_retry(attempt);
                }
                Ok(response) => return Ok(response),
                Err(error) if retryable_error(&error) && attempt < self.policy.max_attempts() => {
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

    fn lock_state(&self) -> Result<MutexGuard<'_, AdapterState>, GscError> {
        self.state.lock().map_err(|_| GscError::StateUnavailable)
    }
}

impl<T: GscTransport> ConnectorAdapter for GscAdapter<T> {
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
                GscError::Connector(error) => error,
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
            GscError::Connector(error) => error,
            GscError::QuotaExhausted => ConnectorError::QuotaExceeded,
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
        state.bound_request = None;
        state.account_probe = None;
        state.bound_pages.clear();
        state.signals.clear();
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscReplayLedger {
    pages: BTreeMap<String, GscGrowthSignal>,
}

impl GscReplayLedger {
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn replay(&self, request_digest: &str, sequence: u64) -> Option<GscGrowthSignal> {
        self.pages
            .get(&ledger_key(request_digest, sequence))
            .map(replayed_signal)
    }

    pub fn record(&mut self, signal: GscGrowthSignal) {
        let key = ledger_key(
            signal.request().request_digest().as_str(),
            signal.page_sequence(),
        );
        self.pages.insert(key, signal);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GscRegistrationState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscServiceDefinition {
    service_id: String,
    provider_id: String,
    adapter_id: String,
    adapter_version: u32,
    capability_id: String,
    read_only: bool,
}

impl GscServiceDefinition {
    fn new() -> Self {
        Self {
            service_id: "growth-signal.google-search-console.search-analytics.read".to_owned(),
            provider_id: GSC_PROVIDER_ID.to_owned(),
            adapter_id: GSC_ADAPTER_ID.to_owned(),
            adapter_version: GSC_ADAPTER_VERSION,
            capability_id: GSC_READ_CAPABILITY.to_owned(),
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
pub struct GscServiceRegistration {
    registration_id: String,
    service_id: String,
    provider_id: String,
    adapter_id: String,
    scope_digest: String,
    request_digest: String,
    state: GscRegistrationState,
    revoked_at: Option<DateTime<Utc>>,
}

impl GscServiceRegistration {
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

    pub const fn state(&self) -> GscRegistrationState {
        self.state
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }
}

pub struct GscSearchAnalyticsService<T: GscTransport> {
    definition: GscServiceDefinition,
    registration: GscServiceRegistration,
    scope: ConnectorScope,
    request: GscSearchRequest,
    secret: SecretReference,
    lease: CredentialLease,
    worker: ConnectorWorker<GscAdapter<T>>,
    adapter_state: Arc<Mutex<AdapterState>>,
    session: Option<AuthSession>,
    probe: Option<ProbeResult>,
    live_probe: Option<LiveProbeFence>,
    ledger: GscReplayLedger,
}

impl<T: GscTransport> fmt::Debug for GscSearchAnalyticsService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscSearchAnalyticsService")
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request.request_digest())
            .field("worker", &self.worker)
            .field("ledger_page_count", &self.ledger.page_count())
            .finish_non_exhaustive()
    }
}

impl<T: GscTransport> GscSearchAnalyticsService<T> {
    pub fn new(
        secret: SecretReference,
        request: GscSearchRequest,
        transport: T,
        policy: GscTimeoutRetryPolicy,
        now: DateTime<Utc>,
        ledger: GscReplayLedger,
    ) -> Result<Self, GscError> {
        let adapter = GscAdapter::new(transport, policy)?;
        Self::new_with_adapter(secret, request, adapter, now, ledger)
    }

    fn new_with_adapter(
        secret: SecretReference,
        request: GscSearchRequest,
        mut adapter: GscAdapter<T>,
        now: DateTime<Utc>,
        ledger: GscReplayLedger,
    ) -> Result<Self, GscError> {
        if secret.scope() != request.scope() {
            return Err(GscError::ScopeMismatch);
        }
        adapter.bind_request(request.clone())?;
        let scope = request.scope().clone();
        let adapter_state = adapter.state_handle();
        let registry = gsc_registry()?;
        let worker = ConnectorWorker::new(
            format!("worker-gsc-{}", &scope.digest()[..20]),
            adapter,
            registry,
            scope.clone(),
            now,
            now + Duration::minutes(10),
        )
        .map_err(GscError::Connector)?;
        let adapter_identity = ProviderAdapterIdentity::new(GSC_ADAPTER_ID, GSC_ADAPTER_VERSION)
            .map_err(ConnectorError::from)?;
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter_identity,
            format!("lease-gsc-{}", &scope.digest()[..20]),
            1,
            now,
            now + Duration::minutes(10),
        )
        .map_err(GscError::Connector)?;
        let definition = GscServiceDefinition::new();
        let request_digest = request.request_digest();
        let registration = GscServiceRegistration {
            registration_id: format!("gsc-registration-{}", &request_digest[..20]),
            service_id: definition.service_id().to_owned(),
            provider_id: definition.provider_id().to_owned(),
            adapter_id: definition.adapter_id().to_owned(),
            scope_digest: scope.digest(),
            request_digest,
            state: GscRegistrationState::Unmounted,
            revoked_at: None,
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

    pub fn definition(&self) -> &GscServiceDefinition {
        &self.definition
    }

    pub fn registration(&self) -> &GscServiceRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn request(&self) -> &GscSearchRequest {
        &self.request
    }

    pub fn ledger(&self) -> GscReplayLedger {
        self.ledger.clone()
    }

    pub fn mount(&mut self, now: DateTime<Utc>) -> Result<(), GscError> {
        match self.registration.state {
            GscRegistrationState::Mounted => return Ok(()),
            GscRegistrationState::Revoked => return Err(GscError::Revoked),
            GscRegistrationState::Unmounted => {}
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, now, now + Duration::minutes(10))
                .map_err(GscError::Connector)?;
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
            .map_err(GscError::Connector)?;
        let probe = self
            .worker
            .probe(ProbeRequest {
                dispatch: dispatch.clone(),
                scope: self.scope.clone(),
                secret_reference: self.secret.clone(),
                credential_lease: self.lease.clone(),
                session: session.clone(),
                probe_revision: 1,
                result_id: format!("probe-result-gsc-{}", &self.scope.digest()[..20]),
                at: now,
            })
            .map_err(GscError::Connector)?;
        let live_probe = self
            .worker
            .authorize_probe(&probe, now)
            .map_err(GscError::Connector)?;
        self.session = Some(session);
        self.probe = Some(probe);
        self.live_probe = Some(live_probe);
        self.registration.state = GscRegistrationState::Mounted;
        Ok(())
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<(), GscError> {
        if self.registration.state == GscRegistrationState::Revoked {
            return Err(GscError::Revoked);
        }
        if self.registration.state == GscRegistrationState::Mounted {
            let dispatch = self.worker.dispatch_fence();
            self.worker
                .cancel(&dispatch, at)
                .map_err(GscError::Connector)?;
            self.session = None;
            self.probe = None;
            self.live_probe = None;
            let mut state = self.lock_adapter_state()?;
            state.account_probe = None;
            state.bound_pages.clear();
            state.signals.clear();
            drop(state);
            self.registration.state = GscRegistrationState::Unmounted;
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason_digest: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<(), GscError> {
        let reason_digest = reason_digest.into();
        if !is_sha256(&reason_digest) || self.registration.state == GscRegistrationState::Revoked {
            return Err(GscError::Revoked);
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, at, at + Duration::minutes(10))
                .map_err(GscError::Connector)?;
        }
        self.worker
            .revoke(RevokeRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.scope.clone(),
                reason_digest: reason_digest.clone(),
                at,
            })
            .map_err(GscError::Connector)?;
        self.secret.revoke(at).map_err(GscError::Connector)?;
        self.registration.state = GscRegistrationState::Revoked;
        self.registration.revoked_at = Some(at);
        self.session = None;
        self.probe = None;
        self.live_probe = None;
        Ok(())
    }

    pub fn read(
        &mut self,
        cursor: Option<&GscCursor>,
        at: DateTime<Utc>,
        budget: DispatchBudget,
    ) -> Result<GscGrowthSignal, GscError> {
        if self.registration.state != GscRegistrationState::Mounted {
            return Err(match self.registration.state {
                GscRegistrationState::Revoked => GscError::Revoked,
                _ => GscError::NotMounted,
            });
        }
        let request_digest = self.request.request_digest();
        let sequence = cursor.map_or(1, GscCursor::sequence);
        if let Some(cached) = self.ledger.replay(&request_digest, sequence) {
            return Ok(cached);
        }
        let source_revision = self
            .lock_adapter_state()?
            .account_probe
            .as_ref()
            .ok_or(GscError::StateUnavailable)?
            .source_revision();
        if let Some(cursor) = cursor {
            cursor.validate(
                &self.scope,
                &request_digest,
                self.request.row_limit(),
                source_revision,
            )?;
        }
        let mut state = self.lock_adapter_state()?;
        if state.revoked {
            return Err(GscError::Revoked);
        }
        state.bound_pages.insert(
            (
                request_digest.clone(),
                cursor.map_or(0, GscCursor::sequence),
            ),
            BoundPage {
                request: self.request.clone(),
                cursor: cursor.cloned(),
            },
        );
        drop(state);
        let live_probe = self.live_probe.clone().ok_or(GscError::StateUnavailable)?;
        let observation = self
            .worker
            .read(ReadRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.scope.clone(),
                live_probe,
                capability: ProviderCapabilityKey::new(GSC_PROVIDER_ID, GSC_READ_CAPABILITY)
                    .map_err(ConnectorError::from)?,
                query_digest: request_digest,
                cursor: cursor
                    .map(|value| value.sdk_cursor(&self.scope))
                    .transpose()?,
                page_size: self.request.row_limit(),
                at,
                budget,
            })
            .map_err(GscError::Connector)?;
        let signal = self
            .lock_adapter_state()?
            .signals
            .remove(observation.observation_id())
            .ok_or(GscError::StateUnavailable)?;
        self.ledger.record(signal.clone());
        Ok(signal)
    }

    fn lock_adapter_state(&self) -> Result<MutexGuard<'_, AdapterState>, GscError> {
        self.adapter_state
            .lock()
            .map_err(|_| GscError::StateUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GscWorld {
    Paginated,
    Empty,
    PartialAccess,
    RetryOnce,
    AccessDenied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GscRequestRecord {
    method: GscHttpMethod,
    path: String,
    body_digest: Option<String>,
}

impl GscRequestRecord {
    pub const fn method(&self) -> GscHttpMethod {
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
pub struct FakeGscTransport {
    scenario: GscWorld,
    requests: Vec<GscRequestRecord>,
    read_calls: u64,
    transient_failures_left: u8,
}

impl FakeGscTransport {
    pub fn new(scenario: GscWorld) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
            read_calls: 0,
            transient_failures_left: u8::from(scenario == GscWorld::RetryOnce),
        }
    }

    pub fn scenario(&self) -> GscWorld {
        self.scenario
    }

    pub fn requests(&self) -> &[GscRequestRecord] {
        &self.requests
    }

    pub const fn read_calls(&self) -> u64 {
        self.read_calls
    }
}

impl GscTransport for FakeGscTransport {
    fn execute(&mut self, request: GscHttpRequest) -> Result<GscHttpResponse, GscError> {
        self.requests.push(GscRequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest: request.body_digest(),
        });
        if self.transient_failures_left > 0 {
            self.transient_failures_left -= 1;
            return GscHttpResponse::new(503, BTreeMap::new(), json!({"error": "retry"}));
        }
        match (request.method, request.path.as_str()) {
            (GscHttpMethod::Get, GSC_SITES_PATH) => fake_sites_response(self.scenario),
            (GscHttpMethod::Post, path) if path.contains("/searchAnalytics/query") => {
                self.read_calls = self.read_calls.saturating_add(1);
                if self.scenario == GscWorld::AccessDenied {
                    return GscHttpResponse::new(403, BTreeMap::new(), json!({"error": "denied"}));
                }
                let start_row = request
                    .body
                    .as_ref()
                    .and_then(|body| body.get("startRow"))
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(0);
                fake_search_response(self.scenario, start_row)
            }
            _ => Err(GscError::InvalidEndpoint),
        }
    }
}

fn fake_headers(remaining: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("x-ratelimit-limit".to_owned(), "1000".to_owned()),
        ("x-ratelimit-remaining".to_owned(), remaining.to_string()),
        (
            "x-request-id".to_owned(),
            "gsc-fixture-request-1".to_owned(),
        ),
    ])
}

fn fake_sites_response(scenario: GscWorld) -> Result<GscHttpResponse, GscError> {
    GscHttpResponse::new(
        200,
        fake_headers(999),
        json!({
            "siteEntry": [{"siteUrl": "https://example.com/"}],
            "partialAccess": scenario == GscWorld::PartialAccess
        }),
    )
}

fn fake_search_response(scenario: GscWorld, start_row: u32) -> Result<GscHttpResponse, GscError> {
    let rows = if scenario == GscWorld::Empty {
        Vec::new()
    } else if start_row == 0 {
        vec![
            json!({"keys": ["fixture query"], "clicks": 12.0, "impressions": 120.0, "ctr": 0.1, "position": 2.0}),
            json!({"keys": ["second query"], "clicks": 4.0, "impressions": 40.0, "ctr": 0.1, "position": 4.0}),
        ]
    } else {
        vec![
            json!({"keys": ["third query"], "clicks": 2.0, "impressions": 20.0, "ctr": 0.1, "position": 5.0}),
        ]
    };
    let has_more = scenario == GscWorld::Paginated && start_row == 0;
    GscHttpResponse::new(
        200,
        fake_headers(998),
        json!({"rows": rows, "hasMore": has_more}),
    )
}

fn parse_page(
    response: &GscHttpResponse,
    request: &GscSearchRequest,
    start_row: u32,
) -> Result<GscSearchPage, GscError> {
    let rows = response
        .body()
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(GscError::InvalidProviderResponse)?
        .iter()
        .map(|row| {
            let keys = row
                .get("keys")
                .and_then(Value::as_array)
                .ok_or(GscError::InvalidProviderResponse)?
                .iter()
                .map(|key| {
                    key.as_str()
                        .map(str::to_owned)
                        .ok_or(GscError::InvalidProviderResponse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(GscSearchRow {
                keys,
                clicks: row.get("clicks").and_then(Value::as_f64),
                impressions: row.get("impressions").and_then(Value::as_f64),
                ctr: row.get("ctr").and_then(Value::as_f64),
                position: row.get("position").and_then(Value::as_f64),
            })
        })
        .collect::<Result<Vec<_>, GscError>>()?;
    let default_has_more = u32::try_from(rows.len()).ok() == Some(request.row_limit());
    let has_more = response
        .body()
        .get("hasMore")
        .and_then(Value::as_bool)
        .unwrap_or(default_has_more);
    let partial_access = response
        .body()
        .get("partialAccess")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(GscSearchPage {
        property: request.property().to_owned(),
        start_row,
        row_limit: request.row_limit(),
        rows,
        has_more,
        partial_access,
    })
}

fn gsc_registry() -> Result<ProviderAdapterRegistry, GscError> {
    ProviderAdapterRegistry::from_contract_json(GSC_READ_CONTRACT_JSON)
        .map_err(|_| GscError::Connector(ConnectorError::InvalidRegistry))
}

fn search_path(property: &str) -> String {
    format!(
        "/webmasters/v3/sites/{}/searchAnalytics/query",
        encode_path_component(property)
    )
}

fn encode_path_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn valid_property(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROPERTY_LENGTH
        && (value.starts_with("sc-domain:")
            || (value.starts_with("https://") && value.ends_with('/')))
        && !value.chars().any(char::is_whitespace)
}

fn valid_dimension(value: &str) -> bool {
    matches!(
        value,
        "query" | "page" | "country" | "device" | "searchAppearance"
    )
}

fn provider_request_id(headers: &BTreeMap<String, String>, digest: &str) -> String {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("x-goog-request-id"))
        .cloned()
        .unwrap_or_else(|| format!("gsc-{}", &digest[..16.min(digest.len())]))
}

fn quota_receipt(
    headers: &BTreeMap<String, String>,
    request_id: &str,
    charged: bool,
) -> SearchAnalyticsQuotaReceipt {
    SearchAnalyticsQuotaReceipt::new(
        request_id,
        1,
        headers
            .get("x-ratelimit-limit")
            .and_then(|value| value.parse().ok()),
        headers
            .get("x-ratelimit-remaining")
            .and_then(|value| value.parse().ok()),
        charged,
    )
}

fn retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

fn retryable_error(error: &GscError) -> bool {
    matches!(error, GscError::Transport | GscError::Timeout)
}

fn ledger_key(request_digest: &str, sequence: u64) -> String {
    canonical_digest(&[request_digest, &sequence.to_string()])
}

fn replayed_signal(signal: &GscGrowthSignal) -> GscGrowthSignal {
    let mut replay = signal.clone();
    replay.replayed = true;
    replay.charged = false;
    replay.quota.charged = false;
    replay
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, GscError> {
    let bytes = serde_json::to_vec(value).map_err(|_| GscError::InvalidProviderResponse)?;
    Ok(sha256_bytes(&bytes))
}

fn canonical_digest(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn revision_from_digest(digest: &str) -> u64 {
    u64::from_str_radix(&digest[..16], 16).unwrap_or(1).max(1)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
