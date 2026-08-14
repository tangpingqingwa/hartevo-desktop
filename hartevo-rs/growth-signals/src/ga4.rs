//! Google Analytics 4 Search Analytics read adapter.
//!
//! The adapter owns only GA4 request/response models and the HTTPS transport.
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
    GA4_ADAPTER_ID, GA4_ADAPTER_VERSION, GA4_API_BASE_URL, GA4_API_VERSION, GA4_PROVIDER_ID,
    GA4_READ_CAPABILITY, GA4_READ_CONTRACT_JSON, SearchAnalyticsEvidenceClassification,
    SearchAnalyticsFreshness, SearchAnalyticsQuotaReceipt, SearchAnalyticsReadReceipt,
};

const MAX_PAGE_SIZE: u32 = 1_000;
const MAX_PROPERTY_LENGTH: usize = 2_048;
const MAX_DIMENSIONS: usize = 4;
const MAX_TOKEN_LENGTH: usize = 4_096;
const RESULT_TTL_SECONDS: i64 = 900;
const PROBE_TTL_SECONDS: i64 = 90;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4TimeWindow {
    start: NaiveDate,
    end: NaiveDate,
}

impl Ga4TimeWindow {
    pub fn new(start: NaiveDate, end: NaiveDate) -> Result<Self, Ga4Error> {
        if start > end {
            return Err(Ga4Error::InvalidRequest);
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
pub struct Ga4SearchRequest {
    scope: ConnectorScope,
    property: String,
    dimensions: Vec<String>,
    metrics: Vec<String>,
    time_window: Ga4TimeWindow,
    page_size: u32,
}

impl Ga4SearchRequest {
    pub fn new(
        scope: ConnectorScope,
        property: impl Into<String>,
        dimensions: Vec<String>,
        metrics: Vec<String>,
        time_window: Ga4TimeWindow,
        page_size: u32,
    ) -> Result<Self, Ga4Error> {
        let request = Self {
            scope,
            property: property.into().trim().to_owned(),
            dimensions: dimensions
                .into_iter()
                .map(|dimension| dimension.trim().to_owned())
                .collect(),
            metrics: metrics
                .into_iter()
                .map(|metric| metric.trim().to_owned())
                .collect(),
            time_window,
            page_size,
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

    pub fn metrics(&self) -> &[String] {
        &self.metrics
    }

    pub const fn time_window(&self) -> &Ga4TimeWindow {
        &self.time_window
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn request_digest(&self) -> String {
        digest_json(self).unwrap_or_else(|_| sha256_bytes(self.property.as_bytes()))
    }

    fn provider_body(&self, cursor: Option<&Ga4Cursor>) -> Value {
        let mut body = json!({
            "dateRanges": [{
                "startDate": self.time_window.start.to_string(),
                "endDate": self.time_window.end.to_string()
            }],
            "dimensions": self.dimensions.iter().map(|name| json!({"name": name})).collect::<Vec<_>>(),
            "metrics": self.metrics.iter().map(|name| json!({"name": name})).collect::<Vec<_>>(),
            "limit": self.page_size,
            "returnPropertyQuota": true,
        });
        if let Some(page_token) = cursor.and_then(Ga4Cursor::page_token) {
            body["pageToken"] = Value::String(page_token.to_owned());
        }
        body
    }

    fn validate(&self) -> Result<(), Ga4Error> {
        if self.scope.provider_id() != GA4_PROVIDER_ID
            || self.scope.scopes().is_empty()
            || !valid_property(&self.property)
            || self.dimensions.is_empty()
            || self.dimensions.len() > MAX_DIMENSIONS
            || self.metrics.is_empty()
            || self.metrics.len() > MAX_DIMENSIONS
            || self
                .dimensions
                .iter()
                .any(|dimension| !valid_dimension(dimension))
            || self.metrics.iter().any(|metric| !valid_metric(metric))
            || !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
        {
            return Err(Ga4Error::InvalidRequest);
        }
        Ok(())
    }
}

/// Provider-facing name for the bounded GA4 Data API request.
pub type Ga4ReportRequest = Ga4SearchRequest;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4Cursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    token_digest: String,
    page_token: Option<String>,
    page_size: u32,
    source_revision: u64,
}

impl fmt::Debug for Ga4Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4Cursor")
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("sequence", &self.sequence)
            .field("token_digest", &self.token_digest)
            .field("has_page_token", &self.page_token.is_some())
            .field("page_size", &self.page_size)
            .field("source_revision", &self.source_revision)
            .finish()
    }
}

impl Ga4Cursor {
    fn new(
        scope: &ConnectorScope,
        request_digest: &str,
        sequence: u64,
        page_token: String,
        page_size: u32,
        source_revision: u64,
    ) -> Result<Self, Ga4Error> {
        if sequence == 0
            || source_revision == 0
            || page_token.is_empty()
            || page_token.len() > MAX_TOKEN_LENGTH
            || !(1..=MAX_PAGE_SIZE).contains(&page_size)
        {
            return Err(Ga4Error::InvalidCursor);
        }
        let token_digest = canonical_digest(&[
            request_digest,
            &sequence.to_string(),
            &sha256_bytes(page_token.as_bytes()),
            &page_size.to_string(),
            &source_revision.to_string(),
        ]);
        Ok(Self {
            scope_digest: scope.digest(),
            request_digest: request_digest.to_owned(),
            sequence,
            token_digest,
            page_token: Some(page_token),
            page_size,
            source_revision,
        })
    }

    pub fn sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, Ga4Error> {
        if self.scope_digest != scope.digest() {
            return Err(Ga4Error::ScopeMismatch);
        }
        Cursor::new(
            scope,
            self.request_digest.clone(),
            self.sequence,
            self.token_digest.clone(),
        )
        .map_err(Ga4Error::Connector)
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

    pub fn page_token(&self) -> Option<&str> {
        self.page_token.as_deref()
    }

    pub const fn has_page_token(&self) -> bool {
        self.page_token.is_some()
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    fn validate(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        page_size: u32,
        source_revision: u64,
    ) -> Result<(), Ga4Error> {
        let page_token = self.page_token.as_deref().ok_or(Ga4Error::InvalidCursor)?;
        if page_token.is_empty() || page_token.len() > MAX_TOKEN_LENGTH {
            return Err(Ga4Error::InvalidCursor);
        }
        let expected = canonical_digest(&[
            request_digest,
            &self.sequence.to_string(),
            &sha256_bytes(page_token.as_bytes()),
            &self.page_size.to_string(),
            &self.source_revision.to_string(),
        ]);
        if self.scope_digest != scope.digest()
            || self.request_digest != request_digest
            || self.token_digest != expected
            || self.page_size != page_size
            || self.source_revision != source_revision
        {
            return Err(Ga4Error::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4SearchRow {
    dimension_values: Vec<String>,
    metric_values: Vec<String>,
}

impl Ga4SearchRow {
    pub fn dimension_values(&self) -> &[String] {
        &self.dimension_values
    }

    pub fn metric_values(&self) -> &[String] {
        &self.metric_values
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4SearchPage {
    property: String,
    page_token_digest: Option<String>,
    page_size: u32,
    rows: Vec<Ga4SearchRow>,
    has_more: bool,
    partial_access: bool,
}

/// Provider-facing name for one bounded GA4 Data API report page.
pub type Ga4ReportPage = Ga4SearchPage;

impl Ga4SearchPage {
    pub fn property(&self) -> &str {
        &self.property
    }

    pub fn property_id(&self) -> &str {
        self.property()
    }

    pub fn page_token_digest(&self) -> Option<&str> {
        self.page_token_digest.as_deref()
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn rows(&self) -> &[Ga4SearchRow] {
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
pub struct Ga4AccountProbe {
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

impl Ga4AccountProbe {
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
pub struct Ga4ReadObservation {
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
    next_cursor: Option<Ga4Cursor>,
}

impl Ga4ReadObservation {
    fn from_sdk(observation: &ReadObservation, next_cursor: Option<Ga4Cursor>) -> Self {
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

    pub const fn next_cursor(&self) -> Option<&Ga4Cursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4GrowthSignal {
    scope: ConnectorScope,
    request: Ga4SearchRequest,
    property: String,
    source_uri: String,
    observed_at: DateTime<Utc>,
    freshness: SearchAnalyticsFreshness,
    source_revision: u64,
    raw_evidence_digest: String,
    content_digest: String,
    classification: SearchAnalyticsEvidenceClassification,
    first_party: bool,
    account_probe: Ga4AccountProbe,
    page: Ga4SearchPage,
    read_observation: Ga4ReadObservation,
    receipt: SearchAnalyticsReadReceipt,
    quota: SearchAnalyticsQuotaReceipt,
    next_cursor: Option<Ga4Cursor>,
    charged: bool,
    replayed: bool,
}

impl Ga4GrowthSignal {
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn request(&self) -> &Ga4SearchRequest {
        &self.request
    }

    pub fn property(&self) -> &str {
        &self.property
    }

    pub fn property_id(&self) -> &str {
        self.property()
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

    pub const fn account_probe(&self) -> &Ga4AccountProbe {
        &self.account_probe
    }

    pub const fn page(&self) -> &Ga4SearchPage {
        &self.page
    }

    pub const fn read_observation(&self) -> &Ga4ReadObservation {
        &self.read_observation
    }

    pub const fn receipt(&self) -> &SearchAnalyticsReadReceipt {
        &self.receipt
    }

    pub const fn quota(&self) -> &SearchAnalyticsQuotaReceipt {
        &self.quota
    }

    pub const fn next_cursor(&self) -> Option<&Ga4Cursor> {
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
pub enum Ga4HttpMethod {
    Get,
    Post,
}

#[derive(Clone, PartialEq)]
pub struct Ga4HttpRequest {
    method: Ga4HttpMethod,
    path: String,
    body: Option<Value>,
}

impl fmt::Debug for Ga4HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_digest", &self.body_digest())
            .finish_non_exhaustive()
    }
}

impl Ga4HttpRequest {
    fn post(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: Ga4HttpMethod::Post,
            path: path.into(),
            body: Some(body),
        }
    }

    pub const fn method(&self) -> Ga4HttpMethod {
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
pub struct Ga4HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
    raw_evidence_digest: String,
}

impl Ga4HttpResponse {
    pub fn new(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
    ) -> Result<Self, Ga4Error> {
        let bytes = serde_json::to_vec(&body).map_err(|_| Ga4Error::InvalidProviderResponse)?;
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
    ) -> Result<Self, Ga4Error> {
        if !is_sha256(&raw_evidence_digest) {
            return Err(Ga4Error::InvalidProviderResponse);
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
pub struct Ga4TimeoutRetryPolicy {
    timeout_ms: u64,
    max_attempts: u8,
    backoff_ms: u64,
    max_backoff_ms: u64,
}

impl Ga4TimeoutRetryPolicy {
    pub fn new(
        timeout_ms: u64,
        max_attempts: u8,
        backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Result<Self, Ga4Error> {
        if !(1..=30_000).contains(&timeout_ms)
            || !(1..=4).contains(&max_attempts)
            || backoff_ms > max_backoff_ms
            || max_backoff_ms > 10_000
        {
            return Err(Ga4Error::InvalidRetryPolicy);
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

impl Default for Ga4TimeoutRetryPolicy {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            max_attempts: 3,
            backoff_ms: 100,
            max_backoff_ms: 1_000,
        }
    }
}

pub struct Ga4OAuthCredentials {
    access_token: Zeroizing<String>,
}

impl fmt::Debug for Ga4OAuthCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4OAuthCredentials")
            .field("present", &true)
            .finish()
    }
}

impl Ga4OAuthCredentials {
    pub fn new(access_token: impl Into<String>) -> Result<Self, Ga4Error> {
        let access_token = access_token.into();
        if access_token.trim().is_empty() {
            return Err(Ga4Error::MissingCredential);
        }
        Ok(Self {
            access_token: Zeroizing::new(access_token),
        })
    }
}

pub trait Ga4Transport: fmt::Debug + Send {
    fn execute(&mut self, request: Ga4HttpRequest) -> Result<Ga4HttpResponse, Ga4Error>;

    fn revoke(&mut self) {}
}

pub struct Ga4HttpTransport {
    client: Client,
    base_url: Url,
    credentials: Ga4OAuthCredentials,
}

impl fmt::Debug for Ga4HttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4HttpTransport")
            .field("base_url", &self.base_url)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl Ga4HttpTransport {
    pub fn new(credentials: Ga4OAuthCredentials, timeout: StdDuration) -> Result<Self, Ga4Error> {
        let base_url = Url::parse(GA4_API_BASE_URL).map_err(|_| Ga4Error::InvalidEndpoint)?;
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| Ga4Error::Transport)?;
        Ok(Self {
            client,
            base_url,
            credentials,
        })
    }

    pub fn production(
        credentials: Ga4OAuthCredentials,
        policy: &Ga4TimeoutRetryPolicy,
    ) -> Result<Self, Ga4Error> {
        Self::new(credentials, StdDuration::from_millis(policy.timeout_ms()))
    }
}

impl Ga4Transport for Ga4HttpTransport {
    fn execute(&mut self, request: Ga4HttpRequest) -> Result<Ga4HttpResponse, Ga4Error> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| Ga4Error::InvalidEndpoint)?;
        let builder = match request.method {
            Ga4HttpMethod::Get => self.client.get(url),
            Ga4HttpMethod::Post => self.client.post(url),
        }
        .bearer_auth(self.credentials.access_token.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/json");
        let response = match request.body {
            Some(body) => builder.json(&body).send(),
            None => builder.send(),
        }
        .map_err(|error| {
            if error.is_timeout() {
                Ga4Error::Timeout
            } else {
                Ga4Error::Transport
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
        let bytes = response.bytes().map_err(|_| Ga4Error::Transport)?;
        let raw_digest = sha256_bytes(&bytes);
        let body = serde_json::from_slice::<Value>(&bytes)
            .map_err(|_| Ga4Error::InvalidProviderResponse)?;
        Ga4HttpResponse::with_raw_digest(status, headers, body, raw_digest)
    }

    fn revoke(&mut self) {
        self.credentials.access_token.zeroize();
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Ga4Error {
    #[error("GA4 request is invalid")]
    InvalidRequest,
    #[error("GA4 endpoint is invalid")]
    InvalidEndpoint,
    #[error("GA4 OAuth credential is missing")]
    MissingCredential,
    #[error("GA4 cursor is invalid")]
    InvalidCursor,
    #[error("GA4 retry policy is invalid")]
    InvalidRetryPolicy,
    #[error("GA4 provider response is invalid")]
    InvalidProviderResponse,
    #[error("GA4 provider returned HTTP status {0}")]
    ProviderHttpStatus(u16),
    #[error("GA4 property access is denied")]
    PropertyAccessDenied,
    #[error("GA4 provider quota is exhausted")]
    QuotaExhausted,
    #[error("GA4 provider transport failed")]
    Transport,
    #[error("GA4 provider request timed out")]
    Timeout,
    #[error("GA4 service is not mounted")]
    NotMounted,
    #[error("GA4 service is revoked")]
    Revoked,
    #[error("GA4 service scope does not match")]
    ScopeMismatch,
    #[error("GA4 provider freshness changed while paging")]
    FreshnessDrift,
    #[error("GA4 connector state is unavailable")]
    StateUnavailable,
    #[error("Connector SDK rejected the GA4 operation: {0}")]
    Connector(ConnectorError),
}

impl From<ConnectorError> for Ga4Error {
    fn from(error: ConnectorError) -> Self {
        Self::Connector(error)
    }
}

#[derive(Clone, Debug)]
struct BoundPage {
    request: Ga4SearchRequest,
    cursor: Option<Ga4Cursor>,
}

#[derive(Default)]
struct AdapterState {
    revoked: bool,
    bound_request: Option<Ga4SearchRequest>,
    account_probe: Option<Ga4AccountProbe>,
    bound_pages: BTreeMap<(String, u64), BoundPage>,
    signals: BTreeMap<String, Ga4GrowthSignal>,
}

pub struct Ga4Adapter<T: Ga4Transport> {
    descriptor: ConnectorDescriptor,
    transport: T,
    policy: Ga4TimeoutRetryPolicy,
    provenance: ProviderProvenanceClass,
    state: Arc<Mutex<AdapterState>>,
}

impl<T: Ga4Transport> fmt::Debug for Ga4Adapter<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4Adapter")
            .field("descriptor", &self.descriptor)
            .field("policy", &self.policy)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<T: Ga4Transport> Drop for Ga4Adapter<T> {
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

impl<T: Ga4Transport> Ga4Adapter<T> {
    pub fn new(transport: T, policy: Ga4TimeoutRetryPolicy) -> Result<Self, Ga4Error> {
        Self::new_with_provenance(
            transport,
            policy,
            ProviderProvenanceClass::ProductionProvider,
        )
    }

    pub fn controlled(transport: T, policy: Ga4TimeoutRetryPolicy) -> Result<Self, Ga4Error> {
        Self::new_with_provenance(
            transport,
            policy,
            ProviderProvenanceClass::ControlledProvider,
        )
    }

    fn new_with_provenance(
        transport: T,
        policy: Ga4TimeoutRetryPolicy,
        provenance: ProviderProvenanceClass,
    ) -> Result<Self, Ga4Error> {
        let registry = ga4_registry()?;
        let descriptor = ConnectorDescriptor::new(
            ProviderAdapterIdentity::new(GA4_ADAPTER_ID, GA4_ADAPTER_VERSION)
                .map_err(ConnectorError::from)?,
            registry.registrations().iter().cloned(),
        )
        .map_err(Ga4Error::Connector)?;
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

    pub fn policy(&self) -> &Ga4TimeoutRetryPolicy {
        &self.policy
    }

    fn state_handle(&self) -> Arc<Mutex<AdapterState>> {
        Arc::clone(&self.state)
    }

    pub fn bind_request(&mut self, request: Ga4SearchRequest) -> Result<(), Ga4Error> {
        request.validate()?;
        let mut state = self.lock_state()?;
        if state.revoked {
            return Err(Ga4Error::Revoked);
        }
        state.bound_request = Some(request);
        Ok(())
    }

    pub fn account_probe(&self) -> Result<Option<Ga4AccountProbe>, Ga4Error> {
        Ok(self.lock_state()?.account_probe.clone())
    }

    pub fn take_signal(&self, observation_id: &str) -> Result<Ga4GrowthSignal, Ga4Error> {
        self.lock_state()?
            .signals
            .remove(observation_id)
            .ok_or(Ga4Error::StateUnavailable)
    }

    pub fn read_controlled(
        &mut self,
        request: Ga4SearchRequest,
        cursor: Option<Ga4Cursor>,
        at: DateTime<Utc>,
    ) -> Result<Ga4GrowthSignal, Ga4Error> {
        let request_scope = request.scope().clone();
        let page_size = request.page_size();
        let request_digest = request.request_digest();
        self.bind_request(request.clone())?;
        if self.account_probe()?.is_none() {
            self.probe_transport(
                &request_scope,
                at,
                ProviderProvenanceClass::ControlledProvider,
            )?;
        }
        let sequence = cursor.as_ref().map_or(0, Ga4Cursor::sequence);
        self.bind_page(request, cursor)?;
        let budget = DispatchBudget::new(100, at + Duration::minutes(1), 100, 0)
            .map_err(Ga4Error::Connector)?;
        let capability = ProviderCapabilityKey::new(GA4_PROVIDER_ID, GA4_READ_CAPABILITY)
            .map_err(ConnectorError::from)?;
        let observation = self.read_bound(
            &request_scope,
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

    fn bind_page(
        &mut self,
        request: Ga4SearchRequest,
        cursor: Option<Ga4Cursor>,
    ) -> Result<(), Ga4Error> {
        request.validate()?;
        let request_digest = request.request_digest();
        let source_revision = self
            .account_probe()?
            .ok_or(Ga4Error::StateUnavailable)?
            .source_revision();
        if let Some(cursor) = &cursor {
            cursor.validate(
                request.scope(),
                &request_digest,
                request.page_size(),
                source_revision,
            )?;
        }
        let sequence = cursor.as_ref().map_or(0, Ga4Cursor::sequence);
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
    ) -> Result<ProbeObservation, Ga4Error> {
        let request = self
            .lock_state()?
            .bound_request
            .clone()
            .ok_or(Ga4Error::InvalidRequest)?;
        if request.scope() != scope || scope.provider_id() != GA4_PROVIDER_ID {
            return Err(Ga4Error::ScopeMismatch);
        }
        if self.lock_state()?.revoked {
            return Err(Ga4Error::Revoked);
        }
        let response = self.execute_with_retry(&Ga4HttpRequest::post(
            report_path(request.property()),
            request.provider_body(None),
        ))?;
        if !(200..300).contains(&response.status()) {
            return Err(if response.status() == 429 {
                Ga4Error::QuotaExhausted
            } else if response.status() == 403 {
                Ga4Error::PropertyAccessDenied
            } else {
                Ga4Error::ProviderHttpStatus(response.status())
            });
        }
        let property_access = true;
        let partial_access = response
            .body()
            .get("partialAccess")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let source_revision = revision_from_digest(response.raw_evidence_digest());
        let provider_request_id =
            provider_request_id(response.headers(), response.raw_evidence_digest());
        let quota = quota_receipt(
            response.body(),
            response.headers(),
            &provider_request_id,
            false,
        );
        let expires_at = at + Duration::seconds(PROBE_TTL_SECONDS);
        let probe = Ga4AccountProbe {
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
    ) -> Result<ReadObservation, Ga4Error> {
        let bound = self
            .lock_state()?
            .bound_pages
            .remove(&(query_digest.to_owned(), sequence))
            .ok_or(Ga4Error::InvalidRequest)?;
        if bound.request.scope() != scope || bound.request.request_digest() != query_digest {
            return Err(Ga4Error::ScopeMismatch);
        }
        let probe = self.account_probe()?.ok_or(Ga4Error::StateUnavailable)?;
        if let Some(cursor) = &bound.cursor {
            cursor.validate(scope, query_digest, page_size, probe.source_revision())?;
        }
        let response = self.execute_with_retry(&Ga4HttpRequest::post(
            report_path(bound.request.property()),
            bound.request.provider_body(bound.cursor.as_ref()),
        ))?;
        if !(200..300).contains(&response.status()) {
            return Err(if response.status() == 429 {
                Ga4Error::QuotaExhausted
            } else if response.status() == 403 {
                Ga4Error::PropertyAccessDenied
            } else {
                Ga4Error::ProviderHttpStatus(response.status())
            });
        }
        let page = parse_page(&response, &bound.request)?;
        let row_count =
            u32::try_from(page.rows().len()).map_err(|_| Ga4Error::InvalidProviderResponse)?;
        let next_page_token = response
            .body()
            .get("nextPageToken")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_owned);
        let next_cursor = if let Some(page_token) = next_page_token {
            Some(Ga4Cursor::new(
                scope,
                query_digest,
                bound
                    .cursor
                    .as_ref()
                    .map_or(2, |cursor| cursor.sequence() + 1),
                page_token,
                bound.request.page_size(),
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
        .map_err(Ga4Error::Connector)?;
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
            bound.cursor.as_ref().map_or(1, Ga4Cursor::sequence),
            row_count,
            sdk_next_cursor,
        )
        .map_err(Ga4Error::Connector)?;
        let provider_request_id = provider_request_id(response.headers(), &response_digest);
        let quota = quota_receipt(
            response.body(),
            response.headers(),
            &provider_request_id,
            false,
        );
        let signal = Ga4GrowthSignal {
            scope: scope.clone(),
            request: bound.request.clone(),
            property: bound.request.property().to_owned(),
            source_uri: format!(
                "ga4://{}/{}?request={}",
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
            .map_err(Ga4Error::Connector)?,
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
            read_observation: Ga4ReadObservation::from_sdk(&observation, next_cursor.clone()),
            receipt: SearchAnalyticsReadReceipt::new(
                crate::SearchAnalyticsProvider::GoogleAnalytics4,
                report_path(bound.request.property()),
                GA4_API_VERSION,
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
        request: &Ga4HttpRequest,
    ) -> Result<Ga4HttpResponse, Ga4Error> {
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

    fn lock_state(&self) -> Result<MutexGuard<'_, AdapterState>, Ga4Error> {
        self.state.lock().map_err(|_| Ga4Error::StateUnavailable)
    }
}

impl<T: Ga4Transport> ConnectorAdapter for Ga4Adapter<T> {
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
                Ga4Error::Connector(error) => error,
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
            Ga4Error::Connector(error) => error,
            Ga4Error::QuotaExhausted => ConnectorError::QuotaExceeded,
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
pub struct Ga4ReplayLedger {
    pages: BTreeMap<String, Ga4GrowthSignal>,
}

impl Ga4ReplayLedger {
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn replay(&self, request_digest: &str, sequence: u64) -> Option<Ga4GrowthSignal> {
        self.pages
            .get(&ledger_key(request_digest, sequence))
            .map(replayed_signal)
    }

    pub fn record(&mut self, signal: Ga4GrowthSignal) {
        let key = ledger_key(
            signal.request().request_digest().as_str(),
            signal.page_sequence(),
        );
        self.pages.insert(key, signal);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ga4RegistrationState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4ServiceDefinition {
    service_id: String,
    provider_id: String,
    adapter_id: String,
    adapter_version: u32,
    capability_id: String,
    read_only: bool,
}

impl Ga4ServiceDefinition {
    fn new() -> Self {
        Self {
            service_id: "growth-signal.google-analytics-4.data-api.read".to_owned(),
            provider_id: GA4_PROVIDER_ID.to_owned(),
            adapter_id: GA4_ADAPTER_ID.to_owned(),
            adapter_version: GA4_ADAPTER_VERSION,
            capability_id: GA4_READ_CAPABILITY.to_owned(),
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
pub struct Ga4ServiceRegistration {
    registration_id: String,
    service_id: String,
    provider_id: String,
    adapter_id: String,
    scope_digest: String,
    request_digest: String,
    state: Ga4RegistrationState,
    revoked_at: Option<DateTime<Utc>>,
}

impl Ga4ServiceRegistration {
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

    pub const fn state(&self) -> Ga4RegistrationState {
        self.state
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }
}

pub struct Ga4SearchAnalyticsService<T: Ga4Transport> {
    definition: Ga4ServiceDefinition,
    registration: Ga4ServiceRegistration,
    scope: ConnectorScope,
    request: Ga4SearchRequest,
    secret: SecretReference,
    lease: CredentialLease,
    worker: ConnectorWorker<Ga4Adapter<T>>,
    adapter_state: Arc<Mutex<AdapterState>>,
    session: Option<AuthSession>,
    probe: Option<ProbeResult>,
    live_probe: Option<LiveProbeFence>,
    ledger: Ga4ReplayLedger,
}

impl<T: Ga4Transport> fmt::Debug for Ga4SearchAnalyticsService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4SearchAnalyticsService")
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request.request_digest())
            .field("worker", &self.worker)
            .field("ledger_page_count", &self.ledger.page_count())
            .finish_non_exhaustive()
    }
}

impl<T: Ga4Transport> Ga4SearchAnalyticsService<T> {
    pub fn new(
        secret: SecretReference,
        request: Ga4SearchRequest,
        transport: T,
        policy: Ga4TimeoutRetryPolicy,
        now: DateTime<Utc>,
        ledger: Ga4ReplayLedger,
    ) -> Result<Self, Ga4Error> {
        let adapter = Ga4Adapter::new(transport, policy)?;
        Self::new_with_adapter(secret, request, adapter, now, ledger)
    }

    fn new_with_adapter(
        secret: SecretReference,
        request: Ga4SearchRequest,
        mut adapter: Ga4Adapter<T>,
        now: DateTime<Utc>,
        ledger: Ga4ReplayLedger,
    ) -> Result<Self, Ga4Error> {
        if secret.scope() != request.scope() {
            return Err(Ga4Error::ScopeMismatch);
        }
        adapter.bind_request(request.clone())?;
        let scope = request.scope().clone();
        let adapter_state = adapter.state_handle();
        let registry = ga4_registry()?;
        let worker = ConnectorWorker::new(
            format!("worker-ga4-{}", &scope.digest()[..20]),
            adapter,
            registry,
            scope.clone(),
            now,
            now + Duration::minutes(10),
        )
        .map_err(Ga4Error::Connector)?;
        let adapter_identity = ProviderAdapterIdentity::new(GA4_ADAPTER_ID, GA4_ADAPTER_VERSION)
            .map_err(ConnectorError::from)?;
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter_identity,
            format!("lease-ga4-{}", &scope.digest()[..20]),
            1,
            now,
            now + Duration::minutes(10),
        )
        .map_err(Ga4Error::Connector)?;
        let definition = Ga4ServiceDefinition::new();
        let request_digest = request.request_digest();
        let registration = Ga4ServiceRegistration {
            registration_id: format!("ga4-registration-{}", &request_digest[..20]),
            service_id: definition.service_id().to_owned(),
            provider_id: definition.provider_id().to_owned(),
            adapter_id: definition.adapter_id().to_owned(),
            scope_digest: scope.digest(),
            request_digest,
            state: Ga4RegistrationState::Unmounted,
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

    pub fn definition(&self) -> &Ga4ServiceDefinition {
        &self.definition
    }

    pub fn registration(&self) -> &Ga4ServiceRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn request(&self) -> &Ga4SearchRequest {
        &self.request
    }

    pub fn ledger(&self) -> Ga4ReplayLedger {
        self.ledger.clone()
    }

    pub fn mount(&mut self, now: DateTime<Utc>) -> Result<(), Ga4Error> {
        match self.registration.state {
            Ga4RegistrationState::Mounted => return Ok(()),
            Ga4RegistrationState::Revoked => return Err(Ga4Error::Revoked),
            Ga4RegistrationState::Unmounted => {}
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, now, now + Duration::minutes(10))
                .map_err(Ga4Error::Connector)?;
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
            .map_err(Ga4Error::Connector)?;
        let probe = self
            .worker
            .probe(ProbeRequest {
                dispatch: dispatch.clone(),
                scope: self.scope.clone(),
                secret_reference: self.secret.clone(),
                credential_lease: self.lease.clone(),
                session: session.clone(),
                probe_revision: 1,
                result_id: format!("probe-result-ga4-{}", &self.scope.digest()[..20]),
                at: now,
            })
            .map_err(Ga4Error::Connector)?;
        let live_probe = self
            .worker
            .authorize_probe(&probe, now)
            .map_err(Ga4Error::Connector)?;
        self.session = Some(session);
        self.probe = Some(probe);
        self.live_probe = Some(live_probe);
        self.registration.state = Ga4RegistrationState::Mounted;
        Ok(())
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<(), Ga4Error> {
        if self.registration.state == Ga4RegistrationState::Revoked {
            return Err(Ga4Error::Revoked);
        }
        if self.registration.state == Ga4RegistrationState::Mounted {
            let dispatch = self.worker.dispatch_fence();
            self.worker
                .cancel(&dispatch, at)
                .map_err(Ga4Error::Connector)?;
            self.session = None;
            self.probe = None;
            self.live_probe = None;
            let mut state = self.lock_adapter_state()?;
            state.account_probe = None;
            state.bound_pages.clear();
            state.signals.clear();
            drop(state);
            self.registration.state = Ga4RegistrationState::Unmounted;
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason_digest: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<(), Ga4Error> {
        let reason_digest = reason_digest.into();
        if !is_sha256(&reason_digest) || self.registration.state == Ga4RegistrationState::Revoked {
            return Err(Ga4Error::Revoked);
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, at, at + Duration::minutes(10))
                .map_err(Ga4Error::Connector)?;
        }
        self.worker
            .revoke(RevokeRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.scope.clone(),
                reason_digest: reason_digest.clone(),
                at,
            })
            .map_err(Ga4Error::Connector)?;
        self.secret.revoke(at).map_err(Ga4Error::Connector)?;
        self.registration.state = Ga4RegistrationState::Revoked;
        self.registration.revoked_at = Some(at);
        self.session = None;
        self.probe = None;
        self.live_probe = None;
        Ok(())
    }

    pub fn read(
        &mut self,
        cursor: Option<&Ga4Cursor>,
        at: DateTime<Utc>,
        budget: DispatchBudget,
    ) -> Result<Ga4GrowthSignal, Ga4Error> {
        if self.registration.state != Ga4RegistrationState::Mounted {
            return Err(match self.registration.state {
                Ga4RegistrationState::Revoked => Ga4Error::Revoked,
                _ => Ga4Error::NotMounted,
            });
        }
        let request_digest = self.request.request_digest();
        let sequence = cursor.map_or(1, Ga4Cursor::sequence);
        if let Some(cached) = self.ledger.replay(&request_digest, sequence) {
            return Ok(cached);
        }
        let source_revision = self
            .lock_adapter_state()?
            .account_probe
            .as_ref()
            .ok_or(Ga4Error::StateUnavailable)?
            .source_revision();
        if let Some(cursor) = cursor {
            cursor.validate(
                &self.scope,
                &request_digest,
                self.request.page_size(),
                source_revision,
            )?;
        }
        let mut state = self.lock_adapter_state()?;
        if state.revoked {
            return Err(Ga4Error::Revoked);
        }
        state.bound_pages.insert(
            (
                request_digest.clone(),
                cursor.map_or(0, Ga4Cursor::sequence),
            ),
            BoundPage {
                request: self.request.clone(),
                cursor: cursor.cloned(),
            },
        );
        drop(state);
        let live_probe = self.live_probe.clone().ok_or(Ga4Error::StateUnavailable)?;
        let observation = self
            .worker
            .read(ReadRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.scope.clone(),
                live_probe,
                capability: ProviderCapabilityKey::new(GA4_PROVIDER_ID, GA4_READ_CAPABILITY)
                    .map_err(ConnectorError::from)?,
                query_digest: request_digest,
                cursor: cursor
                    .map(|value| value.sdk_cursor(&self.scope))
                    .transpose()?,
                page_size: self.request.page_size(),
                at,
                budget,
            })
            .map_err(Ga4Error::Connector)?;
        let signal = self
            .lock_adapter_state()?
            .signals
            .remove(observation.observation_id())
            .ok_or(Ga4Error::StateUnavailable)?;
        self.ledger.record(signal.clone());
        Ok(signal)
    }

    fn lock_adapter_state(&self) -> Result<MutexGuard<'_, AdapterState>, Ga4Error> {
        self.adapter_state
            .lock()
            .map_err(|_| Ga4Error::StateUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ga4World {
    Paginated,
    Empty,
    PartialAccess,
    RetryOnce,
    AccessDenied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ga4RequestRecord {
    method: Ga4HttpMethod,
    path: String,
    body_digest: Option<String>,
}

impl Ga4RequestRecord {
    pub const fn method(&self) -> Ga4HttpMethod {
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
pub struct FakeGa4Transport {
    scenario: Ga4World,
    requests: Vec<Ga4RequestRecord>,
    read_calls: u64,
    transient_failures_left: u8,
}

impl FakeGa4Transport {
    pub fn new(scenario: Ga4World) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
            read_calls: 0,
            transient_failures_left: u8::from(scenario == Ga4World::RetryOnce),
        }
    }

    pub fn scenario(&self) -> Ga4World {
        self.scenario
    }

    pub fn requests(&self) -> &[Ga4RequestRecord] {
        &self.requests
    }

    pub const fn read_calls(&self) -> u64 {
        self.read_calls
    }
}

impl Ga4Transport for FakeGa4Transport {
    fn execute(&mut self, request: Ga4HttpRequest) -> Result<Ga4HttpResponse, Ga4Error> {
        self.requests.push(Ga4RequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest: request.body_digest(),
        });
        if self.transient_failures_left > 0 {
            self.transient_failures_left -= 1;
            return Ga4HttpResponse::new(503, BTreeMap::new(), json!({"error": "retry"}));
        }
        match (request.method, request.path.as_str()) {
            (Ga4HttpMethod::Post, path) if path.contains(":runReport") => {
                self.read_calls = self.read_calls.saturating_add(1);
                if self.scenario == Ga4World::AccessDenied {
                    return Ga4HttpResponse::new(403, BTreeMap::new(), json!({"error": "denied"}));
                }
                let has_page_token = request
                    .body
                    .as_ref()
                    .and_then(|body| body.get("pageToken"))
                    .and_then(Value::as_str)
                    .is_some();
                fake_search_response(self.scenario, has_page_token)
            }
            _ => Err(Ga4Error::InvalidEndpoint),
        }
    }
}

fn fake_headers(remaining: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("x-ratelimit-limit".to_owned(), "1000".to_owned()),
        ("x-ratelimit-remaining".to_owned(), remaining.to_string()),
        (
            "x-request-id".to_owned(),
            "ga4-fixture-request-1".to_owned(),
        ),
    ])
}

fn fake_search_response(
    scenario: Ga4World,
    has_page_token: bool,
) -> Result<Ga4HttpResponse, Ga4Error> {
    let rows = if scenario == Ga4World::Empty {
        Vec::new()
    } else if !has_page_token {
        vec![
            json!({"dimensionValues": [{"value": "2026-08-13"}], "metricValues": [{"value": "12"}]}),
            json!({"dimensionValues": [{"value": "2026-08-14"}], "metricValues": [{"value": "4"}]}),
        ]
    } else {
        vec![
            json!({"dimensionValues": [{"value": "2026-08-15"}], "metricValues": [{"value": "2"}]}),
        ]
    };
    let next_page_token =
        (scenario == Ga4World::Paginated && !has_page_token).then_some("fixture-page-token-2");
    Ga4HttpResponse::new(
        200,
        fake_headers(998),
        json!({
            "dimensionHeaders": [{"name": "date"}],
            "metricHeaders": [{"name": "activeUsers", "type": "TYPE_INTEGER"}],
            "rows": rows,
            "rowCount": if scenario == Ga4World::Empty { 0 } else { 3 },
            "partialAccess": scenario == Ga4World::PartialAccess,
            "propertyQuota": {
                "tokensPerHour": {"consumed": 7, "remaining": 39993},
                "tokensPerProjectPerHour": {"consumed": 7, "remaining": 13993}
            },
            "nextPageToken": next_page_token
        }),
    )
}

fn parse_page(
    response: &Ga4HttpResponse,
    request: &Ga4SearchRequest,
) -> Result<Ga4SearchPage, Ga4Error> {
    let rows = response
        .body()
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(Ga4Error::InvalidProviderResponse)?
        .iter()
        .map(|row| {
            let dimension_values = row
                .get("dimensionValues")
                .and_then(Value::as_array)
                .ok_or(Ga4Error::InvalidProviderResponse)?
                .iter()
                .map(|value| {
                    value
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or(Ga4Error::InvalidProviderResponse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let metric_values = row
                .get("metricValues")
                .and_then(Value::as_array)
                .ok_or(Ga4Error::InvalidProviderResponse)?
                .iter()
                .map(|value| {
                    value
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or(Ga4Error::InvalidProviderResponse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Ga4SearchRow {
                dimension_values,
                metric_values,
            })
        })
        .collect::<Result<Vec<_>, Ga4Error>>()?;
    let page_token_digest = response
        .body()
        .get("nextPageToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(|token| sha256_bytes(token.as_bytes()));
    let has_more = page_token_digest.is_some();
    let partial_access = response
        .body()
        .get("partialAccess")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(Ga4SearchPage {
        property: request.property().to_owned(),
        page_token_digest,
        page_size: request.page_size(),
        rows,
        has_more,
        partial_access,
    })
}

fn ga4_registry() -> Result<ProviderAdapterRegistry, Ga4Error> {
    ProviderAdapterRegistry::from_contract_json(GA4_READ_CONTRACT_JSON)
        .map_err(|_| Ga4Error::Connector(ConnectorError::InvalidRegistry))
}

fn report_path(property: &str) -> String {
    format!(
        "/v1beta/properties/{}:runReport",
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
        && value.chars().all(|character| character.is_ascii_digit())
        && value != "0"
}

fn valid_dimension(value: &str) -> bool {
    valid_field_name(value)
}

fn valid_metric(value: &str) -> bool {
    valid_field_name(value)
}

fn valid_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn provider_request_id(headers: &BTreeMap<String, String>, digest: &str) -> String {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("x-goog-request-id"))
        .cloned()
        .unwrap_or_else(|| format!("ga4-{}", &digest[..16.min(digest.len())]))
}

fn quota_receipt(
    body: &Value,
    headers: &BTreeMap<String, String>,
    request_id: &str,
    charged: bool,
) -> SearchAnalyticsQuotaReceipt {
    let status = body
        .get("propertyQuota")
        .and_then(Value::as_object)
        .and_then(|quota| quota.get("tokensPerHour"))
        .and_then(Value::as_object);
    let consumed = status
        .and_then(|status| status.get("consumed"))
        .and_then(Value::as_u64);
    let remaining = status
        .and_then(|status| status.get("remaining"))
        .and_then(Value::as_u64);
    SearchAnalyticsQuotaReceipt::new(
        request_id,
        consumed.unwrap_or(1),
        remaining
            .zip(consumed)
            .map(|(remaining, consumed)| remaining.saturating_add(consumed)),
        remaining.or_else(|| {
            headers
                .get("x-ratelimit-remaining")
                .and_then(|value| value.parse().ok())
        }),
        charged,
    )
}

fn retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

fn retryable_error(error: &Ga4Error) -> bool {
    matches!(error, Ga4Error::Transport | Ga4Error::Timeout)
}

fn ledger_key(request_digest: &str, sequence: u64) -> String {
    canonical_digest(&[request_digest, &sequence.to_string()])
}

fn replayed_signal(signal: &Ga4GrowthSignal) -> Ga4GrowthSignal {
    let mut replay = signal.clone();
    replay.replayed = true;
    replay.charged = false;
    replay.quota.charged = false;
    replay
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, Ga4Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Ga4Error::InvalidProviderResponse)?;
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
