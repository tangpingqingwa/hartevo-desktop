//! Google Ads REST/GAQL read adapter.
//!
//! This module owns the provider-specific OAuth bearer transport, developer
//! token/customer headers, GAQL selector validation, account probe, typed row
//! envelope, page-token cursor, quota accounting, and deterministic worlds.
//! Authentication and worker lifecycle remain the stable Connector SDK
//! boundary; no effect operation is implemented here.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration as StdDuration,
};

use chrono::{DateTime, Duration, Utc};
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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    GOOGLE_ADS_API_BASE_URL, GOOGLE_ADS_API_VERSION, GOOGLE_ADS_GAQL_ADAPTER_ID,
    GOOGLE_ADS_GAQL_ADAPTER_VERSION, GOOGLE_ADS_PROBE_QUERY, GOOGLE_ADS_PROVIDER_ID,
    GOOGLE_ADS_READ_CAPABILITY, GOOGLE_ADS_READ_CONTRACT_JSON, GOOGLE_ADS_SEARCH_PATH_SUFFIX,
};

const MAX_GAQL_BYTES: usize = 16_384;
const MAX_CUSTOMER_ID_LENGTH: usize = 20;
const MAX_PAGE_TOKEN_LENGTH: usize = 4_096;
const MAX_PAGES: u32 = 10;
const DEFAULT_RESULT_TTL_SECONDS: i64 = 600;
const DEFAULT_PROBE_TTL_SECONDS: i64 = 120;

/// A single bounded, read-only GAQL selector bound to an exact customer scope.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsGaqlRequest {
    scope: ConnectorScope,
    customer_id: String,
    login_customer_id: String,
    api_version: String,
    query: String,
    max_pages: u32,
    max_quota_units: u64,
}

impl fmt::Debug for GoogleAdsGaqlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsGaqlRequest")
            .field("scope", &self.scope)
            .field("customer_id", &self.customer_id)
            .field("login_customer_id", &self.login_customer_id)
            .field("api_version", &self.api_version)
            .field("query_digest", &self.request_digest())
            .field("max_pages", &self.max_pages)
            .field("max_quota_units", &self.max_quota_units)
            .finish_non_exhaustive()
    }
}

impl GoogleAdsGaqlRequest {
    pub fn new(
        scope: ConnectorScope,
        login_customer_id: impl Into<String>,
        query: impl Into<String>,
        max_pages: u32,
        max_quota_units: u64,
    ) -> Result<Self, GoogleAdsError> {
        let login_customer_id = login_customer_id.into();
        let request = Self {
            customer_id: scope.account_id().to_owned(),
            scope,
            login_customer_id: normalize_customer_id(&login_customer_id)?,
            api_version: GOOGLE_ADS_API_VERSION.to_owned(),
            query: query.into().trim().to_owned(),
            max_pages,
            max_quota_units,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn customer_id(&self) -> &str {
        &self.customer_id
    }

    pub fn login_customer_id(&self) -> &str {
        &self.login_customer_id
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub const fn max_pages(&self) -> u32 {
        self.max_pages
    }

    pub const fn max_quota_units(&self) -> u64 {
        self.max_quota_units
    }

    /// The digest binds tenant/project/provider/customer, login customer,
    /// version, selector and local bounds. It never includes OAuth material or
    /// the developer token.
    pub fn request_digest(&self) -> String {
        digest_json(self).unwrap_or_else(|_| sha256_bytes(self.query.as_bytes()))
    }

    fn validate(&self) -> Result<(), GoogleAdsError> {
        if self.scope.provider_id() != GOOGLE_ADS_PROVIDER_ID
            || self.scope.scopes().is_empty()
            || self.customer_id != self.scope.account_id()
            || !valid_customer_id(&self.customer_id)
            || !valid_customer_id(&self.login_customer_id)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || !(1..=100_000).contains(&self.max_quota_units)
            || self.query.is_empty()
            || self.query.len() > MAX_GAQL_BYTES
            || self.query.contains(';')
            || !is_select_query(&self.query)
        {
            return Err(GoogleAdsError::InvalidRequest);
        }
        Ok(())
    }

    fn provider_body(&self, cursor: Option<&GoogleAdsCursor>) -> Value {
        let mut body = json!({"query": self.query});
        if let Some(cursor) = cursor {
            body["pageToken"] = Value::String(cursor.page_token.clone());
        }
        body
    }

    fn endpoint_path(&self) -> String {
        format!(
            "/{}/customers/{}/{}",
            self.api_version, self.customer_id, GOOGLE_ADS_SEARCH_PATH_SUFFIX
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAdsEvidenceClassification {
    FirstParty,
    ControlledFixture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAdsCostClass {
    ApiOperation,
    ControlledFixture,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsQuota {
    provider_operation_count: u32,
    reported_daily_limit: Option<u64>,
    local_limit: u64,
    local_used: u64,
}

impl GoogleAdsQuota {
    pub const fn provider_operation_count(&self) -> u32 {
        self.provider_operation_count
    }

    pub const fn reported_daily_limit(&self) -> Option<u64> {
        self.reported_daily_limit
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
pub struct GoogleAdsUsage {
    cost_class: GoogleAdsCostClass,
    request_units: u32,
    charged: bool,
    attempts: u8,
    request_id: String,
    quota: GoogleAdsQuota,
}

impl GoogleAdsUsage {
    pub const fn cost_class(&self) -> GoogleAdsCostClass {
        self.cost_class
    }

    pub const fn request_units(&self) -> u32 {
        self.request_units
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub const fn quota(&self) -> &GoogleAdsQuota {
        &self.quota
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsAccountProbe {
    scope: ConnectorScope,
    customer_id: String,
    login_customer_id: String,
    status: ProbeStatus,
    provenance_class: ProviderProvenanceClass,
    classification: GoogleAdsEvidenceClassification,
    first_party: bool,
    descriptive_name: Option<String>,
    currency_code: Option<String>,
    time_zone: Option<String>,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    source_revision: u64,
    request_id: String,
    response_digest: String,
    raw_evidence_digest: String,
    cost_class: GoogleAdsCostClass,
    quota: GoogleAdsQuota,
}

impl GoogleAdsAccountProbe {
    pub const fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn customer_id(&self) -> &str {
        &self.customer_id
    }

    pub fn login_customer_id(&self) -> &str {
        &self.login_customer_id
    }

    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub const fn classification(&self) -> GoogleAdsEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub fn descriptive_name(&self) -> Option<&str> {
        self.descriptive_name.as_deref()
    }

    pub fn currency_code(&self) -> Option<&str> {
        self.currency_code.as_deref()
    }

    pub fn time_zone(&self) -> Option<&str> {
        self.time_zone.as_deref()
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

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn cost_class(&self) -> GoogleAdsCostClass {
        self.cost_class
    }

    pub const fn quota(&self) -> &GoogleAdsQuota {
        &self.quota
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsCursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    page_token: String,
    token_digest: String,
    source_revision: u64,
}

impl fmt::Debug for GoogleAdsCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsCursor")
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("sequence", &self.sequence)
            .field("token_digest", &self.token_digest)
            .field("has_page_token", &true)
            .field("source_revision", &self.source_revision)
            .finish_non_exhaustive()
    }
}

impl GoogleAdsCursor {
    fn new(
        scope: &ConnectorScope,
        request_digest: &str,
        sequence: u64,
        page_token: String,
        source_revision: u64,
    ) -> Result<Self, GoogleAdsError> {
        if sequence == 0
            || source_revision == 0
            || page_token.is_empty()
            || page_token.len() > MAX_PAGE_TOKEN_LENGTH
        {
            return Err(GoogleAdsError::InvalidPageToken);
        }
        let token_digest = canonical_digest(&[
            request_digest,
            &sequence.to_string(),
            &page_token,
            &source_revision.to_string(),
        ]);
        Ok(Self {
            scope_digest: scope.digest(),
            request_digest: request_digest.to_owned(),
            sequence,
            page_token,
            token_digest,
            source_revision,
        })
    }

    pub fn sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, GoogleAdsError> {
        if self.scope_digest != scope.digest() {
            return Err(GoogleAdsError::ScopeMismatch);
        }
        Cursor::new(
            scope,
            self.request_digest.clone(),
            self.sequence,
            self.token_digest.clone(),
        )
        .map_err(GoogleAdsError::Connector)
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

    pub fn page_token(&self) -> &str {
        &self.page_token
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    fn validate(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        source_revision: u64,
    ) -> Result<(), GoogleAdsError> {
        let expected = canonical_digest(&[
            request_digest,
            &self.sequence.to_string(),
            &self.page_token,
            &self.source_revision.to_string(),
        ]);
        if self.scope_digest != scope.digest()
            || self.request_digest != request_digest
            || self.token_digest != expected
            || self.source_revision != source_revision
        {
            return Err(GoogleAdsError::InvalidPageToken);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsRow {
    resource_name: Option<String>,
    fields: BTreeMap<String, Value>,
}

impl GoogleAdsRow {
    pub fn resource_name(&self) -> Option<&str> {
        self.resource_name.as_deref()
    }

    pub const fn fields(&self) -> &BTreeMap<String, Value> {
        &self.fields
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsPage {
    page_sequence: u64,
    rows: Vec<GoogleAdsRow>,
    field_mask: Vec<String>,
    next_page_token: Option<String>,
}

impl GoogleAdsPage {
    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub fn rows(&self) -> &[GoogleAdsRow] {
        &self.rows
    }

    pub fn field_mask(&self) -> &[String] {
        &self.field_mask
    }

    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn has_next_page(&self) -> bool {
        self.next_page_token.is_some()
    }

    fn next_cursor(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
        source_revision: u64,
        max_pages: u32,
    ) -> Result<Option<GoogleAdsCursor>, GoogleAdsError> {
        if self.page_sequence >= u64::from(max_pages) {
            return Ok(None);
        }
        self.next_page_token
            .clone()
            .map(|token| {
                GoogleAdsCursor::new(
                    scope,
                    request_digest,
                    self.page_sequence.saturating_add(1),
                    token,
                    source_revision,
                )
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsCallReceipt {
    endpoint: String,
    api_version: String,
    query_digest: String,
    observed_at: DateTime<Utc>,
    request_id: String,
    response_digest: String,
    raw_evidence_digest: String,
    cost_class: GoogleAdsCostClass,
}

impl GoogleAdsCallReceipt {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn cost_class(&self) -> GoogleAdsCostClass {
        self.cost_class
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsFreshness {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_revision: u64,
}

impl GoogleAdsFreshness {
    fn from_sdk(freshness: &FreshnessWindow) -> Self {
        Self {
            observed_at: freshness.observed_at(),
            valid_until: freshness.valid_until(),
            source_revision: freshness.source_revision(),
        }
    }

    pub fn to_sdk(&self) -> Result<FreshnessWindow, GoogleAdsError> {
        FreshnessWindow::new(self.observed_at, self.valid_until, self.source_revision)
            .map_err(GoogleAdsError::Connector)
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsReadObservation {
    observation_id: String,
    scope: ConnectorScope,
    capability: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    query_digest: String,
    response_digest: String,
    content_digest: String,
    provenance_class: ProviderProvenanceClass,
    freshness: GoogleAdsFreshness,
    page_sequence: u64,
    row_count: u32,
    next_cursor: Option<GoogleAdsCursor>,
}

impl GoogleAdsReadObservation {
    fn from_sdk(observation: &ReadObservation, next_cursor: Option<GoogleAdsCursor>) -> Self {
        Self {
            observation_id: observation.observation_id().to_owned(),
            scope: observation.scope().clone(),
            capability: observation.capability().clone(),
            adapter: observation.adapter().clone(),
            query_digest: observation.request_digest().to_owned(),
            response_digest: observation.response_digest().to_owned(),
            content_digest: observation.content_digest().to_owned(),
            provenance_class: observation.provenance_class(),
            freshness: GoogleAdsFreshness::from_sdk(observation.freshness()),
            page_sequence: observation.page_sequence(),
            row_count: observation.item_count(),
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

    pub fn query_digest(&self) -> &str {
        &self.query_digest
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

    pub const fn freshness(&self) -> &GoogleAdsFreshness {
        &self.freshness
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn row_count(&self) -> u32 {
        self.row_count
    }

    pub const fn next_cursor(&self) -> Option<&GoogleAdsCursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsGrowthSignal {
    scope: ConnectorScope,
    request: GoogleAdsGaqlRequest,
    source_uri: String,
    endpoint: String,
    api_version: String,
    observed_at: DateTime<Utc>,
    freshness: GoogleAdsFreshness,
    source_revision: u64,
    raw_evidence_digest: String,
    content_digest: String,
    classification: GoogleAdsEvidenceClassification,
    first_party: bool,
    account_probe: GoogleAdsAccountProbe,
    call: GoogleAdsCallReceipt,
    page: GoogleAdsPage,
    read_observation: GoogleAdsReadObservation,
    usage: GoogleAdsUsage,
    next_cursor: Option<GoogleAdsCursor>,
    charged: bool,
    replayed: bool,
}

impl GoogleAdsGrowthSignal {
    pub const fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn request(&self) -> &GoogleAdsGaqlRequest {
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

    pub const fn freshness(&self) -> &GoogleAdsFreshness {
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

    pub const fn classification(&self) -> GoogleAdsEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn account_probe(&self) -> &GoogleAdsAccountProbe {
        &self.account_probe
    }

    pub const fn call(&self) -> &GoogleAdsCallReceipt {
        &self.call
    }

    pub const fn page(&self) -> &GoogleAdsPage {
        &self.page
    }

    pub const fn read_observation(&self) -> &GoogleAdsReadObservation {
        &self.read_observation
    }

    pub const fn usage(&self) -> &GoogleAdsUsage {
        &self.usage
    }

    pub const fn next_cursor(&self) -> Option<&GoogleAdsCursor> {
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
pub enum GoogleAdsHttpMethod {
    Post,
}

#[derive(Clone, PartialEq)]
pub struct GoogleAdsHttpRequest {
    method: GoogleAdsHttpMethod,
    path: String,
    body: Value,
}

impl fmt::Debug for GoogleAdsHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_digest", &digest_json(&self.body).ok())
            .finish()
    }
}

impl GoogleAdsHttpRequest {
    fn post(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: GoogleAdsHttpMethod::Post,
            path: path.into(),
            body,
        }
    }

    pub const fn method(&self) -> GoogleAdsHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn body(&self) -> &Value {
        &self.body
    }

    pub fn body_digest(&self) -> Result<String, GoogleAdsError> {
        digest_json(&self.body)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GoogleAdsHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
    raw_evidence_digest: String,
}

impl GoogleAdsHttpResponse {
    pub fn new(
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
    ) -> Result<Self, GoogleAdsError> {
        let raw = serde_json::to_vec(&body).map_err(|_| GoogleAdsError::InvalidProviderResponse)?;
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
    ) -> Result<Self, GoogleAdsError> {
        if !is_sha256(&raw_evidence_digest) {
            return Err(GoogleAdsError::InvalidProviderResponse);
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

    pub const fn headers(&self) -> &BTreeMap<String, String> {
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
pub struct GoogleAdsTimeoutRetryPolicy {
    timeout_ms: u64,
    max_attempts: u8,
    backoff_ms: u64,
    max_backoff_ms: u64,
}

impl GoogleAdsTimeoutRetryPolicy {
    pub fn new(
        timeout_ms: u64,
        max_attempts: u8,
        backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Result<Self, GoogleAdsError> {
        if !(1..=30_000).contains(&timeout_ms)
            || !(1..=4).contains(&max_attempts)
            || backoff_ms > max_backoff_ms
            || max_backoff_ms > 10_000
        {
            return Err(GoogleAdsError::InvalidRetryPolicy);
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

impl Default for GoogleAdsTimeoutRetryPolicy {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            max_attempts: 3,
            backoff_ms: 100,
            max_backoff_ms: 1_000,
        }
    }
}

/// Resolved OAuth bearer and developer-token material. It is never serialized
/// and its Debug representation intentionally omits both secret values.
pub struct GoogleAdsOAuthCredentials {
    access_token: Zeroizing<String>,
    developer_token: Zeroizing<String>,
}

impl fmt::Debug for GoogleAdsOAuthCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsOAuthCredentials")
            .field("present", &true)
            .finish()
    }
}

impl GoogleAdsOAuthCredentials {
    pub fn new(
        access_token: impl Into<String>,
        developer_token: impl Into<String>,
    ) -> Result<Self, GoogleAdsError> {
        let access_token = access_token.into();
        let developer_token = developer_token.into();
        if access_token.trim().is_empty() || developer_token.trim().is_empty() {
            return Err(GoogleAdsError::MissingCredential);
        }
        Ok(Self {
            access_token: Zeroizing::new(access_token),
            developer_token: Zeroizing::new(developer_token),
        })
    }
}

pub trait GoogleAdsTransport: fmt::Debug + Send {
    fn execute(
        &mut self,
        request: GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsHttpResponse, GoogleAdsError>;

    fn revoke(&mut self) {}
}

pub struct GoogleAdsHttpTransport {
    client: Client,
    base_url: Url,
    credentials: GoogleAdsOAuthCredentials,
    login_customer_id: String,
}

impl fmt::Debug for GoogleAdsHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsHttpTransport")
            .field("base_url", &self.base_url)
            .field("login_customer_id", &self.login_customer_id)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl GoogleAdsHttpTransport {
    pub fn new(
        credentials: GoogleAdsOAuthCredentials,
        login_customer_id: impl Into<String>,
        timeout: StdDuration,
    ) -> Result<Self, GoogleAdsError> {
        let login_customer_id = login_customer_id.into();
        let login_customer_id = normalize_customer_id(&login_customer_id)?;
        let base_url =
            Url::parse(GOOGLE_ADS_API_BASE_URL).map_err(|_| GoogleAdsError::InvalidEndpoint)?;
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| GoogleAdsError::Transport)?;
        Ok(Self {
            client,
            base_url,
            credentials,
            login_customer_id,
        })
    }

    pub fn production(
        credentials: GoogleAdsOAuthCredentials,
        login_customer_id: impl Into<String>,
        policy: &GoogleAdsTimeoutRetryPolicy,
    ) -> Result<Self, GoogleAdsError> {
        Self::new(
            credentials,
            login_customer_id,
            StdDuration::from_millis(policy.timeout_ms()),
        )
    }
}

impl GoogleAdsTransport for GoogleAdsHttpTransport {
    fn execute(
        &mut self,
        request: GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsHttpResponse, GoogleAdsError> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| GoogleAdsError::InvalidEndpoint)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(self.credentials.access_token.as_str())
            .header("developer-token", self.credentials.developer_token.as_str())
            .header("login-customer-id", &self.login_customer_id)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&request.body)
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    GoogleAdsError::Timeout
                } else {
                    GoogleAdsError::Transport
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
        let bytes = response.bytes().map_err(|_| GoogleAdsError::Transport)?;
        let raw_evidence_digest = sha256_bytes(&bytes);
        let body = serde_json::from_slice::<Value>(&bytes)
            .map_err(|_| GoogleAdsError::InvalidProviderResponse)?;
        GoogleAdsHttpResponse::with_raw_evidence_digest(status, headers, body, raw_evidence_digest)
    }

    fn revoke(&mut self) {
        self.credentials.access_token.zeroize();
        self.credentials.developer_token.zeroize();
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GoogleAdsError {
    #[error("Google Ads request is invalid")]
    InvalidRequest,
    #[error("Google Ads endpoint is invalid")]
    InvalidEndpoint,
    #[error("Google Ads customer id is invalid")]
    InvalidCustomerId,
    #[error("Google Ads GAQL must be a bounded SELECT query")]
    InvalidQuery,
    #[error("Google Ads page token is invalid")]
    InvalidPageToken,
    #[error("Google Ads retry policy is invalid")]
    InvalidRetryPolicy,
    #[error("Google Ads credential is missing")]
    MissingCredential,
    #[error("Google Ads provider response is invalid")]
    InvalidProviderResponse,
    #[error("Google Ads provider returned HTTP status {0}")]
    ProviderHttpStatus(u16),
    #[error("Google Ads provider returned status {status} ({code})")]
    ProviderStatus { code: i64, status: String },
    #[error("Google Ads OAuth authentication failed")]
    Unauthorized,
    #[error("Google Ads customer permission was denied")]
    PermissionDenied,
    #[error("Google Ads provider transport failed")]
    Transport,
    #[error("Google Ads provider request timed out")]
    Timeout,
    #[error("Google Ads provider quota is exhausted")]
    QuotaExhausted,
    #[error("Google Ads service is not mounted")]
    NotMounted,
    #[error("Google Ads service is revoked")]
    Revoked,
    #[error("Google Ads service scope does not match")]
    ScopeMismatch,
    #[error("Google Ads provider freshness changed while paging")]
    FreshnessDrift,
    #[error("Google Ads provider state is not ready")]
    ProviderPending,
    #[error("Google Ads connector state is unavailable")]
    StateUnavailable,
    #[error("Google Ads quota boundary is exhausted")]
    QuotaLimitExceeded,
    #[error("Connector SDK rejected the Google Ads operation: {0}")]
    Connector(ConnectorError),
}

impl From<ConnectorError> for GoogleAdsError {
    fn from(error: ConnectorError) -> Self {
        Self::Connector(error)
    }
}

#[derive(Clone, Debug)]
struct BoundGoogleAdsPage {
    request: GoogleAdsGaqlRequest,
    cursor: Option<GoogleAdsCursor>,
}

#[derive(Default)]
struct GoogleAdsAdapterState {
    revoked: bool,
    account_probe: Option<GoogleAdsAccountProbe>,
    bound_pages: BTreeMap<(String, u64), BoundGoogleAdsPage>,
    signals: BTreeMap<String, GoogleAdsGrowthSignal>,
}

pub struct GoogleAdsAdapter<T: GoogleAdsTransport> {
    descriptor: ConnectorDescriptor,
    transport: T,
    policy: GoogleAdsTimeoutRetryPolicy,
    provenance: ProviderProvenanceClass,
    login_customer_id: String,
    result_ttl: Duration,
    state: Arc<Mutex<GoogleAdsAdapterState>>,
}

impl<T: GoogleAdsTransport> fmt::Debug for GoogleAdsAdapter<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsAdapter")
            .field("descriptor", &self.descriptor)
            .field("policy", &self.policy)
            .field("login_customer_id", &self.login_customer_id)
            .field("result_ttl", &self.result_ttl)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl<T: GoogleAdsTransport> Drop for GoogleAdsAdapter<T> {
    fn drop(&mut self) {
        self.transport.revoke();
        if let Ok(mut state) = self.state.lock() {
            state.revoked = true;
            state.account_probe = None;
            state.bound_pages.clear();
            state.signals.clear();
        }
    }
}

impl<T: GoogleAdsTransport> GoogleAdsAdapter<T> {
    pub fn new(
        transport: T,
        login_customer_id: impl Into<String>,
        policy: GoogleAdsTimeoutRetryPolicy,
    ) -> Result<Self, GoogleAdsError> {
        Self::new_with_provenance(
            transport,
            login_customer_id,
            policy,
            ProviderProvenanceClass::ProductionProvider,
        )
    }

    pub fn controlled(
        transport: T,
        login_customer_id: impl Into<String>,
        policy: GoogleAdsTimeoutRetryPolicy,
    ) -> Result<Self, GoogleAdsError> {
        Self::new_with_provenance(
            transport,
            login_customer_id,
            policy,
            ProviderProvenanceClass::ControlledProvider,
        )
    }

    fn new_with_provenance(
        transport: T,
        login_customer_id: impl Into<String>,
        policy: GoogleAdsTimeoutRetryPolicy,
        provenance: ProviderProvenanceClass,
    ) -> Result<Self, GoogleAdsError> {
        let login_customer_id = login_customer_id.into();
        let login_customer_id = normalize_customer_id(&login_customer_id)?;
        let registry = google_ads_registry()?;
        let descriptor = ConnectorDescriptor::new(
            ProviderAdapterIdentity::new(
                GOOGLE_ADS_GAQL_ADAPTER_ID,
                GOOGLE_ADS_GAQL_ADAPTER_VERSION,
            )
            .map_err(ConnectorError::from)?,
            registry.registrations().iter().cloned(),
        )
        .map_err(GoogleAdsError::Connector)?;
        Ok(Self {
            descriptor,
            transport,
            policy,
            provenance,
            login_customer_id,
            result_ttl: Duration::seconds(DEFAULT_RESULT_TTL_SECONDS),
            state: Arc::new(Mutex::new(GoogleAdsAdapterState::default())),
        })
    }

    pub fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    pub fn policy(&self) -> &GoogleAdsTimeoutRetryPolicy {
        &self.policy
    }

    fn state_handle(&self) -> Arc<Mutex<GoogleAdsAdapterState>> {
        Arc::clone(&self.state)
    }

    pub fn account_probe(&self) -> Result<Option<GoogleAdsAccountProbe>, GoogleAdsError> {
        Ok(self.lock_state()?.account_probe.clone())
    }

    pub fn take_signal(
        &self,
        observation_id: &str,
    ) -> Result<GoogleAdsGrowthSignal, GoogleAdsError> {
        self.lock_state()?
            .signals
            .remove(observation_id)
            .ok_or(GoogleAdsError::StateUnavailable)
    }

    pub fn bind_page(
        &mut self,
        request: GoogleAdsGaqlRequest,
        cursor: Option<GoogleAdsCursor>,
    ) -> Result<(), GoogleAdsError> {
        request.validate()?;
        let source_revision = self.current_source_revision()?;
        if let Some(cursor) = &cursor {
            cursor.validate(request.scope(), &request.request_digest(), source_revision)?;
        }
        let key = (
            request.request_digest(),
            cursor.as_ref().map_or(0, GoogleAdsCursor::sequence),
        );
        let mut state = self.lock_state()?;
        if state.revoked {
            return Err(GoogleAdsError::Revoked);
        }
        state
            .bound_pages
            .insert(key, BoundGoogleAdsPage { request, cursor });
        Ok(())
    }

    /// Controlled transport entry point for deterministic worlds. The result
    /// is explicitly controlled evidence and cannot pass the SDK production
    /// probe fence or claim a live Google Ads account.
    pub fn read_controlled(
        &mut self,
        request: GoogleAdsGaqlRequest,
        cursor: Option<GoogleAdsCursor>,
        at: DateTime<Utc>,
    ) -> Result<GoogleAdsGrowthSignal, GoogleAdsError> {
        if self.account_probe()?.is_none() {
            self.probe_transport(
                request.scope(),
                at,
                ProviderProvenanceClass::ControlledProvider,
            )?;
        }
        let request_digest = request.request_digest();
        let sequence = cursor.as_ref().map_or(0, GoogleAdsCursor::sequence);
        let scope = request.scope().clone();
        let quota_limit = request.max_quota_units();
        let budget = DispatchBudget::new(100, at + Duration::minutes(1), quota_limit, 0)
            .map_err(GoogleAdsError::Connector)?;
        self.bind_page(request, cursor)?;
        let capability =
            ProviderCapabilityKey::new(GOOGLE_ADS_PROVIDER_ID, GOOGLE_ADS_READ_CAPABILITY)
                .map_err(ConnectorError::from)?;
        let observation = self.read_bound(
            &scope,
            &capability,
            &request_digest,
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
    ) -> Result<ProbeObservation, GoogleAdsError> {
        if scope.provider_id() != GOOGLE_ADS_PROVIDER_ID
            || !valid_customer_id(scope.account_id())
            || scope.account_id() == self.login_customer_id
                && !valid_customer_id(&self.login_customer_id)
        {
            return Err(GoogleAdsError::ScopeMismatch);
        }
        if self.lock_state()?.revoked {
            return Err(GoogleAdsError::Revoked);
        }
        let probe_request = GoogleAdsHttpRequest::post(
            format!(
                "/{}/customers/{}/{}",
                GOOGLE_ADS_API_VERSION,
                scope.account_id(),
                GOOGLE_ADS_SEARCH_PATH_SUFFIX
            ),
            json!({"query": GOOGLE_ADS_PROBE_QUERY}),
        );
        let envelope = self.execute_with_retry(&probe_request)?;
        let row = envelope
            .results
            .first()
            .ok_or(GoogleAdsError::InvalidProviderResponse)?;
        let parsed = parse_google_ads_row(row)?;
        let customer = parsed
            .fields
            .get("customer")
            .ok_or(GoogleAdsError::InvalidProviderResponse)?;
        let customer_id =
            nested_string(customer, "id").ok_or(GoogleAdsError::InvalidProviderResponse)?;
        if customer_id != scope.account_id() {
            return Err(GoogleAdsError::ScopeMismatch);
        }
        let source_revision = source_revision(&canonical_digest(&[
            envelope.response.raw_evidence_digest(),
            GOOGLE_ADS_API_VERSION,
            scope.account_id(),
            self.login_customer_id.as_str(),
        ]));
        let classification = classification_for(provenance);
        let account_probe = GoogleAdsAccountProbe {
            scope: scope.clone(),
            customer_id: customer_id.to_owned(),
            login_customer_id: self.login_customer_id.clone(),
            status: ProbeStatus::Reachable,
            provenance_class: provenance,
            classification,
            first_party: provenance == ProviderProvenanceClass::ProductionProvider,
            descriptive_name: nested_string(customer, "descriptiveName").map(str::to_owned),
            currency_code: nested_string(customer, "currencyCode").map(str::to_owned),
            time_zone: nested_string(customer, "timeZone").map(str::to_owned),
            observed_at: at,
            expires_at: at + Duration::seconds(DEFAULT_PROBE_TTL_SECONDS),
            source_revision,
            request_id: envelope.request_id.clone(),
            response_digest: envelope.response.raw_evidence_digest().to_owned(),
            raw_evidence_digest: envelope.response.raw_evidence_digest().to_owned(),
            cost_class: cost_class_for(provenance),
            quota: quota_from_headers(envelope.response.headers(), 1, 1),
        };
        let mut state = self.lock_state()?;
        state.account_probe = Some(account_probe);
        Ok(ProbeObservation::new(
            ProbeStatus::Reachable,
            provenance,
            at,
            at + Duration::seconds(DEFAULT_PROBE_TTL_SECONDS),
            envelope.response.raw_evidence_digest().to_owned(),
        )?)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn read_bound(
        &mut self,
        scope: &ConnectorScope,
        capability: &ProviderCapabilityKey,
        request_digest: &str,
        at: DateTime<Utc>,
        budget: &DispatchBudget,
        sequence: u64,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, GoogleAdsError> {
        let bound = {
            let mut state = self.lock_state()?;
            if state.revoked {
                return Err(GoogleAdsError::Revoked);
            }
            state
                .bound_pages
                .remove(&(request_digest.to_owned(), sequence))
                .ok_or(GoogleAdsError::InvalidRequest)?
        };
        if bound.request.scope() != scope || bound.request.request_digest() != request_digest {
            return Err(GoogleAdsError::ScopeMismatch);
        }
        let source_revision = self.current_source_revision()?;
        if let Some(cursor) = &bound.cursor {
            cursor.validate(scope, request_digest, source_revision)?;
        }
        let estimated_units = 1_u64;
        if estimated_units > budget.quota.limit() {
            return Err(GoogleAdsError::QuotaLimitExceeded);
        }
        let provider_request = GoogleAdsHttpRequest::post(
            bound.request.endpoint_path(),
            bound.request.provider_body(bound.cursor.as_ref()),
        );
        let envelope = self.execute_with_retry(&provider_request)?;
        let page_sequence = if sequence == 0 { 1 } else { sequence };
        let page = GoogleAdsPage {
            page_sequence,
            rows: envelope
                .results
                .iter()
                .map(parse_google_ads_row)
                .collect::<Result<Vec<_>, _>>()?,
            field_mask: envelope.field_mask.clone(),
            next_page_token: envelope.next_page_token.clone(),
        };
        let next_cursor = page.next_cursor(
            scope,
            request_digest,
            source_revision,
            bound.request.max_pages(),
        )?;
        let content_digest = digest_json(&page)?;
        let response_digest = envelope.response.raw_evidence_digest().to_owned();
        let observation_id = format!(
            "read-observation-{}",
            &response_digest[..24.min(response_digest.len())]
        );
        let freshness = FreshnessWindow::new(at, at + self.result_ttl, source_revision)
            .map_err(GoogleAdsError::Connector)?;
        let sdk_next_cursor = next_cursor
            .as_ref()
            .map(|cursor| cursor.sdk_cursor(scope))
            .transpose()?;
        let row_count =
            u32::try_from(page.row_count()).map_err(|_| GoogleAdsError::InvalidProviderResponse)?;
        let read_observation = ReadObservation::new(
            observation_id.clone(),
            scope.clone(),
            capability.clone(),
            self.descriptor.identity().clone(),
            request_digest.to_owned(),
            response_digest.clone(),
            content_digest.clone(),
            provenance,
            freshness.clone(),
            page_sequence,
            row_count,
            sdk_next_cursor,
        )
        .map_err(GoogleAdsError::Connector)?;
        let (account_probe, classification, first_party) = {
            let state = self.lock_state()?;
            let probe = state
                .account_probe
                .clone()
                .ok_or(GoogleAdsError::ProviderPending)?;
            (probe.clone(), probe.classification, probe.first_party)
        };
        let cost_class = cost_class_for(provenance);
        let quota = quota_from_headers(
            envelope.response.headers(),
            budget.quota.limit(),
            budget.quota.used().saturating_add(estimated_units),
        );
        let usage = GoogleAdsUsage {
            cost_class,
            request_units: 1,
            charged: provenance == ProviderProvenanceClass::ProductionProvider,
            attempts: envelope.attempts,
            request_id: envelope.request_id.clone(),
            quota,
        };
        let call = GoogleAdsCallReceipt {
            endpoint: bound.request.endpoint_path(),
            api_version: bound.request.api_version().to_owned(),
            query_digest: request_digest.to_owned(),
            observed_at: at,
            request_id: envelope.request_id.clone(),
            response_digest: response_digest.clone(),
            raw_evidence_digest: envelope.response.raw_evidence_digest().to_owned(),
            cost_class,
        };
        let signal = GoogleAdsGrowthSignal {
            scope: scope.clone(),
            request: bound.request.clone(),
            source_uri: format!(
                "googleads://{}/googleAds:search?query={}",
                scope.account_id(),
                request_digest
            ),
            endpoint: bound.request.endpoint_path(),
            api_version: bound.request.api_version().to_owned(),
            observed_at: at,
            freshness: GoogleAdsFreshness::from_sdk(&freshness),
            source_revision,
            raw_evidence_digest: envelope.response.raw_evidence_digest().to_owned(),
            content_digest,
            classification,
            first_party,
            account_probe,
            call,
            page,
            read_observation: GoogleAdsReadObservation::from_sdk(
                &read_observation,
                next_cursor.clone(),
            ),
            usage,
            next_cursor,
            charged: provenance == ProviderProvenanceClass::ProductionProvider,
            replayed: false,
        };
        self.lock_state()?.signals.insert(observation_id, signal);
        Ok(read_observation)
    }

    fn execute_with_retry(
        &mut self,
        request: &GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsTransportEnvelope, GoogleAdsError> {
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
                    let parsed = parse_success(&response)?;
                    return Ok(GoogleAdsTransportEnvelope {
                        response,
                        request_id: parsed.request_id,
                        results: parsed.results,
                        field_mask: parsed.field_mask,
                        next_page_token: parsed.next_page_token,
                        attempts: attempt,
                    });
                }
                Err(error)
                    if matches!(error, GoogleAdsError::Transport | GoogleAdsError::Timeout)
                        && attempt < self.policy.max_attempts() =>
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

    fn current_source_revision(&self) -> Result<u64, GoogleAdsError> {
        self.lock_state()?
            .account_probe
            .as_ref()
            .map(GoogleAdsAccountProbe::source_revision)
            .ok_or(GoogleAdsError::ProviderPending)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, GoogleAdsAdapterState>, GoogleAdsError> {
        self.state
            .lock()
            .map_err(|_| GoogleAdsError::StateUnavailable)
    }
}

impl<T: GoogleAdsTransport> ConnectorAdapter for GoogleAdsAdapter<T> {
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
                GoogleAdsError::Connector(error) => error,
                _ => ConnectorError::ProviderRejected,
            })
    }

    fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
        let sequence = request.cursor.as_ref().map_or(0, Cursor::sequence);
        self.read_bound(
            &request.scope,
            &request.capability,
            &request.query_digest,
            request.at,
            &request.budget,
            sequence,
            self.provenance,
        )
        .map_err(|error| match error {
            GoogleAdsError::Connector(error) => error,
            GoogleAdsError::QuotaLimitExceeded => ConnectorError::QuotaExceeded,
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
        state.account_probe = None;
        state.bound_pages.clear();
        state.signals.clear();
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct GoogleAdsTransportEnvelope {
    response: GoogleAdsHttpResponse,
    request_id: String,
    results: Vec<Value>,
    field_mask: Vec<String>,
    next_page_token: Option<String>,
    attempts: u8,
}

#[derive(Clone, Debug)]
struct ParsedGoogleAdsResponse {
    request_id: String,
    results: Vec<Value>,
    field_mask: Vec<String>,
    next_page_token: Option<String>,
}

fn google_ads_registry() -> Result<ProviderAdapterRegistry, GoogleAdsError> {
    ProviderAdapterRegistry::from_contract_json(GOOGLE_ADS_READ_CONTRACT_JSON)
        .map_err(|_| GoogleAdsError::Connector(ConnectorError::InvalidRegistry))
}

fn parse_success(
    response: &GoogleAdsHttpResponse,
) -> Result<ParsedGoogleAdsResponse, GoogleAdsError> {
    if !(200..300).contains(&response.status()) {
        return Err(provider_error(response));
    }
    let request_id =
        request_id(response.headers()).ok_or(GoogleAdsError::InvalidProviderResponse)?;
    let results = response
        .body()
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let field_mask = response
        .body()
        .get("fieldMask")
        .and_then(Value::as_str)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let next_page_token = response
        .body()
        .get("nextPageToken")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if next_page_token
        .as_deref()
        .is_some_and(|token| token.is_empty() || token.len() > MAX_PAGE_TOKEN_LENGTH)
    {
        return Err(GoogleAdsError::InvalidPageToken);
    }
    Ok(ParsedGoogleAdsResponse {
        request_id,
        results,
        field_mask,
        next_page_token,
    })
}

fn provider_error(response: &GoogleAdsHttpResponse) -> GoogleAdsError {
    let error = response.body().get("error");
    let code = error
        .and_then(|value| value.get("code"))
        .and_then(Value::as_i64)
        .unwrap_or(i64::from(response.status()));
    let status = error
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("HTTP_ERROR")
        .to_owned();
    let message = error
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if response.status() == 401 || status == "UNAUTHENTICATED" {
        GoogleAdsError::Unauthorized
    } else if response.status() == 403 || status == "PERMISSION_DENIED" {
        GoogleAdsError::PermissionDenied
    } else if response.status() == 429 || status == "RESOURCE_EXHAUSTED" {
        GoogleAdsError::QuotaExhausted
    } else if status == "INVALID_ARGUMENT" && message.contains("page") {
        GoogleAdsError::InvalidPageToken
    } else if response.status() == 400 || status == "INVALID_ARGUMENT" {
        GoogleAdsError::InvalidQuery
    } else if response.status() >= 400 {
        GoogleAdsError::ProviderStatus { code, status }
    } else {
        GoogleAdsError::ProviderHttpStatus(response.status())
    }
}

fn parse_google_ads_row(value: &Value) -> Result<GoogleAdsRow, GoogleAdsError> {
    let fields = value
        .as_object()
        .ok_or(GoogleAdsError::InvalidProviderResponse)?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    Ok(GoogleAdsRow {
        resource_name: find_resource_name(value),
        fields,
    })
}

fn find_resource_name(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => {
            if let Some(resource_name) = object.get("resourceName").and_then(Value::as_str) {
                return Some(resource_name.to_owned());
            }
            object.values().find_map(find_resource_name)
        }
        Value::Array(values) => values.iter().find_map(find_resource_name),
        _ => None,
    }
}

fn nested_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key).and_then(Value::as_str)
}

fn request_id(headers: &BTreeMap<String, String>) -> Option<String> {
    ["google-ads-request-id", "request-id"]
        .iter()
        .find_map(|name| headers.get(*name))
        .filter(|value| !value.trim().is_empty())
        .cloned()
}

fn quota_from_headers(
    headers: &BTreeMap<String, String>,
    local_limit: u64,
    local_used: u64,
) -> GoogleAdsQuota {
    GoogleAdsQuota {
        provider_operation_count: 1,
        reported_daily_limit: headers
            .get("google-ads-daily-operations-limit")
            .and_then(|value| value.parse::<u64>().ok()),
        local_limit,
        local_used,
    }
}

fn classification_for(provenance: ProviderProvenanceClass) -> GoogleAdsEvidenceClassification {
    if provenance == ProviderProvenanceClass::ProductionProvider {
        GoogleAdsEvidenceClassification::FirstParty
    } else {
        GoogleAdsEvidenceClassification::ControlledFixture
    }
}

fn cost_class_for(provenance: ProviderProvenanceClass) -> GoogleAdsCostClass {
    if provenance == ProviderProvenanceClass::ProductionProvider {
        GoogleAdsCostClass::ApiOperation
    } else {
        GoogleAdsCostClass::ControlledFixture
    }
}

fn is_retryable_status(status: u16) -> bool {
    status == 429 || status >= 500
}

fn is_select_query(query: &str) -> bool {
    let mut words = query.split_whitespace();
    let first_is_select = words
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("SELECT"));
    first_is_select && words.any(|word| word.eq_ignore_ascii_case("FROM"))
}

fn normalize_customer_id(value: &str) -> Result<String, GoogleAdsError> {
    let value = value.trim().replace('-', "");
    if valid_customer_id(&value) {
        Ok(value)
    } else {
        Err(GoogleAdsError::InvalidCustomerId)
    }
}

fn valid_customer_id(value: &str) -> bool {
    (1..=MAX_CUSTOMER_ID_LENGTH).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, GoogleAdsError> {
    let bytes = serde_json::to_vec(value).map_err(|_| GoogleAdsError::InvalidRequest)?;
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
pub struct GoogleAdsReplayLedger {
    pages: BTreeMap<String, GoogleAdsGrowthSignal>,
}

impl GoogleAdsReplayLedger {
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn replay(&self, request_digest: &str, sequence: u64) -> Option<GoogleAdsGrowthSignal> {
        self.pages
            .get(&ledger_key(request_digest, sequence))
            .map(replayed_signal)
    }

    pub fn record(&mut self, signal: GoogleAdsGrowthSignal) {
        let key = ledger_key(
            signal.request().request_digest().as_str(),
            signal.read_observation().page_sequence(),
        );
        self.pages.insert(key, signal);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAdsRegistrationState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsServiceDefinition {
    service_id: String,
    provider_id: String,
    adapter_id: String,
    adapter_version: u32,
    capability_id: String,
    read_only: bool,
}

impl GoogleAdsServiceDefinition {
    fn new() -> Self {
        Self {
            service_id: "growth-signal.google-ads.gaql.read".to_owned(),
            provider_id: GOOGLE_ADS_PROVIDER_ID.to_owned(),
            adapter_id: GOOGLE_ADS_GAQL_ADAPTER_ID.to_owned(),
            adapter_version: GOOGLE_ADS_GAQL_ADAPTER_VERSION,
            capability_id: GOOGLE_ADS_READ_CAPABILITY.to_owned(),
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
pub struct GoogleAdsServiceRegistration {
    registration_id: String,
    service_id: String,
    provider_id: String,
    adapter_id: String,
    scope_digest: String,
    request_digest: String,
    state: GoogleAdsRegistrationState,
    revoked_at: Option<DateTime<Utc>>,
    revocation_reason_digest: Option<String>,
}

impl GoogleAdsServiceRegistration {
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

    pub const fn state(&self) -> GoogleAdsRegistrationState {
        self.state
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn revocation_reason_digest(&self) -> Option<&str> {
        self.revocation_reason_digest.as_deref()
    }
}

pub struct GoogleAdsService<T: GoogleAdsTransport> {
    definition: GoogleAdsServiceDefinition,
    registration: GoogleAdsServiceRegistration,
    scope: ConnectorScope,
    request: GoogleAdsGaqlRequest,
    secret: SecretReference,
    lease: CredentialLease,
    worker: ConnectorWorker<GoogleAdsAdapter<T>>,
    adapter_state: Arc<Mutex<GoogleAdsAdapterState>>,
    session: Option<AuthSession>,
    probe: Option<ProbeResult>,
    live_probe: Option<LiveProbeFence>,
    ledger: GoogleAdsReplayLedger,
}

impl<T: GoogleAdsTransport> fmt::Debug for GoogleAdsService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsService")
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request.request_digest())
            .field("worker", &self.worker)
            .field("ledger_page_count", &self.ledger.page_count())
            .finish_non_exhaustive()
    }
}

impl<T: GoogleAdsTransport> GoogleAdsService<T> {
    pub fn new(
        secret: SecretReference,
        request: GoogleAdsGaqlRequest,
        transport: T,
        policy: GoogleAdsTimeoutRetryPolicy,
        now: DateTime<Utc>,
        ledger: GoogleAdsReplayLedger,
    ) -> Result<Self, GoogleAdsError> {
        let adapter = GoogleAdsAdapter::new(transport, request.login_customer_id(), policy)?;
        Self::new_with_adapter(secret, request, adapter, now, ledger)
    }

    fn new_with_adapter(
        secret: SecretReference,
        request: GoogleAdsGaqlRequest,
        adapter: GoogleAdsAdapter<T>,
        now: DateTime<Utc>,
        ledger: GoogleAdsReplayLedger,
    ) -> Result<Self, GoogleAdsError> {
        if secret.scope() != request.scope() {
            return Err(GoogleAdsError::ScopeMismatch);
        }
        let scope = request.scope().clone();
        let adapter_state = adapter.state_handle();
        let registry = google_ads_registry()?;
        let worker = ConnectorWorker::new(
            format!("worker-google-ads-{}", &scope.digest()[..20]),
            adapter,
            registry,
            scope.clone(),
            now,
            now + Duration::minutes(10),
        )
        .map_err(GoogleAdsError::Connector)?;
        let adapter_identity = ProviderAdapterIdentity::new(
            GOOGLE_ADS_GAQL_ADAPTER_ID,
            GOOGLE_ADS_GAQL_ADAPTER_VERSION,
        )
        .map_err(ConnectorError::from)?;
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter_identity,
            format!("lease-google-ads-{}", &scope.digest()[..20]),
            1,
            now,
            now + Duration::minutes(10),
        )
        .map_err(GoogleAdsError::Connector)?;
        let definition = GoogleAdsServiceDefinition::new();
        let request_digest = request.request_digest();
        let registration_digest =
            canonical_digest(&[scope.digest().as_str(), request_digest.as_str()]);
        let registration = GoogleAdsServiceRegistration {
            registration_id: format!("google-ads-registration-{registration_digest}"),
            service_id: definition.service_id().to_owned(),
            provider_id: definition.provider_id().to_owned(),
            adapter_id: definition.adapter_id().to_owned(),
            scope_digest: scope.digest(),
            request_digest,
            state: GoogleAdsRegistrationState::Unmounted,
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

    pub fn definition(&self) -> &GoogleAdsServiceDefinition {
        &self.definition
    }

    pub fn registration(&self) -> &GoogleAdsServiceRegistration {
        &self.registration
    }

    pub const fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn request(&self) -> &GoogleAdsGaqlRequest {
        &self.request
    }

    pub fn ledger(&self) -> GoogleAdsReplayLedger {
        self.ledger.clone()
    }

    pub fn mount(&mut self, now: DateTime<Utc>) -> Result<(), GoogleAdsError> {
        match self.registration.state {
            GoogleAdsRegistrationState::Mounted => return Ok(()),
            GoogleAdsRegistrationState::Revoked => return Err(GoogleAdsError::Revoked),
            GoogleAdsRegistrationState::Unmounted => {}
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, now, now + Duration::minutes(10))
                .map_err(GoogleAdsError::Connector)?;
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
            .map_err(GoogleAdsError::Connector)?;
        let probe = self
            .worker
            .probe(ProbeRequest {
                dispatch: dispatch.clone(),
                scope: self.scope.clone(),
                secret_reference: self.secret.clone(),
                credential_lease: self.lease.clone(),
                session: session.clone(),
                probe_revision: 1,
                result_id: format!("probe-result-google-ads-{}", &self.scope.digest()[..20]),
                at: now,
            })
            .map_err(GoogleAdsError::Connector)?;
        let live_probe = self
            .worker
            .authorize_probe(&probe, now)
            .map_err(GoogleAdsError::Connector)?;
        self.session = Some(session);
        self.probe = Some(probe);
        self.live_probe = Some(live_probe);
        self.registration.state = GoogleAdsRegistrationState::Mounted;
        Ok(())
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<(), GoogleAdsError> {
        if self.registration.state == GoogleAdsRegistrationState::Revoked {
            return Err(GoogleAdsError::Revoked);
        }
        if self.registration.state == GoogleAdsRegistrationState::Mounted {
            let dispatch = self.worker.dispatch_fence();
            self.worker
                .cancel(&dispatch, at)
                .map_err(GoogleAdsError::Connector)?;
            self.session = None;
            self.probe = None;
            self.live_probe = None;
            let mut state = self
                .adapter_state
                .lock()
                .map_err(|_| GoogleAdsError::StateUnavailable)?;
            state.account_probe = None;
            state.bound_pages.clear();
            state.signals.clear();
            self.registration.state = GoogleAdsRegistrationState::Unmounted;
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason_digest: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<(), GoogleAdsError> {
        let reason_digest = reason_digest.into();
        if !is_sha256(&reason_digest) {
            return Err(GoogleAdsError::InvalidRequest);
        }
        if self.registration.state == GoogleAdsRegistrationState::Revoked {
            return Err(GoogleAdsError::Revoked);
        }
        if self.worker.lease().state() != hartevo_connector_sdk::WorkerLeaseState::Active {
            let previous = self.worker.dispatch_fence();
            self.worker
                .renew_generation(&previous, at, at + Duration::minutes(10))
                .map_err(GoogleAdsError::Connector)?;
        }
        let dispatch = self.worker.dispatch_fence();
        self.worker
            .revoke(RevokeRequest {
                dispatch,
                scope: self.scope.clone(),
                reason_digest: reason_digest.clone(),
                at,
            })
            .map_err(GoogleAdsError::Connector)?;
        let _ = self.secret.revoke(at);
        self.registration.state = GoogleAdsRegistrationState::Revoked;
        self.registration.revoked_at = Some(at);
        self.registration.revocation_reason_digest = Some(reason_digest);
        self.session = None;
        self.probe = None;
        self.live_probe = None;
        Ok(())
    }

    pub fn read(
        &mut self,
        cursor: Option<&GoogleAdsCursor>,
        at: DateTime<Utc>,
        budget: DispatchBudget,
    ) -> Result<GoogleAdsGrowthSignal, GoogleAdsError> {
        if self.registration.state != GoogleAdsRegistrationState::Mounted {
            return Err(match self.registration.state {
                GoogleAdsRegistrationState::Revoked => GoogleAdsError::Revoked,
                GoogleAdsRegistrationState::Unmounted | GoogleAdsRegistrationState::Mounted => {
                    GoogleAdsError::NotMounted
                }
            });
        }
        let request_digest = self.request.request_digest();
        let sequence = cursor.map_or(1, GoogleAdsCursor::sequence);
        if let Some(cached) = self.ledger.replay(&request_digest, sequence) {
            return Ok(cached);
        }
        let source_revision = self
            .adapter_state
            .lock()
            .map_err(|_| GoogleAdsError::StateUnavailable)?
            .account_probe
            .as_ref()
            .map(GoogleAdsAccountProbe::source_revision)
            .ok_or(GoogleAdsError::ProviderPending)?;
        if let Some(cursor) = cursor {
            cursor.validate(&self.scope, &request_digest, source_revision)?;
        }
        bind_page_in_state(&self.adapter_state, self.request.clone(), cursor.cloned())?;
        let dispatch = self.worker.dispatch_fence();
        let live_probe = self
            .live_probe
            .clone()
            .ok_or(GoogleAdsError::ProviderPending)?;
        let observation = self
            .worker
            .read(ReadRequest {
                dispatch,
                scope: self.scope.clone(),
                live_probe,
                capability: ProviderCapabilityKey::new(
                    GOOGLE_ADS_PROVIDER_ID,
                    GOOGLE_ADS_READ_CAPABILITY,
                )
                .map_err(ConnectorError::from)?,
                query_digest: request_digest,
                cursor: cursor
                    .map(|cursor| cursor.sdk_cursor(&self.scope))
                    .transpose()?,
                page_size: 1,
                at,
                budget,
            })
            .map_err(GoogleAdsError::Connector)?;
        let signal = self
            .adapter_state
            .lock()
            .map_err(|_| GoogleAdsError::StateUnavailable)?
            .signals
            .remove(observation.observation_id())
            .ok_or(GoogleAdsError::StateUnavailable)?;
        self.ledger.record(signal.clone());
        Ok(signal)
    }
}

fn bind_page_in_state(
    state: &Arc<Mutex<GoogleAdsAdapterState>>,
    request: GoogleAdsGaqlRequest,
    cursor: Option<GoogleAdsCursor>,
) -> Result<(), GoogleAdsError> {
    request.validate()?;
    let key = (
        request.request_digest(),
        cursor.as_ref().map_or(0, GoogleAdsCursor::sequence),
    );
    let mut state = state.lock().map_err(|_| GoogleAdsError::StateUnavailable)?;
    if state.revoked {
        return Err(GoogleAdsError::Revoked);
    }
    state
        .bound_pages
        .insert(key, BoundGoogleAdsPage { request, cursor });
    Ok(())
}

fn replayed_signal(signal: &GoogleAdsGrowthSignal) -> GoogleAdsGrowthSignal {
    let mut replay = signal.clone();
    replay.replayed = true;
    replay.charged = false;
    replay.usage.cost_class = GoogleAdsCostClass::Replay;
    replay.usage.charged = false;
    replay.usage.request_units = 0;
    replay.usage.attempts = 0;
    replay
}

fn ledger_key(request_digest: &str, sequence: u64) -> String {
    canonical_digest(&[request_digest, &sequence.to_string()])
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAdsWorld {
    PaginatedRows,
    EmptyResult,
    InvalidPageToken,
    QuotaExhausted,
    RetryOnce,
    ReadOnlyViolation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsRequestRecord {
    method: GoogleAdsHttpMethod,
    path: String,
    body_digest: String,
}

impl GoogleAdsRequestRecord {
    pub const fn method(&self) -> GoogleAdsHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }
}

#[derive(Clone, Debug)]
pub struct FakeGoogleAdsTransport {
    scenario: GoogleAdsWorld,
    requests: Vec<GoogleAdsRequestRecord>,
    provider_calls: u64,
    transient_failures_left: u8,
}

impl FakeGoogleAdsTransport {
    pub fn new(scenario: GoogleAdsWorld) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
            provider_calls: 0,
            transient_failures_left: u8::from(scenario == GoogleAdsWorld::RetryOnce),
        }
    }

    pub const fn scenario(&self) -> GoogleAdsWorld {
        self.scenario
    }

    pub fn requests(&self) -> &[GoogleAdsRequestRecord] {
        &self.requests
    }

    pub const fn provider_calls(&self) -> u64 {
        self.provider_calls
    }
}

impl GoogleAdsTransport for FakeGoogleAdsTransport {
    fn execute(
        &mut self,
        request: GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsHttpResponse, GoogleAdsError> {
        self.provider_calls = self.provider_calls.saturating_add(1);
        self.requests.push(GoogleAdsRequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest: request.body_digest()?,
        });
        if self.transient_failures_left > 0 {
            self.transient_failures_left -= 1;
            return GoogleAdsHttpResponse::new(
                503,
                fake_headers("fixture-request-retry"),
                json!({
                    "error": {
                        "code": 503,
                        "status": "UNAVAILABLE",
                        "message": "fixture retry"
                    }
                }),
            );
        }
        let query = request
            .body
            .get("query")
            .and_then(Value::as_str)
            .ok_or(GoogleAdsError::InvalidRequest)?;
        if self.scenario == GoogleAdsWorld::QuotaExhausted {
            return GoogleAdsHttpResponse::new(
                429,
                fake_headers("fixture-request-quota"),
                json!({
                    "error": {
                        "code": 429,
                        "status": "RESOURCE_EXHAUSTED",
                        "message": "fixture quota"
                    }
                }),
            );
        }
        if !is_select_query(query) || self.scenario == GoogleAdsWorld::ReadOnlyViolation {
            return GoogleAdsHttpResponse::new(
                400,
                fake_headers("fixture-request-invalid"),
                json!({
                    "error": {
                        "code": 400,
                        "status": "INVALID_ARGUMENT",
                        "message": "fixture only accepts SELECT"
                    }
                }),
            );
        }
        let page_token = request.body.get("pageToken").and_then(Value::as_str);
        if self.scenario == GoogleAdsWorld::InvalidPageToken && page_token.is_some() {
            return GoogleAdsHttpResponse::new(
                400,
                fake_headers("fixture-request-invalid-page"),
                json!({
                    "error": {
                        "code": 400,
                        "status": "INVALID_ARGUMENT",
                        "message": "invalid page token"
                    }
                }),
            );
        }
        if query == GOOGLE_ADS_PROBE_QUERY {
            return fake_probe_response();
        }
        fake_read_response(self.scenario, page_token)
    }
}

fn fake_headers(request_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("google-ads-request-id".to_owned(), request_id.to_owned()),
        (
            "google-ads-daily-operations-limit".to_owned(),
            "15000".to_owned(),
        ),
    ])
}

fn fake_probe_response() -> Result<GoogleAdsHttpResponse, GoogleAdsError> {
    GoogleAdsHttpResponse::new(
        200,
        fake_headers("fixture-request-probe"),
        json!({
            "results": [{
                "customer": {
                    "resourceName": "customers/1234567890",
                    "id": "1234567890",
                    "descriptiveName": "Fixture account",
                    "currencyCode": "USD",
                    "timeZone": "UTC"
                }
            }],
            "fieldMask": "customer.id,customer.descriptiveName,customer.currencyCode,customer.timeZone"
        }),
    )
}

fn fake_read_response(
    scenario: GoogleAdsWorld,
    page_token: Option<&str>,
) -> Result<GoogleAdsHttpResponse, GoogleAdsError> {
    let second_page = page_token.is_some();
    let results = if scenario == GoogleAdsWorld::EmptyResult {
        Vec::new()
    } else if second_page {
        vec![json!({
            "campaign": {
                "resourceName": "customers/1234567890/campaigns/2",
                "id": "2",
                "name": "Fixture second campaign",
                "status": "ENABLED"
            }
        })]
    } else {
        vec![
            json!({
                "campaign": {
                    "resourceName": "customers/1234567890/campaigns/1",
                    "id": "1",
                    "name": "Fixture campaign",
                    "status": "ENABLED"
                }
            }),
            json!({
                "campaign": {
                    "resourceName": "customers/1234567890/campaigns/3",
                    "id": "3",
                    "name": "Fixture campaign two",
                    "status": "PAUSED"
                }
            }),
        ]
    };
    let next_page_token = if matches!(
        scenario,
        GoogleAdsWorld::PaginatedRows | GoogleAdsWorld::InvalidPageToken
    ) && !second_page
    {
        Some("fixture-page-token-2")
    } else {
        None
    };
    GoogleAdsHttpResponse::new(
        200,
        fake_headers(if second_page {
            "fixture-request-page-2"
        } else {
            "fixture-request-page-1"
        }),
        json!({
            "results": results,
            "fieldMask": "campaign.id,campaign.name,campaign.status",
            "nextPageToken": next_page_token
        }),
    )
}
