//! Google Analytics Data API v1/v1beta property-scoped read reports.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{
    ConnectorDescriptor, ConnectorError, ConnectorScope, ProviderProvenanceClass, ReadObservation,
    SecretReference,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::common::{
    EvidenceClassification, Freshness, ProviderReceiptReference, ReadScope, canonical_digest,
    response_digest,
};

pub const GOOGLE_ANALYTICS_PROVIDER_ID: &str = "google-analytics";
pub const GOOGLE_ANALYTICS_API_BASE_URL: &str = "https://analyticsdata.googleapis.com/";
pub const GOOGLE_ANALYTICS_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/analytics.readonly";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GoogleAnalyticsPropertyId(String);

impl GoogleAnalyticsPropertyId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, GoogleAnalyticsError> {
        let value = value.as_ref().trim();
        let value = value.strip_prefix("properties/").unwrap_or(value);
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(GoogleAnalyticsError::InvalidPropertyId);
        }
        Ok(Self(format!("properties/{value}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AnalyticsFieldName(String);

impl AnalyticsFieldName {
    pub fn new(value: impl Into<String>) -> Result<Self, GoogleAnalyticsError> {
        let value = value.into();
        if value.trim().is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(GoogleAnalyticsError::InvalidFieldName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleAnalyticsAuthReference {
    oauth_reference: SecretReference,
}

impl GoogleAnalyticsAuthReference {
    pub fn new(oauth_reference: SecretReference) -> Result<Self, GoogleAnalyticsError> {
        if oauth_reference.scope().provider_id() != GOOGLE_ANALYTICS_PROVIDER_ID {
            return Err(GoogleAnalyticsError::InvalidSecretScope);
        }
        Ok(Self { oauth_reference })
    }

    pub const fn oauth_reference(&self) -> &SecretReference {
        &self.oauth_reference
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsCursor {
    property: GoogleAnalyticsPropertyId,
    query_digest: String,
    offset: u64,
}

impl AnalyticsCursor {
    pub fn new(
        property: GoogleAnalyticsPropertyId,
        query_digest: impl Into<String>,
        offset: u64,
    ) -> Result<Self, GoogleAnalyticsError> {
        let query_digest = query_digest.into();
        if query_digest.len() != 64 {
            return Err(GoogleAnalyticsError::InvalidCursor);
        }
        Ok(Self {
            property,
            query_digest,
            offset,
        })
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsReportRequest {
    scope: ReadScope,
    property: GoogleAnalyticsPropertyId,
    dimensions: Vec<AnalyticsFieldName>,
    metrics: Vec<AnalyticsFieldName>,
    limit: u64,
    cursor: Option<AnalyticsCursor>,
}

impl AnalyticsReportRequest {
    pub fn new(
        scope: ReadScope,
        property: GoogleAnalyticsPropertyId,
        dimensions: Vec<AnalyticsFieldName>,
        metrics: Vec<AnalyticsFieldName>,
        limit: u64,
        cursor: Option<AnalyticsCursor>,
    ) -> Result<Self, GoogleAnalyticsError> {
        if dimensions.is_empty() || metrics.is_empty() || limit == 0 || limit > 250_000 {
            return Err(GoogleAnalyticsError::InvalidRequest);
        }
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.property != property
                || cursor.query_digest
                    != canonical_digest(&(&scope, &property, &dimensions, &metrics, limit))
        }) {
            return Err(GoogleAnalyticsError::CursorScopeMismatch);
        }
        Ok(Self {
            scope,
            property,
            dimensions,
            metrics,
            limit,
            cursor,
        })
    }

    pub fn request_digest(&self) -> String {
        canonical_digest(self)
    }

    pub const fn scope(&self) -> &ReadScope {
        &self.scope
    }

    fn query_digest(&self) -> String {
        canonical_digest(&(
            &self.scope,
            &self.property,
            &self.dimensions,
            &self.metrics,
            self.limit,
        ))
    }

    fn offset(&self) -> u64 {
        self.cursor.as_ref().map_or(0, AnalyticsCursor::offset)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsQuotaStatus {
    consumed: u64,
    remaining: u64,
}

impl AnalyticsQuotaStatus {
    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsPropertyQuota {
    #[serde(default)]
    tokens_per_day: Option<AnalyticsQuotaStatus>,
    #[serde(default)]
    tokens_per_hour: Option<AnalyticsQuotaStatus>,
    #[serde(default)]
    concurrent_requests: Option<AnalyticsQuotaStatus>,
    #[serde(default)]
    server_errors_per_project_per_hour: Option<AnalyticsQuotaStatus>,
    #[serde(default)]
    potentially_thresholded_requests_per_hour: Option<AnalyticsQuotaStatus>,
    #[serde(default)]
    tokens_per_project_per_hour: Option<AnalyticsQuotaStatus>,
}

impl AnalyticsPropertyQuota {
    pub fn tokens_per_hour(&self) -> Option<&AnalyticsQuotaStatus> {
        self.tokens_per_hour.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsRow {
    dimension_values: Vec<String>,
    metric_values: Vec<String>,
}

impl AnalyticsRow {
    fn from_value(value: &Value) -> Self {
        Self {
            dimension_values: value
                .get("dimensionValues")
                .and_then(Value::as_array)
                .map(|values| values.iter().map(value_string).collect())
                .unwrap_or_default(),
            metric_values: value
                .get("metricValues")
                .and_then(Value::as_array)
                .map(|values| values.iter().map(value_string).collect())
                .unwrap_or_default(),
        }
    }

    pub fn dimension_values(&self) -> &[String] {
        &self.dimension_values
    }

    pub fn metric_values(&self) -> &[String] {
        &self.metric_values
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsReadObservation {
    scope: ReadScope,
    property: GoogleAnalyticsPropertyId,
    row_count: u64,
    rows: Vec<AnalyticsRow>,
    next_cursor: Option<AnalyticsCursor>,
    quota: Option<AnalyticsPropertyQuota>,
    observed_at: DateTime<Utc>,
    freshness: Freshness,
    classification: EvidenceClassification,
    first_party: bool,
    receipt_reference: ProviderReceiptReference,
    replayed: bool,
}

impl AnalyticsReadObservation {
    pub fn rows(&self) -> &[AnalyticsRow] {
        &self.rows
    }

    pub const fn row_count(&self) -> u64 {
        self.row_count
    }

    pub const fn property(&self) -> &GoogleAnalyticsPropertyId {
        &self.property
    }

    pub const fn next_cursor(&self) -> Option<&AnalyticsCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn quota(&self) -> Option<&AnalyticsPropertyQuota> {
        self.quota.as_ref()
    }

    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub const fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    pub const fn receipt_reference(&self) -> &ProviderReceiptReference {
        &self.receipt_reference
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyticsReplayLedger {
    observations: BTreeMap<String, AnalyticsReadObservation>,
}

impl AnalyticsReplayLedger {
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GoogleAnalyticsError {
    #[error("Google Analytics property id is invalid")]
    InvalidPropertyId,
    #[error("Google Analytics field name is invalid")]
    InvalidFieldName,
    #[error("Google Analytics credential scope is invalid")]
    InvalidSecretScope,
    #[error("Google Analytics request is invalid")]
    InvalidRequest,
    #[error("Google Analytics cursor is invalid")]
    InvalidCursor,
    #[error("Google Analytics cursor does not match property or query")]
    CursorScopeMismatch,
    #[error("Google Analytics provider returned an invalid response")]
    MalformedResponse,
    #[error("Google Analytics provider returned HTTP {http_status} and code {provider_code}")]
    ProviderStatus {
        http_status: u16,
        provider_code: String,
    },
    #[error("Google Analytics transport failed")]
    Transport,
}

pub trait GoogleAnalyticsTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: GoogleAnalyticsHttpRequest,
    ) -> Result<GoogleAnalyticsHttpResponse, GoogleAnalyticsError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GoogleAnalyticsHttpMethod {
    Post,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAnalyticsHttpRequest {
    method: GoogleAnalyticsHttpMethod,
    path: String,
    body: Option<Value>,
}

impl GoogleAnalyticsHttpRequest {
    fn new(path: impl Into<String>, body: Option<Value>) -> Self {
        Self {
            method: GoogleAnalyticsHttpMethod::Post,
            path: path.into(),
            body,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> Option<String> {
        self.body.as_ref().map(canonical_digest)
    }
}

impl fmt::Debug for GoogleAnalyticsHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAnalyticsHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("bodyDigest", &self.body_digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAnalyticsHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
}

impl GoogleAnalyticsHttpResponse {
    pub fn new(status: u16, headers: BTreeMap<String, String>, body: Value) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

impl fmt::Debug for GoogleAnalyticsHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAnalyticsHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("bodyDigest", &response_digest(&self.body))
            .finish()
    }
}

pub struct GoogleAnalyticsHttpTransport {
    client: Client,
    base_url: Url,
    access_token: Zeroizing<String>,
}

impl fmt::Debug for GoogleAnalyticsHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAnalyticsHttpTransport")
            .field("base_url", &self.base_url)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl GoogleAnalyticsHttpTransport {
    pub fn new(
        base_url: impl AsRef<str>,
        access_token: impl Into<String>,
    ) -> Result<Self, GoogleAnalyticsError> {
        let base_url =
            Url::parse(base_url.as_ref()).map_err(|_| GoogleAnalyticsError::Transport)?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(GoogleAnalyticsError::Transport);
        }
        Ok(Self {
            client: Client::builder()
                .build()
                .map_err(|_| GoogleAnalyticsError::Transport)?,
            base_url,
            access_token: Zeroizing::new(access_token.into()),
        })
    }

    pub fn production(access_token: impl Into<String>) -> Result<Self, GoogleAnalyticsError> {
        Self::new(GOOGLE_ANALYTICS_API_BASE_URL, access_token)
    }
}

impl GoogleAnalyticsTransport for GoogleAnalyticsHttpTransport {
    fn execute(
        &mut self,
        request: GoogleAnalyticsHttpRequest,
    ) -> Result<GoogleAnalyticsHttpResponse, GoogleAnalyticsError> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| GoogleAnalyticsError::Transport)?;
        let mut builder = self
            .client
            .post(url)
            .bearer_auth(self.access_token.as_str());
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }
        let response = builder
            .send()
            .map_err(|_| GoogleAnalyticsError::Transport)?;
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
        let body = response
            .json::<Value>()
            .map_err(|_| GoogleAnalyticsError::MalformedResponse)?;
        Ok(GoogleAnalyticsHttpResponse::new(status, headers, body))
    }
}

pub struct GoogleAnalyticsClient<T> {
    auth: GoogleAnalyticsAuthReference,
    transport: T,
    replay: AnalyticsReplayLedger,
}

impl<T: GoogleAnalyticsTransport> fmt::Debug for GoogleAnalyticsClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAnalyticsClient")
            .field("auth", &self.auth)
            .field("transport", &self.transport)
            .field("replay", &self.replay)
            .finish()
    }
}

impl<T: GoogleAnalyticsTransport> GoogleAnalyticsClient<T> {
    pub fn new(auth: GoogleAnalyticsAuthReference, transport: T) -> Self {
        Self {
            auth,
            transport,
            replay: AnalyticsReplayLedger::default(),
        }
    }

    pub fn connector_scope(&self) -> &ConnectorScope {
        self.auth.oauth_reference().scope()
    }

    pub fn connector_descriptor() -> Result<ConnectorDescriptor, ConnectorError> {
        crate::sdk::descriptor_for(GOOGLE_ANALYTICS_PROVIDER_ID, "hartevo.google-analytics")
    }

    pub fn sdk_read_observation(
        &self,
        observation: &AnalyticsReadObservation,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, ConnectorError> {
        let descriptor = Self::connector_descriptor()?;
        let request_digest = observation.receipt_reference().request_digest();
        let next_cursor = observation
            .next_cursor()
            .map(|cursor| {
                crate::sdk::cursor(
                    self.auth.oauth_reference().scope(),
                    request_digest,
                    1,
                    &canonical_digest(&cursor.offset()),
                )
            })
            .transpose()?;
        ReadObservation::new(
            format!("read-observation-{request_digest}"),
            self.auth.oauth_reference().scope().clone(),
            crate::sdk::capability(GOOGLE_ANALYTICS_PROVIDER_ID, "analytics.read")?,
            descriptor.identity().clone(),
            request_digest.to_owned(),
            observation.receipt_reference().response_digest().to_owned(),
            observation.receipt_reference().response_digest().to_owned(),
            provenance,
            crate::sdk::freshness(
                observation.freshness().observed_at(),
                observation.freshness().valid_until(),
                observation
                    .quota()
                    .and_then(|quota| quota.tokens_per_hour())
                    .map_or(1, |quota| quota.consumed().saturating_add(1)),
            )?,
            1,
            u32::try_from(observation.rows().len()).unwrap_or(u32::MAX),
            next_cursor,
        )
    }

    pub fn run_report(
        &mut self,
        request: &AnalyticsReportRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<AnalyticsReadObservation, GoogleAnalyticsError> {
        let request_digest = request.request_digest();
        if let Some(cached) = self.replay.observations.get(&request_digest) {
            let mut cached = cached.clone();
            cached.replayed = true;
            return Ok(cached);
        }
        let path = format!("/v1beta/{}:runReport", request.property.as_str());
        let body = json!({
            "dateRanges":[{"startDate":request.scope.window().start().format("%Y-%m-%d").to_string(),"endDate":request.scope.window().end().format("%Y-%m-%d").to_string()}],
            "dimensions": request.dimensions.iter().map(|field| json!({"name":field.as_str()})).collect::<Vec<_>>(),
            "metrics": request.metrics.iter().map(|field| json!({"name":field.as_str()})).collect::<Vec<_>>(),
            "limit": request.limit,
            "offset": request.offset(),
            "returnPropertyQuota": true,
        });
        let response = self
            .transport
            .execute(GoogleAnalyticsHttpRequest::new(path.clone(), Some(body)))?;
        if response.status >= 400 {
            return Err(provider_error(&response));
        }
        let row_count = response
            .body
            .get("rowCount")
            .and_then(Value::as_u64)
            .ok_or(GoogleAnalyticsError::MalformedResponse)?;
        let rows = response
            .body
            .get("rows")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().map(AnalyticsRow::from_value).collect())
            .unwrap_or_default();
        let next_cursor = if request.offset().saturating_add(request.limit) < row_count {
            Some(AnalyticsCursor::new(
                request.property.clone(),
                request.query_digest(),
                request.offset().saturating_add(request.limit),
            )?)
        } else {
            None
        };
        let freshness = Freshness::new(observed_at, observed_at + chrono::Duration::hours(24))
            .map_err(|_| GoogleAnalyticsError::MalformedResponse)?;
        let observation = AnalyticsReadObservation {
            scope: request.scope.clone(),
            property: request.property.clone(),
            row_count,
            rows,
            next_cursor,
            quota: response
                .body
                .get("propertyQuota")
                .cloned()
                .and_then(|quota| serde_json::from_value(quota).ok()),
            observed_at,
            freshness,
            classification: EvidenceClassification::FirstPartyAccount,
            first_party: true,
            receipt_reference: ProviderReceiptReference::new(
                GOOGLE_ANALYTICS_PROVIDER_ID,
                "read",
                &path,
                request_digest.clone(),
                response_digest(&response.body),
                response.headers.get("x-request-id").cloned(),
                None,
            ),
            replayed: false,
        };
        self.replay
            .observations
            .insert(request_digest, observation.clone());
        Ok(observation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleAnalyticsWorldScenario {
    Results,
    EmptyResult,
    PartialPropertyAccess,
    QuotaExhausted,
}

#[derive(Clone, Debug)]
pub struct GoogleAnalyticsRequestRecord {
    path: String,
    body_digest: Option<String>,
}

impl GoogleAnalyticsRequestRecord {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> Option<&str> {
        self.body_digest.as_deref()
    }
}

#[derive(Clone, Debug)]
pub struct FakeGoogleAnalyticsTransport {
    scenario: GoogleAnalyticsWorldScenario,
    requests: Vec<GoogleAnalyticsRequestRecord>,
}

impl FakeGoogleAnalyticsTransport {
    pub fn new(scenario: GoogleAnalyticsWorldScenario) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[GoogleAnalyticsRequestRecord] {
        &self.requests
    }
}

impl GoogleAnalyticsTransport for FakeGoogleAnalyticsTransport {
    fn execute(
        &mut self,
        request: GoogleAnalyticsHttpRequest,
    ) -> Result<GoogleAnalyticsHttpResponse, GoogleAnalyticsError> {
        self.requests.push(GoogleAnalyticsRequestRecord {
            path: request.path.clone(),
            body_digest: request.body_digest(),
        });
        if self.scenario == GoogleAnalyticsWorldScenario::QuotaExhausted {
            return Ok(GoogleAnalyticsHttpResponse::new(
                429,
                BTreeMap::new(),
                json!({"error":{"status":"RESOURCE_EXHAUSTED"}}),
            ));
        }
        if self.scenario == GoogleAnalyticsWorldScenario::PartialPropertyAccess
            && request.path.contains("properties/999999")
        {
            return Ok(GoogleAnalyticsHttpResponse::new(
                403,
                BTreeMap::new(),
                json!({"error":{"status":"PERMISSION_DENIED"}}),
            ));
        }
        let empty = self.scenario == GoogleAnalyticsWorldScenario::EmptyResult;
        let rows = if empty {
            json!([])
        } else {
            json!([{"dimensionValues":[{"value":"2026-08-01"}],"metricValues":[{"value":"42"}]}])
        };
        Ok(GoogleAnalyticsHttpResponse::new(
            200,
            BTreeMap::new(),
            json!({
                "dimensionHeaders":[{"name":"date"}],
                "metricHeaders":[{"name":"activeUsers","type":"TYPE_INTEGER"}],
                "rows":rows,
                "rowCount":if empty {0} else {2},
                "propertyQuota":{"tokensPerDay":{"consumed":10,"remaining":199_990},"tokensPerHour":{"consumed":10,"remaining":39_990},"tokensPerProjectPerHour":{"consumed":10,"remaining":13_990}}
            }),
        ))
    }
}

fn provider_error(response: &GoogleAnalyticsHttpResponse) -> GoogleAnalyticsError {
    GoogleAnalyticsError::ProviderStatus {
        http_status: response.status,
        provider_code: response
            .body
            .get("error")
            .and_then(|error| error.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_owned(),
    }
}

fn value_string(value: &Value) -> String {
    value
        .get("value")
        .and_then(Value::as_str)
        .map_or_else(|| value.to_string(), str::to_owned)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_connector_sdk::ConnectorScope;
    use hartevo_domain_kernel::{ProjectId, TenantId};

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
            MarketCode::new("US").expect("market"),
            LanguageCode::new("en").expect("language"),
            CalendarDateRange::new(
                parse_date("2026-08-01").expect("date"),
                parse_date("2026-08-07").expect("date"),
            )
            .expect("window"),
        )
    }

    fn auth() -> GoogleAnalyticsAuthReference {
        GoogleAnalyticsAuthReference::new(
            SecretReference::new(
                "secret-ref-ga4",
                ConnectorScope::new(
                    "tenant-signal",
                    "project-signal",
                    GOOGLE_ANALYTICS_PROVIDER_ID,
                    "google-account",
                    [GOOGLE_ANALYTICS_READONLY_SCOPE.into()],
                )
                .expect("scope"),
                1,
            )
            .expect("secret"),
        )
        .expect("auth")
    }

    fn request(property: GoogleAnalyticsPropertyId) -> AnalyticsReportRequest {
        AnalyticsReportRequest::new(
            scope(),
            property,
            vec![AnalyticsFieldName::new("date").expect("dimension")],
            vec![AnalyticsFieldName::new("activeUsers").expect("metric")],
            1,
            None,
        )
        .expect("request")
    }

    #[test]
    fn property_ids_are_canonical_and_reports_are_first_party() {
        assert_eq!(
            GoogleAnalyticsPropertyId::new("12345")
                .expect("property")
                .as_str(),
            "properties/12345"
        );
        let mut client = GoogleAnalyticsClient::new(
            auth(),
            FakeGoogleAnalyticsTransport::new(GoogleAnalyticsWorldScenario::Results),
        );
        let observation = client
            .run_report(
                &request(GoogleAnalyticsPropertyId::new("12345").expect("property")),
                now(),
            )
            .expect("report");
        assert!(observation.first_party());
        assert_eq!(
            observation.classification(),
            EvidenceClassification::FirstPartyAccount
        );
        assert_eq!(observation.row_count(), 2);
        assert_eq!(observation.rows()[0].metric_values(), &["42"]);
        assert_eq!(
            observation
                .quota()
                .expect("quota")
                .tokens_per_hour()
                .expect("hour")
                .remaining(),
            39_990
        );
    }

    #[test]
    fn offset_cursor_is_property_and_query_scoped_and_replay_is_free() {
        let property = GoogleAnalyticsPropertyId::new("12345").expect("property");
        let mut client = GoogleAnalyticsClient::new(
            auth(),
            FakeGoogleAnalyticsTransport::new(GoogleAnalyticsWorldScenario::Results),
        );
        let first_request = request(property.clone());
        let first = client.run_report(&first_request, now()).expect("first");
        let cursor = first.next_cursor().cloned().expect("cursor");
        let next_request = AnalyticsReportRequest::new(
            scope(),
            property.clone(),
            vec![AnalyticsFieldName::new("date").expect("dimension")],
            vec![AnalyticsFieldName::new("activeUsers").expect("metric")],
            1,
            Some(cursor),
        )
        .expect("next");
        let next = client
            .run_report(&next_request, now())
            .expect("next report");
        assert_eq!(next.rows().len(), 1);
        assert!(
            client
                .run_report(&first_request, now())
                .expect("replay")
                .replayed()
        );
        assert_eq!(client.replay.observation_count(), 2);
    }

    #[test]
    fn empty_partial_and_quota_exhaustion_worlds_remain_distinct() {
        let property = GoogleAnalyticsPropertyId::new("12345").expect("property");
        let mut empty = GoogleAnalyticsClient::new(
            auth(),
            FakeGoogleAnalyticsTransport::new(GoogleAnalyticsWorldScenario::EmptyResult),
        );
        assert!(
            empty
                .run_report(&request(property.clone()), now())
                .expect("empty")
                .rows()
                .is_empty()
        );
        let mut partial = GoogleAnalyticsClient::new(
            auth(),
            FakeGoogleAnalyticsTransport::new(GoogleAnalyticsWorldScenario::PartialPropertyAccess),
        );
        assert!(
            matches!(partial.run_report(&request(GoogleAnalyticsPropertyId::new("999999").expect("property")), now()), Err(GoogleAnalyticsError::ProviderStatus { http_status: 403, provider_code }) if provider_code == "PERMISSION_DENIED")
        );
        let mut quota = GoogleAnalyticsClient::new(
            auth(),
            FakeGoogleAnalyticsTransport::new(GoogleAnalyticsWorldScenario::QuotaExhausted),
        );
        assert!(
            matches!(quota.run_report(&request(property), now()), Err(GoogleAnalyticsError::ProviderStatus { http_status: 429, provider_code }) if provider_code == "RESOURCE_EXHAUSTED")
        );
    }
}
