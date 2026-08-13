//! Google Ads API v25 read-only account probe and GAQL reporting seam.

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

pub const GOOGLE_ADS_PROVIDER_ID: &str = "google-ads";
pub const GOOGLE_ADS_API_VERSION: &str = "v25";
pub const GOOGLE_ADS_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/adwords";
pub const GOOGLE_ADS_API_BASE_URL: &str = "https://googleads.googleapis.com/";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GoogleAdsCustomerId(String);

impl GoogleAdsCustomerId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, GoogleAdsError> {
        let normalized = value.as_ref().trim().replace('-', "");
        if !(1..=20).contains(&normalized.len())
            || !normalized.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(GoogleAdsError::InvalidCustomerId);
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn resource_name(&self) -> String {
        format!("customers/{}", self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ReadOnlyGaql(String);

impl ReadOnlyGaql {
    pub fn new(value: impl Into<String>) -> Result<Self, GoogleAdsError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.contains(';') {
            return Err(GoogleAdsError::InvalidGaql);
        }
        let tokens = trimmed
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .filter(|token| !token.is_empty())
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>();
        if tokens.first().map(String::as_str) != Some("SELECT")
            || !tokens.iter().any(|token| token == "FROM")
            || tokens.iter().any(|token| {
                matches!(
                    token.as_str(),
                    "MUTATE" | "CREATE" | "UPDATE" | "REMOVE" | "INSERT" | "DELETE" | "UPLOAD"
                )
            })
        {
            return Err(GoogleAdsError::InvalidGaql);
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleAdsAuthReferences {
    oauth_access_reference: SecretReference,
    developer_token_reference: SecretReference,
}

impl GoogleAdsAuthReferences {
    pub fn new(
        oauth_access_reference: SecretReference,
        developer_token_reference: SecretReference,
    ) -> Result<Self, GoogleAdsError> {
        if oauth_access_reference.scope().provider_id() != GOOGLE_ADS_PROVIDER_ID
            || developer_token_reference.scope().provider_id() != GOOGLE_ADS_PROVIDER_ID
            || oauth_access_reference.scope().tenant_id()
                != developer_token_reference.scope().tenant_id()
            || oauth_access_reference.scope().project_id()
                != developer_token_reference.scope().project_id()
        {
            return Err(GoogleAdsError::InvalidSecretScope);
        }
        Ok(Self {
            oauth_access_reference,
            developer_token_reference,
        })
    }

    pub const fn oauth_access_reference(&self) -> &SecretReference {
        &self.oauth_access_reference
    }

    pub const fn developer_token_reference(&self) -> &SecretReference {
        &self.developer_token_reference
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsPageCursor {
    customer_id: GoogleAdsCustomerId,
    query_digest: String,
    page_token: String,
}

impl GoogleAdsPageCursor {
    pub fn new(
        customer_id: GoogleAdsCustomerId,
        query_digest: impl Into<String>,
        page_token: impl Into<String>,
    ) -> Result<Self, GoogleAdsError> {
        let query_digest = query_digest.into();
        let page_token = page_token.into();
        if query_digest.len() != 64 || page_token.trim().is_empty() {
            return Err(GoogleAdsError::InvalidCursor);
        }
        Ok(Self {
            customer_id,
            query_digest,
            page_token,
        })
    }

    pub fn page_token(&self) -> &str {
        &self.page_token
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsReadRequest {
    scope: ReadScope,
    customer_id: GoogleAdsCustomerId,
    query: ReadOnlyGaql,
    page_size: u32,
    cursor: Option<GoogleAdsPageCursor>,
}

impl GoogleAdsReadRequest {
    pub fn new(
        scope: ReadScope,
        customer_id: GoogleAdsCustomerId,
        query: ReadOnlyGaql,
        page_size: u32,
        cursor: Option<GoogleAdsPageCursor>,
    ) -> Result<Self, GoogleAdsError> {
        if page_size == 0 || page_size > 10_000 {
            return Err(GoogleAdsError::InvalidRequest);
        }
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.customer_id != customer_id || cursor.query_digest != query.digest()
        }) {
            return Err(GoogleAdsError::CursorScopeMismatch);
        }
        Ok(Self {
            scope,
            customer_id,
            query,
            page_size,
            cursor,
        })
    }

    pub fn request_digest(&self) -> String {
        canonical_digest(self)
    }

    pub const fn scope(&self) -> &ReadScope {
        &self.scope
    }

    pub fn query_digest(&self) -> String {
        self.query.digest()
    }

    pub const fn cursor(&self) -> Option<&GoogleAdsPageCursor> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsRow {
    resource_name: Option<String>,
    fields: BTreeMap<String, String>,
}

impl GoogleAdsRow {
    fn from_value(value: &Value) -> Self {
        let resource_name = value
            .get("customer")
            .and_then(Value::as_object)
            .and_then(|customer| customer.get("resourceName"))
            .and_then(Value::as_str)
            .or_else(|| value.get("resourceName").and_then(Value::as_str))
            .map(str::to_owned);
        let fields = value
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(key, _)| key.as_str() != "resourceName")
                    .map(|(key, value)| (key.clone(), scalar_to_string(value)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            resource_name,
            fields,
        }
    }

    pub fn resource_name(&self) -> Option<&str> {
        self.resource_name.as_deref()
    }

    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAdsAccessLevel {
    Test,
    Explorer,
    Basic,
    Standard,
}

impl GoogleAdsAccessLevel {
    const fn daily_limit(&self) -> Option<u64> {
        match self {
            Self::Test | Self::Basic => Some(15_000),
            Self::Explorer => Some(2_880),
            Self::Standard => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsQuotaSnapshot {
    access_level: GoogleAdsAccessLevel,
    operations_used: u64,
    daily_limit: Option<u64>,
    last_request_charged_operations: u64,
    replayed_requests: u64,
}

impl GoogleAdsQuotaSnapshot {
    pub const fn operations_used(&self) -> u64 {
        self.operations_used
    }

    pub const fn daily_limit(&self) -> Option<u64> {
        self.daily_limit
    }

    pub const fn last_request_charged_operations(&self) -> u64 {
        self.last_request_charged_operations
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsQuotaLedger {
    access_level: GoogleAdsAccessLevel,
    operations_used: u64,
    replayed_requests: u64,
    last_request_charged_operations: u64,
}

impl GoogleAdsQuotaLedger {
    pub fn new(
        access_level: GoogleAdsAccessLevel,
        operations_used: u64,
    ) -> Result<Self, GoogleAdsError> {
        if access_level
            .daily_limit()
            .is_some_and(|limit| operations_used > limit)
        {
            return Err(GoogleAdsError::QuotaExhausted);
        }
        Ok(Self {
            access_level,
            operations_used,
            replayed_requests: 0,
            last_request_charged_operations: 0,
        })
    }

    pub fn snapshot(&self) -> GoogleAdsQuotaSnapshot {
        GoogleAdsQuotaSnapshot {
            access_level: self.access_level.clone(),
            operations_used: self.operations_used,
            daily_limit: self.access_level.daily_limit(),
            last_request_charged_operations: self.last_request_charged_operations,
            replayed_requests: self.replayed_requests,
        }
    }

    fn ensure_capacity(&self) -> Result<(), GoogleAdsError> {
        if self
            .access_level
            .daily_limit()
            .is_some_and(|limit| self.operations_used >= limit)
        {
            return Err(GoogleAdsError::QuotaExhausted);
        }
        Ok(())
    }

    fn record_charged(&mut self) {
        self.operations_used = self.operations_used.saturating_add(1);
        self.last_request_charged_operations = 1;
    }

    fn record_free_page(&mut self) {
        self.last_request_charged_operations = 0;
    }

    fn record_replay(&mut self) {
        self.replayed_requests = self.replayed_requests.saturating_add(1);
        self.last_request_charged_operations = 0;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsAccountProbe {
    accounts: Vec<GoogleAdsCustomerId>,
    observed_at: DateTime<Utc>,
    freshness: Freshness,
    classification: EvidenceClassification,
    first_party: bool,
    receipt_reference: ProviderReceiptReference,
    quota: GoogleAdsQuotaSnapshot,
}

impl GoogleAdsAccountProbe {
    pub fn accounts(&self) -> &[GoogleAdsCustomerId] {
        &self.accounts
    }

    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn quota(&self) -> &GoogleAdsQuotaSnapshot {
        &self.quota
    }

    pub const fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    pub const fn receipt_reference(&self) -> &ProviderReceiptReference {
        &self.receipt_reference
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsReadObservation {
    scope: ReadScope,
    customer_id: GoogleAdsCustomerId,
    query_digest: String,
    rows: Vec<GoogleAdsRow>,
    next_cursor: Option<GoogleAdsPageCursor>,
    observed_at: DateTime<Utc>,
    freshness: Freshness,
    classification: EvidenceClassification,
    first_party: bool,
    receipt_reference: ProviderReceiptReference,
    quota: GoogleAdsQuotaSnapshot,
    replayed: bool,
}

impl GoogleAdsReadObservation {
    pub fn rows(&self) -> &[GoogleAdsRow] {
        &self.rows
    }

    pub const fn next_cursor(&self) -> Option<&GoogleAdsPageCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn quota(&self) -> &GoogleAdsQuotaSnapshot {
        &self.quota
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn request_digest(&self) -> &str {
        self.receipt_reference.request_digest()
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
pub struct GoogleAdsReplayLedger {
    observations: BTreeMap<String, GoogleAdsReadObservation>,
}

impl GoogleAdsReplayLedger {
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GoogleAdsError {
    #[error("Google Ads customer id is invalid")]
    InvalidCustomerId,
    #[error("Google Ads GAQL is not a read-only SELECT")]
    InvalidGaql,
    #[error("Google Ads request is invalid")]
    InvalidRequest,
    #[error("Google Ads credential scope is invalid")]
    InvalidSecretScope,
    #[error("Google Ads cursor is invalid")]
    InvalidCursor,
    #[error("Google Ads cursor does not match customer or query")]
    CursorScopeMismatch,
    #[error("Google Ads daily operation quota is exhausted")]
    QuotaExhausted,
    #[error("Google Ads page token is invalid")]
    InvalidPageToken,
    #[error("Google Ads provider returned an invalid response")]
    MalformedResponse,
    #[error("Google Ads provider returned HTTP {http_status} and code {provider_code}")]
    ProviderStatus {
        http_status: u16,
        provider_code: String,
    },
    #[error("Google Ads transport failed")]
    Transport,
}

pub trait GoogleAdsTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsHttpResponse, GoogleAdsError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GoogleAdsHttpMethod {
    Get,
    Post,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsHttpRequest {
    method: GoogleAdsHttpMethod,
    path: String,
    body: Option<Value>,
}

impl GoogleAdsHttpRequest {
    fn new(method: GoogleAdsHttpMethod, path: impl Into<String>, body: Option<Value>) -> Self {
        Self {
            method,
            path: path.into(),
            body,
        }
    }

    pub fn method(&self) -> GoogleAdsHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> Option<String> {
        self.body.as_ref().map(canonical_digest)
    }
}

impl fmt::Debug for GoogleAdsHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("bodyDigest", &self.body_digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
}

impl GoogleAdsHttpResponse {
    pub fn new(status: u16, headers: BTreeMap<String, String>, body: Value) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

impl fmt::Debug for GoogleAdsHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("bodyDigest", &response_digest(&self.body))
            .finish()
    }
}

pub struct GoogleAdsHttpTransport {
    client: Client,
    base_url: Url,
    access_token: Zeroizing<String>,
    developer_token: Zeroizing<String>,
    login_customer_id: Option<GoogleAdsCustomerId>,
}

impl fmt::Debug for GoogleAdsHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsHttpTransport")
            .field("base_url", &self.base_url)
            .field("login_customer_id", &self.login_customer_id)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl GoogleAdsHttpTransport {
    pub fn new(
        base_url: impl AsRef<str>,
        access_token: impl Into<String>,
        developer_token: impl Into<String>,
        login_customer_id: Option<GoogleAdsCustomerId>,
    ) -> Result<Self, GoogleAdsError> {
        let base_url = Url::parse(base_url.as_ref()).map_err(|_| GoogleAdsError::Transport)?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(GoogleAdsError::Transport);
        }
        Ok(Self {
            client: Client::builder()
                .build()
                .map_err(|_| GoogleAdsError::Transport)?,
            base_url,
            access_token: Zeroizing::new(access_token.into()),
            developer_token: Zeroizing::new(developer_token.into()),
            login_customer_id,
        })
    }

    pub fn production(
        access_token: impl Into<String>,
        developer_token: impl Into<String>,
        login_customer_id: Option<GoogleAdsCustomerId>,
    ) -> Result<Self, GoogleAdsError> {
        Self::new(
            GOOGLE_ADS_API_BASE_URL,
            access_token,
            developer_token,
            login_customer_id,
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
            .map_err(|_| GoogleAdsError::Transport)?;
        let method = match request.method {
            GoogleAdsHttpMethod::Get => reqwest::Method::GET,
            GoogleAdsHttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self
            .client
            .request(method, url)
            .bearer_auth(self.access_token.as_str())
            .header("developer-token", self.developer_token.as_str());
        if let Some(login_customer_id) = &self.login_customer_id {
            builder = builder.header("login-customer-id", login_customer_id.as_str());
        }
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }
        let response = builder.send().map_err(|_| GoogleAdsError::Transport)?;
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
            .map_err(|_| GoogleAdsError::MalformedResponse)?;
        Ok(GoogleAdsHttpResponse::new(status, headers, body))
    }
}

pub struct GoogleAdsClient<T> {
    auth: GoogleAdsAuthReferences,
    transport: T,
    quota: GoogleAdsQuotaLedger,
    replay: GoogleAdsReplayLedger,
}

impl<T: GoogleAdsTransport> fmt::Debug for GoogleAdsClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsClient")
            .field("auth", &self.auth)
            .field("transport", &self.transport)
            .field("quota", &self.quota)
            .field("replay", &self.replay)
            .finish()
    }
}

impl<T: GoogleAdsTransport> GoogleAdsClient<T> {
    pub fn new(auth: GoogleAdsAuthReferences, transport: T, quota: GoogleAdsQuotaLedger) -> Self {
        Self {
            auth,
            transport,
            quota,
            replay: GoogleAdsReplayLedger::default(),
        }
    }

    pub const fn auth(&self) -> &GoogleAdsAuthReferences {
        &self.auth
    }

    pub fn connector_descriptor() -> Result<ConnectorDescriptor, ConnectorError> {
        crate::sdk::descriptor_for(GOOGLE_ADS_PROVIDER_ID, "hartevo.google-ads")
    }

    pub fn sdk_read_observation(
        &self,
        observation: &GoogleAdsReadObservation,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, ConnectorError> {
        let descriptor = Self::connector_descriptor()?;
        let request_digest = observation.request_digest();
        let next_cursor = observation
            .next_cursor()
            .map(|cursor| {
                crate::sdk::cursor(
                    self.auth.oauth_access_reference().scope(),
                    request_digest,
                    1,
                    &canonical_digest(&cursor.page_token()),
                )
            })
            .transpose()?;
        ReadObservation::new(
            format!("read-observation-{request_digest}"),
            self.auth.oauth_access_reference().scope().clone(),
            crate::sdk::capability(GOOGLE_ADS_PROVIDER_ID, "ads.read")?,
            descriptor.identity().clone(),
            request_digest.to_owned(),
            observation.receipt_reference().response_digest().to_owned(),
            observation.receipt_reference().response_digest().to_owned(),
            provenance,
            crate::sdk::freshness(
                observation.freshness().observed_at(),
                observation.freshness().valid_until(),
                observation.quota().operations_used().saturating_add(1),
            )?,
            1,
            u32::try_from(observation.rows().len()).unwrap_or(u32::MAX),
            next_cursor,
        )
    }

    pub fn probe_accounts(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<GoogleAdsAccountProbe, GoogleAdsError> {
        self.quota.ensure_capacity()?;
        let path = format!("/{GOOGLE_ADS_API_VERSION}/customers:listAccessibleCustomers");
        let response = self.transport.execute(GoogleAdsHttpRequest::new(
            GoogleAdsHttpMethod::Get,
            path.clone(),
            None,
        ))?;
        if response.status >= 400 {
            self.quota.record_charged();
            return Err(provider_error(&response));
        }
        self.quota.record_charged();
        let names = response
            .body
            .get("resourceNames")
            .and_then(Value::as_array)
            .ok_or(GoogleAdsError::MalformedResponse)?;
        let accounts = names
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|name| name.strip_prefix("customers/"))
            .map(GoogleAdsCustomerId::new)
            .collect::<Result<Vec<_>, _>>()?;
        let request_id = response.headers.get("request-id").cloned();
        let digest = response_digest(&response.body);
        let freshness = Freshness::new(observed_at, observed_at + chrono::Duration::minutes(2))
            .map_err(|_| GoogleAdsError::MalformedResponse)?;
        Ok(GoogleAdsAccountProbe {
            accounts,
            observed_at,
            freshness,
            classification: EvidenceClassification::FirstPartyAccount,
            first_party: true,
            receipt_reference: ProviderReceiptReference::new(
                GOOGLE_ADS_PROVIDER_ID,
                "probe",
                &path,
                "account-probe",
                digest,
                request_id,
                None,
            ),
            quota: self.quota.snapshot(),
        })
    }

    pub fn read_gaql(
        &mut self,
        request: &GoogleAdsReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<GoogleAdsReadObservation, GoogleAdsError> {
        let request_digest = request.request_digest();
        if let Some(cached) = self.replay.observations.get(&request_digest) {
            self.quota.record_replay();
            let mut cached = cached.clone();
            cached.replayed = true;
            cached.quota = self.quota.snapshot();
            return Ok(cached);
        }
        if request.cursor.is_none() {
            self.quota.ensure_capacity()?;
        }
        let path = format!(
            "/{GOOGLE_ADS_API_VERSION}/customers/{}/googleAds:search",
            request.customer_id.as_str()
        );
        let mut body = json!({
            "query": request.query.as_str(),
            "pageSize": request.page_size,
        });
        if let Some(cursor) = &request.cursor {
            body["pageToken"] = Value::String(cursor.page_token.clone());
        }
        let response = self.transport.execute(GoogleAdsHttpRequest::new(
            GoogleAdsHttpMethod::Post,
            path.clone(),
            Some(body),
        ))?;
        if response.status >= 400 {
            self.quota.record_charged();
            if response.body.to_string().contains("INVALID_PAGE_TOKEN") {
                return Err(GoogleAdsError::InvalidPageToken);
            }
            return Err(provider_error(&response));
        }
        if request.cursor.is_none() {
            self.quota.record_charged();
        } else {
            self.quota.record_free_page();
        }
        let rows = response
            .body
            .get("results")
            .and_then(Value::as_array)
            .ok_or(GoogleAdsError::MalformedResponse)?
            .iter()
            .map(GoogleAdsRow::from_value)
            .collect::<Vec<_>>();
        let next_cursor = response
            .body
            .get("nextPageToken")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(|token| {
                GoogleAdsPageCursor::new(
                    request.customer_id.clone(),
                    request.query.digest(),
                    token.to_owned(),
                )
            })
            .transpose()?;
        let freshness = Freshness::new(observed_at, observed_at + chrono::Duration::minutes(2))
            .map_err(|_| GoogleAdsError::MalformedResponse)?;
        let observation = GoogleAdsReadObservation {
            scope: request.scope.clone(),
            customer_id: request.customer_id.clone(),
            query_digest: request.query.digest(),
            rows,
            next_cursor,
            observed_at,
            freshness,
            classification: EvidenceClassification::FirstPartyAccount,
            first_party: true,
            receipt_reference: ProviderReceiptReference::new(
                GOOGLE_ADS_PROVIDER_ID,
                "read",
                &path,
                request_digest.clone(),
                response_digest(&response.body),
                response.headers.get("request-id").cloned(),
                None,
            ),
            quota: self.quota.snapshot(),
            replayed: false,
        };
        self.replay
            .observations
            .insert(request_digest, observation.clone());
        Ok(observation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleAdsWorldScenario {
    Accounts,
    EmptyResult,
    InvalidPageToken,
    QuotaExhausted,
}

#[derive(Clone, Debug)]
pub struct GoogleAdsRequestRecord {
    method: GoogleAdsHttpMethod,
    path: String,
    body_digest: Option<String>,
}

impl GoogleAdsRequestRecord {
    pub const fn method(&self) -> GoogleAdsHttpMethod {
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
pub struct FakeGoogleAdsTransport {
    scenario: GoogleAdsWorldScenario,
    requests: Vec<GoogleAdsRequestRecord>,
}

impl FakeGoogleAdsTransport {
    pub fn new(scenario: GoogleAdsWorldScenario) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[GoogleAdsRequestRecord] {
        &self.requests
    }
}

impl GoogleAdsTransport for FakeGoogleAdsTransport {
    fn execute(
        &mut self,
        request: GoogleAdsHttpRequest,
    ) -> Result<GoogleAdsHttpResponse, GoogleAdsError> {
        self.requests.push(GoogleAdsRequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest: request.body_digest(),
        });
        let headers = BTreeMap::from([("request-id".into(), "fake-request-1".into())]);
        if self.scenario == GoogleAdsWorldScenario::QuotaExhausted {
            return Ok(GoogleAdsHttpResponse::new(
                429,
                headers,
                json!({"error":{"status":"RESOURCE_EXHAUSTED"}}),
            ));
        }
        if self.scenario == GoogleAdsWorldScenario::InvalidPageToken
            && request
                .body
                .as_ref()
                .is_some_and(|body| body.get("pageToken").is_some())
        {
            return Ok(GoogleAdsHttpResponse::new(
                400,
                headers,
                json!({"error":{"status":"INVALID_PAGE_TOKEN"}}),
            ));
        }
        if request.path.ends_with("listAccessibleCustomers") {
            return Ok(GoogleAdsHttpResponse::new(
                200,
                headers,
                json!({"resourceNames":["customers/1234567890"]}),
            ));
        }
        let results = if self.scenario == GoogleAdsWorldScenario::EmptyResult {
            json!([])
        } else {
            json!([{"customer":{"resourceName":"customers/1234567890","descriptiveName":"Fixture account"},"metrics":{"clicks":"7"}}])
        };
        Ok(GoogleAdsHttpResponse::new(
            200,
            headers,
            json!({"results":results,"nextPageToken":"fixture-next-page"}),
        ))
    }
}

fn provider_error(response: &GoogleAdsHttpResponse) -> GoogleAdsError {
    let provider_code = response
        .body
        .get("error")
        .and_then(|error| error.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_owned();
    GoogleAdsError::ProviderStatus {
        http_status: response.status,
        provider_code,
    }
}

fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn google_ads_scope(reference: &SecretReference) -> Result<&ConnectorScope, GoogleAdsError> {
    if reference.scope().provider_id() != GOOGLE_ADS_PROVIDER_ID {
        return Err(GoogleAdsError::InvalidSecretScope);
    }
    Ok(reference.scope())
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

    fn secret(reference_id: &str, scope_name: &str) -> SecretReference {
        SecretReference::new(
            reference_id,
            ConnectorScope::new(
                "tenant-signal",
                "project-signal",
                GOOGLE_ADS_PROVIDER_ID,
                "ads-account",
                [scope_name.to_owned()],
            )
            .expect("scope"),
            1,
        )
        .expect("secret")
    }

    fn auth() -> GoogleAdsAuthReferences {
        GoogleAdsAuthReferences::new(
            secret("secret-ref-ads-oauth", GOOGLE_ADS_OAUTH_SCOPE),
            secret("secret-ref-ads-developer", "developer-token"),
        )
        .expect("auth")
    }

    #[test]
    fn account_probe_is_first_party_and_normalizes_customer_resource_names() {
        let transport = FakeGoogleAdsTransport::new(GoogleAdsWorldScenario::Accounts);
        let mut client = GoogleAdsClient::new(
            auth(),
            transport,
            GoogleAdsQuotaLedger::new(GoogleAdsAccessLevel::Basic, 0).expect("quota"),
        );
        let probe = client.probe_accounts(now()).expect("probe");
        assert!(probe.first_party());
        assert_eq!(
            probe.classification(),
            EvidenceClassification::FirstPartyAccount
        );
        assert_eq!(probe.accounts()[0].as_str(), "1234567890");
        assert_eq!(probe.quota().operations_used(), 1);
    }

    #[test]
    fn gaql_boundary_rejects_mutations_and_accepts_select_only() {
        assert!(ReadOnlyGaql::new("SELECT campaign.id FROM campaign").is_ok());
        for query in [
            "UPDATE campaign SET name = 'bad'",
            "SELECT campaign.id FROM campaign; DELETE campaign",
            "MUTATE campaign",
        ] {
            assert_eq!(ReadOnlyGaql::new(query), Err(GoogleAdsError::InvalidGaql));
        }
    }

    #[test]
    fn valid_pagination_is_free_and_replay_does_not_charge_again() {
        let transport = FakeGoogleAdsTransport::new(GoogleAdsWorldScenario::Accounts);
        let mut client = GoogleAdsClient::new(
            auth(),
            transport,
            GoogleAdsQuotaLedger::new(GoogleAdsAccessLevel::Basic, 0).expect("quota"),
        );
        let customer = GoogleAdsCustomerId::new("123-456-7890").expect("customer");
        let query = ReadOnlyGaql::new("SELECT customer.id FROM customer").expect("query");
        let request =
            GoogleAdsReadRequest::new(scope(), customer.clone(), query.clone(), 100, None)
                .expect("request");
        let first = client.read_gaql(&request, now()).expect("read");
        assert_eq!(first.quota().last_request_charged_operations(), 1);
        let cursor = first.next_cursor().cloned().expect("cursor");
        let next =
            GoogleAdsReadRequest::new(scope(), customer, query, 100, Some(cursor)).expect("next");
        let second = client.read_gaql(&next, now()).expect("page");
        assert_eq!(second.quota().last_request_charged_operations(), 0);
        let replay = client.read_gaql(&request, now()).expect("replay");
        assert!(replay.replayed());
        assert_eq!(replay.quota().last_request_charged_operations(), 0);
        assert_eq!(client.replay.observation_count(), 2);
    }

    #[test]
    fn invalid_page_token_is_a_charged_failure_and_quota_exhaustion_fails_closed() {
        let transport = FakeGoogleAdsTransport::new(GoogleAdsWorldScenario::InvalidPageToken);
        let mut client = GoogleAdsClient::new(
            auth(),
            transport,
            GoogleAdsQuotaLedger::new(GoogleAdsAccessLevel::Basic, 14_999).expect("quota"),
        );
        let customer = GoogleAdsCustomerId::new("1234567890").expect("customer");
        let query = ReadOnlyGaql::new("SELECT customer.id FROM customer").expect("query");
        let cursor = GoogleAdsPageCursor::new(customer.clone(), query.digest(), "bad-token")
            .expect("cursor");
        let request = GoogleAdsReadRequest::new(scope(), customer, query, 100, Some(cursor))
            .expect("request");
        assert_eq!(
            client.read_gaql(&request, now()),
            Err(GoogleAdsError::InvalidPageToken)
        );
        assert_eq!(client.quota.snapshot().operations_used(), 15_000);
        assert_eq!(
            client.read_gaql(
                &GoogleAdsReadRequest::new(
                    scope(),
                    GoogleAdsCustomerId::new("1234567890").expect("customer"),
                    ReadOnlyGaql::new("SELECT customer.id FROM customer").expect("query"),
                    100,
                    None
                )
                .expect("request"),
                now()
            ),
            Err(GoogleAdsError::QuotaExhausted)
        );
    }

    #[test]
    fn fake_quota_exhaustion_is_provider_status_not_success() {
        let transport = FakeGoogleAdsTransport::new(GoogleAdsWorldScenario::QuotaExhausted);
        let mut client = GoogleAdsClient::new(
            auth(),
            transport,
            GoogleAdsQuotaLedger::new(GoogleAdsAccessLevel::Basic, 0).expect("quota"),
        );
        assert!(matches!(
            client.probe_accounts(now()),
            Err(GoogleAdsError::ProviderStatus { .. })
        ));
    }
}
