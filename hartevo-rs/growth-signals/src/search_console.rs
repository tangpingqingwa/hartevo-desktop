//! Google Search Console OAuth, property discovery, and Search Analytics reads.

use std::{collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{
    ConnectorDescriptor, ConnectorError, ConnectorScope, ProviderProvenanceClass, ReadObservation,
    SecretReference,
};
use reqwest::blocking::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::common::{
    EvidenceClassification, Freshness, ProviderReceiptReference, ReadScope, canonical_digest,
    response_digest,
};

pub const GOOGLE_SEARCH_CONSOLE_PROVIDER_ID: &str = "google-search-console";
pub const GOOGLE_SEARCH_CONSOLE_API_BASE_URL: &str = "https://www.googleapis.com/";
pub const GOOGLE_SEARCH_CONSOLE_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/webmasters.readonly";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SearchConsoleSiteId(String);

impl SearchConsoleSiteId {
    pub fn new(value: impl Into<String>) -> Result<Self, SearchConsoleError> {
        let value = value.into();
        let trimmed = value.trim();
        if let Some(domain) = trimmed.strip_prefix("sc-domain:") {
            if !valid_domain(domain) {
                return Err(SearchConsoleError::InvalidSiteId);
            }
            return Ok(Self(format!("sc-domain:{}", domain.to_ascii_lowercase())));
        }
        let url = Url::parse(trimmed).map_err(|_| SearchConsoleError::InvalidSiteId)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.username() != ""
            || url.password().is_some()
        {
            return Err(SearchConsoleError::InvalidSiteId);
        }
        let host = url.host_str().expect("host checked").to_ascii_lowercase();
        let mut canonical = format!("{}://{}", url.scheme().to_ascii_lowercase(), host);
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        canonical.push_str(path);
        if !canonical.ends_with('/') {
            canonical.push('/');
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn encoded(&self) -> String {
        percent_encode(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchConsolePermissionLevel {
    SiteOwner,
    SiteFullUser,
    SiteRestrictedUser,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleSite {
    site_id: SearchConsoleSiteId,
    permission_level: SearchConsolePermissionLevel,
}

impl SearchConsoleSite {
    pub fn site_id(&self) -> &SearchConsoleSiteId {
        &self.site_id
    }

    pub const fn permission_level(&self) -> &SearchConsolePermissionLevel {
        &self.permission_level
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchConsoleDimension {
    Query,
    Page,
    Country,
    Device,
    Date,
    SearchAppearance,
}

impl SearchConsoleDimension {
    const fn as_api_name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Page => "page",
            Self::Country => "country",
            Self::Device => "device",
            Self::Date => "date",
            Self::SearchAppearance => "searchAppearance",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleCursor {
    site_id: SearchConsoleSiteId,
    query_digest: String,
    start_row: u32,
}

impl SearchConsoleCursor {
    pub fn new(
        site_id: SearchConsoleSiteId,
        query_digest: impl Into<String>,
        start_row: u32,
    ) -> Result<Self, SearchConsoleError> {
        let query_digest = query_digest.into();
        if query_digest.len() != 64 {
            return Err(SearchConsoleError::InvalidCursor);
        }
        Ok(Self {
            site_id,
            query_digest,
            start_row,
        })
    }

    pub const fn start_row(&self) -> u32 {
        self.start_row
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleQueryRequest {
    scope: ReadScope,
    site_id: SearchConsoleSiteId,
    dimensions: Vec<SearchConsoleDimension>,
    row_limit: u32,
    cursor: Option<SearchConsoleCursor>,
}

impl SearchConsoleQueryRequest {
    pub fn new(
        scope: ReadScope,
        site_id: SearchConsoleSiteId,
        dimensions: Vec<SearchConsoleDimension>,
        row_limit: u32,
        cursor: Option<SearchConsoleCursor>,
    ) -> Result<Self, SearchConsoleError> {
        if dimensions.is_empty() || row_limit == 0 || row_limit > 25_000 {
            return Err(SearchConsoleError::InvalidRequest);
        }
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.site_id != site_id
                || cursor.query_digest
                    != canonical_digest(&(&scope, &site_id, &dimensions, row_limit))
        }) {
            return Err(SearchConsoleError::CursorScopeMismatch);
        }
        Ok(Self {
            scope,
            site_id,
            dimensions,
            row_limit,
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
        canonical_digest(&(&self.scope, &self.site_id, &self.dimensions, self.row_limit))
    }

    fn start_row(&self) -> u32 {
        self.cursor
            .as_ref()
            .map_or(0, SearchConsoleCursor::start_row)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleRow {
    keys: Vec<String>,
    clicks: Decimal,
    impressions: Decimal,
    ctr: Decimal,
    position: Decimal,
}

impl SearchConsoleRow {
    fn from_value(value: &Value) -> Result<Self, SearchConsoleError> {
        Ok(Self {
            keys: value
                .get("keys")
                .and_then(Value::as_array)
                .ok_or(SearchConsoleError::MalformedResponse)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            clicks: number_field(value, "clicks")?,
            impressions: number_field(value, "impressions")?,
            ctr: number_field(value, "ctr")?,
            position: number_field(value, "position")?,
        })
    }

    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    pub const fn clicks(&self) -> Decimal {
        self.clicks
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleSitesObservation {
    sites: Vec<SearchConsoleSite>,
    observed_at: DateTime<Utc>,
    freshness: Freshness,
    classification: EvidenceClassification,
    first_party: bool,
    receipt_reference: ProviderReceiptReference,
}

impl SearchConsoleSitesObservation {
    pub fn sites(&self) -> &[SearchConsoleSite] {
        &self.sites
    }

    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
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
pub struct SearchConsoleReadObservation {
    scope: ReadScope,
    site_id: SearchConsoleSiteId,
    rows: Vec<SearchConsoleRow>,
    next_cursor: Option<SearchConsoleCursor>,
    observed_at: DateTime<Utc>,
    freshness: Freshness,
    classification: EvidenceClassification,
    first_party: bool,
    receipt_reference: ProviderReceiptReference,
    replayed: bool,
}

impl SearchConsoleReadObservation {
    pub fn rows(&self) -> &[SearchConsoleRow] {
        &self.rows
    }

    pub const fn next_cursor(&self) -> Option<&SearchConsoleCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn classification(&self) -> EvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    pub const fn receipt_reference(&self) -> &ProviderReceiptReference {
        &self.receipt_reference
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SearchConsoleError {
    #[error("Search Console site id is invalid")]
    InvalidSiteId,
    #[error("Search Console credential scope is invalid")]
    InvalidSecretScope,
    #[error("Search Console request is invalid")]
    InvalidRequest,
    #[error("Search Console cursor is invalid")]
    InvalidCursor,
    #[error("Search Console cursor does not match site or query")]
    CursorScopeMismatch,
    #[error("Search Console provider returned an invalid response")]
    MalformedResponse,
    #[error("Search Console provider returned HTTP {http_status} and code {provider_code}")]
    ProviderStatus {
        http_status: u16,
        provider_code: String,
    },
    #[error("Search Console transport failed")]
    Transport,
}

pub trait SearchConsoleTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: SearchConsoleHttpRequest,
    ) -> Result<SearchConsoleHttpResponse, SearchConsoleError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SearchConsoleHttpMethod {
    Get,
    Post,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleHttpRequest {
    method: SearchConsoleHttpMethod,
    path: String,
    body: Option<Value>,
}

impl SearchConsoleHttpRequest {
    fn new(method: SearchConsoleHttpMethod, path: impl Into<String>, body: Option<Value>) -> Self {
        Self {
            method,
            path: path.into(),
            body,
        }
    }

    pub fn method(&self) -> SearchConsoleHttpMethod {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_digest(&self) -> Option<String> {
        self.body.as_ref().map(canonical_digest)
    }
}

impl fmt::Debug for SearchConsoleHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchConsoleHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("bodyDigest", &self.body_digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchConsoleHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
}

impl SearchConsoleHttpResponse {
    pub fn new(status: u16, headers: BTreeMap<String, String>, body: Value) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

impl fmt::Debug for SearchConsoleHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchConsoleHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("bodyDigest", &response_digest(&self.body))
            .finish()
    }
}

pub struct SearchConsoleHttpTransport {
    client: Client,
    base_url: Url,
    access_token: Zeroizing<String>,
}

impl fmt::Debug for SearchConsoleHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchConsoleHttpTransport")
            .field("base_url", &self.base_url)
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SearchConsoleHttpTransport {
    pub fn new(
        base_url: impl AsRef<str>,
        access_token: impl Into<String>,
    ) -> Result<Self, SearchConsoleError> {
        let base_url = Url::parse(base_url.as_ref()).map_err(|_| SearchConsoleError::Transport)?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(SearchConsoleError::Transport);
        }
        Ok(Self {
            client: Client::builder()
                .build()
                .map_err(|_| SearchConsoleError::Transport)?,
            base_url,
            access_token: Zeroizing::new(access_token.into()),
        })
    }

    pub fn production(access_token: impl Into<String>) -> Result<Self, SearchConsoleError> {
        Self::new(GOOGLE_SEARCH_CONSOLE_API_BASE_URL, access_token)
    }
}

impl SearchConsoleTransport for SearchConsoleHttpTransport {
    fn execute(
        &mut self,
        request: SearchConsoleHttpRequest,
    ) -> Result<SearchConsoleHttpResponse, SearchConsoleError> {
        let url = self
            .base_url
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| SearchConsoleError::Transport)?;
        let method = match request.method {
            SearchConsoleHttpMethod::Get => reqwest::Method::GET,
            SearchConsoleHttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self
            .client
            .request(method, url)
            .bearer_auth(self.access_token.as_str());
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }
        let response = builder.send().map_err(|_| SearchConsoleError::Transport)?;
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
            .map_err(|_| SearchConsoleError::MalformedResponse)?;
        Ok(SearchConsoleHttpResponse::new(status, headers, body))
    }
}

pub struct SearchConsoleClient<T> {
    auth: SecretReference,
    transport: T,
    replay: BTreeMap<String, SearchConsoleReadObservation>,
}

impl<T: SearchConsoleTransport> fmt::Debug for SearchConsoleClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchConsoleClient")
            .field("auth", &self.auth)
            .field("transport", &self.transport)
            .field("replay_count", &self.replay.len())
            .finish()
    }
}

impl<T: SearchConsoleTransport> SearchConsoleClient<T> {
    pub fn new(auth: SecretReference, transport: T) -> Result<Self, SearchConsoleError> {
        if auth.scope().provider_id() != GOOGLE_SEARCH_CONSOLE_PROVIDER_ID {
            return Err(SearchConsoleError::InvalidSecretScope);
        }
        Ok(Self {
            auth,
            transport,
            replay: BTreeMap::new(),
        })
    }

    pub fn connector_scope(&self) -> &ConnectorScope {
        self.auth.scope()
    }

    pub fn connector_descriptor() -> Result<ConnectorDescriptor, ConnectorError> {
        crate::sdk::descriptor_for(
            GOOGLE_SEARCH_CONSOLE_PROVIDER_ID,
            "hartevo.google-search-console",
        )
    }

    pub fn sdk_read_observation(
        &self,
        observation: &SearchConsoleReadObservation,
        provenance: ProviderProvenanceClass,
    ) -> Result<ReadObservation, ConnectorError> {
        let descriptor = Self::connector_descriptor()?;
        let request_digest = observation.receipt_reference().request_digest();
        let next_cursor = observation
            .next_cursor()
            .map(|cursor| {
                crate::sdk::cursor(
                    self.auth.scope(),
                    request_digest,
                    1,
                    &canonical_digest(&cursor.start_row()),
                )
            })
            .transpose()?;
        ReadObservation::new(
            format!("read-observation-{request_digest}"),
            self.auth.scope().clone(),
            crate::sdk::capability(GOOGLE_SEARCH_CONSOLE_PROVIDER_ID, "search.measure")?,
            descriptor.identity().clone(),
            request_digest.to_owned(),
            observation.receipt_reference().response_digest().to_owned(),
            observation.receipt_reference().response_digest().to_owned(),
            provenance,
            crate::sdk::freshness(
                observation.freshness().observed_at(),
                observation.freshness().valid_until(),
                1,
            )?,
            1,
            u32::try_from(observation.rows().len()).unwrap_or(u32::MAX),
            next_cursor,
        )
    }

    pub fn list_sites(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<SearchConsoleSitesObservation, SearchConsoleError> {
        let path = "/webmasters/v3/sites";
        let response = self.transport.execute(SearchConsoleHttpRequest::new(
            SearchConsoleHttpMethod::Get,
            path,
            None,
        ))?;
        if response.status >= 400 {
            return Err(provider_error(&response));
        }
        let sites = response
            .body
            .get("siteEntry")
            .and_then(Value::as_array)
            .ok_or(SearchConsoleError::MalformedResponse)?
            .iter()
            .map(parse_site)
            .collect::<Result<Vec<_>, _>>()?;
        let freshness = Freshness::new(observed_at, observed_at + chrono::Duration::minutes(2))
            .map_err(|_| SearchConsoleError::MalformedResponse)?;
        Ok(SearchConsoleSitesObservation {
            sites,
            observed_at,
            freshness,
            classification: EvidenceClassification::FirstPartyAccount,
            first_party: true,
            receipt_reference: ProviderReceiptReference::new(
                GOOGLE_SEARCH_CONSOLE_PROVIDER_ID,
                "probe",
                path,
                "sites-list",
                response_digest(&response.body),
                None,
                None,
            ),
        })
    }

    pub fn query(
        &mut self,
        request: &SearchConsoleQueryRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<SearchConsoleReadObservation, SearchConsoleError> {
        let request_digest = request.request_digest();
        if let Some(cached) = self.replay.get(&request_digest) {
            let mut replayed = cached.clone();
            replayed.replayed = true;
            return Ok(replayed);
        }
        let path = format!(
            "/webmasters/v3/sites/{}/searchAnalytics/query",
            request.site_id.encoded()
        );
        let body = json!({
            "startDate": request.scope.window().start().format("%Y-%m-%d").to_string(),
            "endDate": request.scope.window().end().format("%Y-%m-%d").to_string(),
            "dimensions": request.dimensions.iter().map(|dimension| dimension.as_api_name()).collect::<Vec<_>>(),
            "type": "web",
            "rowLimit": request.row_limit,
            "startRow": request.start_row(),
        });
        let response = self.transport.execute(SearchConsoleHttpRequest::new(
            SearchConsoleHttpMethod::Post,
            path.clone(),
            Some(body),
        ))?;
        if response.status >= 400 {
            return Err(provider_error(&response));
        }
        let rows = response
            .body
            .get("rows")
            .and_then(Value::as_array)
            .map_or(&[][..], |rows| rows.as_slice())
            .iter()
            .map(SearchConsoleRow::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if u32::try_from(rows.len())
            .map_err(|_| SearchConsoleError::MalformedResponse)?
            >= request.row_limit
        {
            Some(SearchConsoleCursor::new(
                request.site_id.clone(),
                request.query_digest(),
                request.start_row().saturating_add(request.row_limit),
            )?)
        } else {
            None
        };
        let freshness = Freshness::new(observed_at, observed_at + chrono::Duration::hours(24))
            .map_err(|_| SearchConsoleError::MalformedResponse)?;
        let observation = SearchConsoleReadObservation {
            scope: request.scope.clone(),
            site_id: request.site_id.clone(),
            rows,
            next_cursor,
            observed_at,
            freshness,
            classification: EvidenceClassification::FirstPartyAccount,
            first_party: true,
            receipt_reference: ProviderReceiptReference::new(
                GOOGLE_SEARCH_CONSOLE_PROVIDER_ID,
                "read",
                &path,
                request_digest.clone(),
                response_digest(&response.body),
                None,
                None,
            ),
            replayed: false,
        };
        self.replay.insert(request_digest, observation.clone());
        Ok(observation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchConsoleWorldScenario {
    SitesAndResults,
    EmptyResult,
    PartialPropertyAccess,
}

#[derive(Clone, Debug)]
pub struct SearchConsoleRequestRecord {
    method: SearchConsoleHttpMethod,
    path: String,
    body_digest: Option<String>,
}

impl SearchConsoleRequestRecord {
    pub const fn method(&self) -> SearchConsoleHttpMethod {
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
pub struct FakeSearchConsoleTransport {
    scenario: SearchConsoleWorldScenario,
    requests: Vec<SearchConsoleRequestRecord>,
}

impl FakeSearchConsoleTransport {
    pub fn new(scenario: SearchConsoleWorldScenario) -> Self {
        Self {
            scenario,
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[SearchConsoleRequestRecord] {
        &self.requests
    }
}

impl SearchConsoleTransport for FakeSearchConsoleTransport {
    fn execute(
        &mut self,
        request: SearchConsoleHttpRequest,
    ) -> Result<SearchConsoleHttpResponse, SearchConsoleError> {
        self.requests.push(SearchConsoleRequestRecord {
            method: request.method,
            path: request.path.clone(),
            body_digest: request.body_digest(),
        });
        if request.path.ends_with("/sites") {
            return Ok(SearchConsoleHttpResponse::new(
                200,
                BTreeMap::new(),
                json!({"siteEntry":[
                    {"siteUrl":"https://example.com/","permissionLevel":"siteOwner"},
                    {"siteUrl":"sc-domain:example.org","permissionLevel":"siteRestrictedUser"}
                ]}),
            ));
        }
        if self.scenario == SearchConsoleWorldScenario::PartialPropertyAccess
            && request.path.contains("private.example")
        {
            return Ok(SearchConsoleHttpResponse::new(
                403,
                BTreeMap::new(),
                json!({"error":{"code":403,"status":"PERMISSION_DENIED"}}),
            ));
        }
        let rows = if self.scenario == SearchConsoleWorldScenario::EmptyResult {
            json!([])
        } else {
            json!([{"keys":["coffee filter"],"clicks":12.0,"impressions":120.0,"ctr":0.1,"position":3.2}])
        };
        Ok(SearchConsoleHttpResponse::new(
            200,
            BTreeMap::new(),
            json!({"rows":rows}),
        ))
    }
}

fn parse_site(value: &Value) -> Result<SearchConsoleSite, SearchConsoleError> {
    let site_id = SearchConsoleSiteId::new(
        value
            .get("siteUrl")
            .and_then(Value::as_str)
            .ok_or(SearchConsoleError::MalformedResponse)?,
    )?;
    let permission_level = match value
        .get("permissionLevel")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "siteOwner" => SearchConsolePermissionLevel::SiteOwner,
        "siteFullUser" => SearchConsolePermissionLevel::SiteFullUser,
        "siteRestrictedUser" => SearchConsolePermissionLevel::SiteRestrictedUser,
        _ => SearchConsolePermissionLevel::Unknown,
    };
    Ok(SearchConsoleSite {
        site_id,
        permission_level,
    })
}

fn provider_error(response: &SearchConsoleHttpResponse) -> SearchConsoleError {
    SearchConsoleError::ProviderStatus {
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

fn number_field(value: &Value, name: &str) -> Result<Decimal, SearchConsoleError> {
    value
        .get(name)
        .map(|number| Decimal::from_str(&number.to_string()))
        .transpose()
        .map_err(|_| SearchConsoleError::MalformedResponse)?
        .ok_or(SearchConsoleError::MalformedResponse)
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                vec![char::from(byte).to_string()]
            } else {
                vec![format!("%{byte:02X}")]
            }
        })
        .collect()
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

    fn secret() -> SecretReference {
        SecretReference::new(
            "secret-ref-gsc",
            ConnectorScope::new(
                "tenant-signal",
                "project-signal",
                GOOGLE_SEARCH_CONSOLE_PROVIDER_ID,
                "google-account",
                [GOOGLE_SEARCH_CONSOLE_READONLY_SCOPE.into()],
            )
            .expect("scope"),
            1,
        )
        .expect("secret")
    }

    #[test]
    fn canonical_site_ids_preserve_property_scope() {
        assert_eq!(
            SearchConsoleSiteId::new("HTTPS://Example.COM")
                .expect("site")
                .as_str(),
            "https://example.com/"
        );
        assert_eq!(
            SearchConsoleSiteId::new("sc-domain:Example.COM")
                .expect("domain")
                .as_str(),
            "sc-domain:example.com"
        );
        assert_eq!(
            SearchConsoleSiteId::new("https://example.com/a")
                .expect("url prefix")
                .as_str(),
            "https://example.com/a/"
        );
    }

    #[test]
    fn sites_and_search_rows_are_first_party_and_property_scoped() {
        let transport =
            FakeSearchConsoleTransport::new(SearchConsoleWorldScenario::SitesAndResults);
        let mut client = SearchConsoleClient::new(secret(), transport).expect("client");
        let sites = client.list_sites(now()).expect("sites");
        assert!(sites.first_party());
        assert_eq!(
            sites.classification(),
            EvidenceClassification::FirstPartyAccount
        );
        assert_eq!(sites.sites().len(), 2);
        let site = sites.sites()[0].site_id().clone();
        let request = SearchConsoleQueryRequest::new(
            scope(),
            site,
            vec![SearchConsoleDimension::Query],
            25,
            None,
        )
        .expect("request");
        let observation = client.query(&request, now()).expect("query");
        assert!(observation.first_party());
        assert_eq!(observation.rows()[0].clicks(), Decimal::new(12, 0));
        assert!(
            observation
                .receipt_reference()
                .endpoint()
                .contains("searchAnalytics/query")
        );
    }

    #[test]
    fn empty_and_partial_property_access_are_distinct_failures() {
        let empty = FakeSearchConsoleTransport::new(SearchConsoleWorldScenario::EmptyResult);
        let mut empty_client = SearchConsoleClient::new(secret(), empty).expect("client");
        let request = SearchConsoleQueryRequest::new(
            scope(),
            SearchConsoleSiteId::new("https://example.com/").expect("site"),
            vec![SearchConsoleDimension::Query],
            25,
            None,
        )
        .expect("request");
        assert!(
            empty_client
                .query(&request, now())
                .expect("query")
                .rows()
                .is_empty()
        );

        let partial =
            FakeSearchConsoleTransport::new(SearchConsoleWorldScenario::PartialPropertyAccess);
        let mut partial_client = SearchConsoleClient::new(secret(), partial).expect("client");
        let private_request = SearchConsoleQueryRequest::new(
            scope(),
            SearchConsoleSiteId::new("https://private.example/").expect("site"),
            vec![SearchConsoleDimension::Query],
            25,
            None,
        )
        .expect("request");
        assert_eq!(
            partial_client.query(&private_request, now()),
            Err(SearchConsoleError::ProviderStatus {
                http_status: 403,
                provider_code: "PERMISSION_DENIED".into()
            })
        );
    }

    #[test]
    fn cursor_cannot_cross_property_or_query_scope() {
        let site = SearchConsoleSiteId::new("https://example.com/").expect("site");
        let query = canonical_digest(&(
            &scope(),
            &site,
            &vec![SearchConsoleDimension::Query],
            25_u32,
        ));
        let cursor = SearchConsoleCursor::new(site.clone(), query, 25).expect("cursor");
        let request = SearchConsoleQueryRequest::new(
            scope(),
            site,
            vec![SearchConsoleDimension::Query],
            25,
            Some(cursor),
        );
        assert!(request.is_ok());
        let other_site = SearchConsoleSiteId::new("https://other.example/").expect("site");
        let wrong_cursor = SearchConsoleCursor::new(
            other_site,
            request.as_ref().expect("request").query_digest(),
            25,
        )
        .expect("cursor");
        assert_eq!(
            SearchConsoleQueryRequest::new(
                scope(),
                SearchConsoleSiteId::new("https://example.com/").expect("site"),
                vec![SearchConsoleDimension::Query],
                25,
                Some(wrong_cursor)
            ),
            Err(SearchConsoleError::CursorScopeMismatch)
        );
    }
}
