//! Authenticated DataForSEO read-only canary and deterministic report.
//!
//! The canary deliberately keeps credentials separate from the connector
//! scope. It emits only account scope metadata, digests, quota headers, cost,
//! freshness, source revision, and durable page cursors.

use std::{env, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::{
    ConnectorError, ConnectorScope, ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::{ProjectId, TenantId};
use rust_decimal::Decimal;
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    CalendarDateRange, EvidenceClassification, Freshness, LanguageCode, MarketCode, ReadScope,
    dataforseo::{
        DATAFORSEO_MAX_DEPTH, DATAFORSEO_MAX_PAGE_SIZE, DATAFORSEO_PROVIDER_ID, DataForSeoClient,
        DataForSeoDevice, DataForSeoError, DataForSeoHttpTransport, DataForSeoMode,
        DataForSeoPageCursor, DataForSeoRateLimit, DataForSeoSearchPage, DataForSeoSearchRequest,
        DataForSeoTransport,
    },
    parse_date,
};

const DEFAULT_PAGE_SIZE: usize = 10;
const DEFAULT_DEPTH: u16 = 10;
const DEFAULT_DEVICE: &str = "desktop";
const DEFAULT_SECRET_REFERENCE_ID: &str = "secret-ref-dataforseo-canary";
const DEFAULT_CONNECTOR_SCOPE: &str = "serp.read";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DataForSeoCanaryError {
    #[error("BLOCKED_ENV: missing required environment variables: {missing:?}")]
    BlockedEnv { missing: Vec<String> },
    #[error("invalid DataForSEO canary environment: {0}")]
    InvalidEnvironment(String),
    #[error(transparent)]
    DataForSeo(#[from] DataForSeoError),
    #[error(transparent)]
    Connector(#[from] ConnectorError),
    #[error("DataForSEO canary exceeded the provider depth bound while paginating")]
    PaginationBound,
}

/// The credential material is used only to construct the authenticated HTTP
/// transport and is intentionally absent from every report and debug value.
pub struct DataForSeoCanaryCredentials {
    login: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl fmt::Debug for DataForSeoCanaryCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoCanaryCredentials")
            .field("credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl DataForSeoCanaryCredentials {
    pub fn new(
        login: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, DataForSeoCanaryError> {
        let login = login.into();
        let password = password.into();
        if login.trim().is_empty() || password.trim().is_empty() {
            return Err(DataForSeoCanaryError::InvalidEnvironment(
                "DATAFORSEO_LOGIN and DATAFORSEO_PASSWORD must not be empty".into(),
            ));
        }
        Ok(Self {
            login: Zeroizing::new(login),
            password: Zeroizing::new(password),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataForSeoCanaryConfig {
    scope: ReadScope,
    account_id: String,
    request: DataForSeoSearchRequest,
    page_size: usize,
    observed_at: DateTime<Utc>,
    secret_reference_id: String,
    credential_revision: u64,
    connector_scopes: Vec<String>,
}

impl DataForSeoCanaryConfig {
    pub fn new(
        scope: ReadScope,
        account_id: impl Into<String>,
        request: DataForSeoSearchRequest,
        page_size: usize,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, DataForSeoCanaryError> {
        let account_id = account_id.into();
        let account_id = account_id.trim().to_owned();
        if request.mode() != DataForSeoMode::Live
            || account_id.trim().is_empty()
            || page_size == 0
            || page_size > DATAFORSEO_MAX_PAGE_SIZE
            || scope != *request.scope()
        {
            return Err(DataForSeoCanaryError::InvalidEnvironment(
                "the authenticated canary requires a live request, account scope, and a bounded page size".into(),
            ));
        }
        Ok(Self {
            scope,
            account_id,
            request,
            page_size,
            observed_at,
            secret_reference_id: DEFAULT_SECRET_REFERENCE_ID.into(),
            credential_revision: 1,
            connector_scopes: vec![DEFAULT_CONNECTOR_SCOPE.into()],
        })
    }

    #[must_use]
    pub fn with_secret_reference_id(mut self, secret_reference_id: impl Into<String>) -> Self {
        self.secret_reference_id = secret_reference_id.into();
        self
    }

    #[must_use]
    pub fn with_credential_revision(mut self, credential_revision: u64) -> Self {
        self.credential_revision = credential_revision;
        self
    }

    #[must_use]
    pub fn with_connector_scopes(
        mut self,
        connector_scopes: impl IntoIterator<Item = String>,
    ) -> Self {
        self.connector_scopes = connector_scopes.into_iter().collect();
        self
    }

    pub const fn scope(&self) -> &ReadScope {
        &self.scope
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub const fn request(&self) -> &DataForSeoSearchRequest {
        &self.request
    }

    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn secret_reference_id(&self) -> &str {
        &self.secret_reference_id
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn connector_scope(&self) -> Result<ConnectorScope, ConnectorError> {
        ConnectorScope::new(
            self.scope.tenant_id().as_str(),
            self.scope.project_id().as_str(),
            DATAFORSEO_PROVIDER_ID,
            self.account_id.clone(),
            self.connector_scopes.clone(),
        )
    }

    pub fn secret_reference(&self) -> Result<SecretReference, ConnectorError> {
        SecretReference::new(
            self.secret_reference_id.clone(),
            self.connector_scope()?,
            self.credential_revision,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCanaryScopeReport {
    tenant_id: String,
    project_id: String,
    provider_id: String,
    account_id: String,
    scopes: Vec<String>,
    scope_digest: String,
}

impl DataForSeoCanaryScopeReport {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCanaryCursorReport {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    offset: usize,
    page_size: usize,
    source_revision: u64,
    token_digest: String,
}

impl DataForSeoCanaryCursorReport {
    fn from_cursor(cursor: &DataForSeoPageCursor) -> Self {
        Self {
            scope_digest: cursor.scope_digest().to_owned(),
            request_digest: cursor.request_digest().to_owned(),
            sequence: cursor.sequence(),
            offset: cursor.offset(),
            page_size: cursor.page_size(),
            source_revision: cursor.source_revision(),
            token_digest: cursor.token_digest().to_owned(),
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCanaryPageReport {
    page_sequence: u64,
    item_count: usize,
    charged: bool,
    replayed: bool,
    cost_usd: Decimal,
    rate_limit: DataForSeoRateLimit,
    freshness: Freshness,
    normalized_response_digest: String,
    raw_evidence_digest: String,
    source_revision: u64,
    cursor: Option<DataForSeoCanaryCursorReport>,
    next_cursor: Option<DataForSeoCanaryCursorReport>,
}

impl DataForSeoCanaryPageReport {
    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn next_cursor(&self) -> Option<&DataForSeoCanaryCursorReport> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoCanaryReport {
    provider_id: String,
    secret_reference_id: String,
    credential_revision: u64,
    account_scope: DataForSeoCanaryScopeReport,
    mode: DataForSeoMode,
    classification: EvidenceClassification,
    first_party: bool,
    request_digest: String,
    estimated_cost_usd: Decimal,
    provider_cost_usd: Decimal,
    charged_cost_usd: Decimal,
    charged_page_count: usize,
    total_item_count: usize,
    provenance: ProviderProvenanceClass,
    pages: Vec<DataForSeoCanaryPageReport>,
}

impl DataForSeoCanaryReport {
    pub fn account_scope(&self) -> &DataForSeoCanaryScopeReport {
        &self.account_scope
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn pages(&self) -> &[DataForSeoCanaryPageReport] {
        &self.pages
    }

    pub fn charged_cost_usd(&self) -> Decimal {
        self.charged_cost_usd
    }

    pub fn provider_cost_usd(&self) -> Decimal {
        self.provider_cost_usd
    }

    pub const fn charged_page_count(&self) -> usize {
        self.charged_page_count
    }

    pub const fn total_item_count(&self) -> usize {
        self.total_item_count
    }
}

pub struct DataForSeoCanaryEnv {
    config: DataForSeoCanaryConfig,
    credentials: DataForSeoCanaryCredentials,
}

impl fmt::Debug for DataForSeoCanaryEnv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoCanaryEnv")
            .field("config", &self.config)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl DataForSeoCanaryEnv {
    pub fn from_env() -> Result<Self, DataForSeoCanaryError> {
        let mut missing = Vec::new();
        let login = required_env("DATAFORSEO_LOGIN", &mut missing);
        let password = required_env("DATAFORSEO_PASSWORD", &mut missing);
        let tenant_id = required_env("DATAFORSEO_TENANT_ID", &mut missing);
        let project_id = required_env("DATAFORSEO_PROJECT_ID", &mut missing);
        let account_id = required_env("DATAFORSEO_ACCOUNT_ID", &mut missing);
        let keyword = required_env("DATAFORSEO_KEYWORD", &mut missing);
        let location_code = required_env("DATAFORSEO_LOCATION_CODE", &mut missing);
        let language_code = required_env("DATAFORSEO_LANGUAGE_CODE", &mut missing);
        let market = required_env("DATAFORSEO_MARKET", &mut missing);
        let window_start = required_env("DATAFORSEO_WINDOW_START", &mut missing);
        let window_end = required_env("DATAFORSEO_WINDOW_END", &mut missing);
        let estimated_cost_usd = required_env("DATAFORSEO_ESTIMATED_COST_USD", &mut missing);
        let max_cost_usd = required_env("DATAFORSEO_MAX_COST_USD", &mut missing);
        if !missing.is_empty() {
            return Err(DataForSeoCanaryError::BlockedEnv { missing });
        }

        let login = login.expect("required DataForSEO login is present");
        let password = password.expect("required DataForSEO password is present");
        let tenant_id = tenant_id.expect("required tenant id is present");
        let project_id = project_id.expect("required project id is present");
        let account_id = account_id.expect("required account id is present");
        let keyword = keyword.expect("required keyword is present");
        let location_code = location_code.expect("required location code is present");
        let language_code = language_code.expect("required language code is present");
        let market = market.expect("required market is present");
        let window_start = window_start.expect("required window start is present");
        let window_end = window_end.expect("required window end is present");
        let estimated_cost_usd = estimated_cost_usd.expect("required estimate is present");
        let max_cost_usd = max_cost_usd.expect("required cost limit is present");

        let scope = ReadScope::new(
            TenantId::from(trimmed(&tenant_id).as_str()),
            ProjectId::from(trimmed(&project_id).as_str()),
            MarketCode::new(trimmed(&market).as_str())
                .map_err(|error| DataForSeoCanaryError::InvalidEnvironment(error.to_string()))?,
            LanguageCode::new(trimmed(&language_code).as_str())
                .map_err(|error| DataForSeoCanaryError::InvalidEnvironment(error.to_string()))?,
            CalendarDateRange::new(
                parse_date(trimmed(&window_start).as_str()).map_err(|error| {
                    DataForSeoCanaryError::InvalidEnvironment(error.to_string())
                })?,
                parse_date(trimmed(&window_end).as_str()).map_err(|error| {
                    DataForSeoCanaryError::InvalidEnvironment(error.to_string())
                })?,
            )
            .map_err(|error| DataForSeoCanaryError::InvalidEnvironment(error.to_string()))?,
        );
        let request = DataForSeoSearchRequest::new(
            scope.clone(),
            keyword.trim(),
            parse_value("DATAFORSEO_LOCATION_CODE", &location_code)?,
            parse_device(&optional_env("DATAFORSEO_DEVICE", DEFAULT_DEVICE))?,
            parse_value(
                "DATAFORSEO_DEPTH",
                &optional_env("DATAFORSEO_DEPTH", &DEFAULT_DEPTH.to_string()),
            )?,
            DataForSeoMode::Live,
            parse_decimal("DATAFORSEO_ESTIMATED_COST_USD", &estimated_cost_usd)?,
            Some(parse_decimal("DATAFORSEO_MAX_COST_USD", &max_cost_usd)?),
        )?;
        let config = DataForSeoCanaryConfig::new(
            scope,
            trimmed(&account_id),
            request,
            parse_value(
                "DATAFORSEO_PAGE_SIZE",
                &optional_env("DATAFORSEO_PAGE_SIZE", &DEFAULT_PAGE_SIZE.to_string()),
            )?,
            optional_timestamp("DATAFORSEO_OBSERVED_AT")?,
        )?
        .with_secret_reference_id(optional_env(
            "DATAFORSEO_SECRET_REFERENCE_ID",
            DEFAULT_SECRET_REFERENCE_ID,
        ))
        .with_credential_revision(parse_value(
            "DATAFORSEO_CREDENTIAL_REVISION",
            &optional_env("DATAFORSEO_CREDENTIAL_REVISION", "1"),
        )?)
        .with_connector_scopes(parse_scopes()?);
        Ok(Self {
            config,
            credentials: DataForSeoCanaryCredentials::new(login, password)?,
        })
    }

    pub const fn config(&self) -> &DataForSeoCanaryConfig {
        &self.config
    }
}

pub fn run_authenticated(
    environment: &DataForSeoCanaryEnv,
) -> Result<DataForSeoCanaryReport, DataForSeoCanaryError> {
    let transport = DataForSeoHttpTransport::production(
        environment.credentials.login.as_str().to_owned(),
        environment.credentials.password.as_str().to_owned(),
    )?;
    run_with_transport_and_provenance(
        environment.config(),
        transport,
        ProviderProvenanceClass::ProductionProvider,
    )
}

/// Run the exact canary path against a deterministic transport. This is the
/// testkit seam; it still constructs the same opaque secret reference, SDK
/// cursors, replay ledger, and report as the authenticated path.
pub fn run_with_transport<T: DataForSeoTransport>(
    config: &DataForSeoCanaryConfig,
    transport: T,
) -> Result<DataForSeoCanaryReport, DataForSeoCanaryError> {
    run_with_transport_and_provenance(
        config,
        transport,
        ProviderProvenanceClass::ControlledProvider,
    )
}

fn run_with_transport_and_provenance<T: DataForSeoTransport>(
    config: &DataForSeoCanaryConfig,
    transport: T,
    provenance: ProviderProvenanceClass,
) -> Result<DataForSeoCanaryReport, DataForSeoCanaryError> {
    let connector_scope = config.connector_scope()?;
    let secret_reference = config.secret_reference()?;
    let mut client = DataForSeoClient::new(secret_reference, transport)?;
    let mut cursor = None;
    let mut pages = Vec::new();
    let mut charged_cost_usd = Decimal::ZERO;
    let mut provider_cost_usd = None;
    let mut total_item_count = 0_usize;
    let mut charged_page_count = 0_usize;

    for _ in 0..=DATAFORSEO_MAX_DEPTH {
        let page = client.read_live_page(
            config.request(),
            config.page_size(),
            cursor.as_ref(),
            config.observed_at(),
        )?;
        let _sdk_projection = client.sdk_read_page_observation(&page, provenance)?;
        let observation = page.observation();
        provider_cost_usd.get_or_insert(observation.cost_usd());
        if page.charged() {
            charged_page_count = charged_page_count.saturating_add(1);
            charged_cost_usd += observation.cost_usd();
        }
        total_item_count = total_item_count.saturating_add(page.items().len());
        let next_cursor = page.next_cursor().cloned();
        pages.push(page_report(&page));
        match next_cursor {
            Some(next_cursor) => cursor = Some(next_cursor),
            None => {
                return Ok(DataForSeoCanaryReport {
                    provider_id: DATAFORSEO_PROVIDER_ID.into(),
                    secret_reference_id: config.secret_reference_id().into(),
                    credential_revision: config.credential_revision(),
                    account_scope: scope_report(&connector_scope),
                    mode: config.request().mode(),
                    classification: EvidenceClassification::ProviderEstimate,
                    first_party: false,
                    request_digest: config.request().request_digest(),
                    estimated_cost_usd: config
                        .request()
                        .estimate_only_evidence()
                        .estimated_cost_usd(),
                    provider_cost_usd: provider_cost_usd.unwrap_or(Decimal::ZERO),
                    charged_cost_usd,
                    charged_page_count,
                    total_item_count,
                    provenance,
                    pages,
                });
            }
        }
    }
    Err(DataForSeoCanaryError::PaginationBound)
}

fn page_report(page: &DataForSeoSearchPage) -> DataForSeoCanaryPageReport {
    let observation = page.observation();
    DataForSeoCanaryPageReport {
        page_sequence: page.page_sequence(),
        item_count: page.items().len(),
        charged: page.charged(),
        replayed: page.replayed(),
        cost_usd: observation.cost_usd(),
        rate_limit: observation.rate_limit().clone(),
        freshness: observation.freshness().clone(),
        normalized_response_digest: observation.response_digest().into(),
        raw_evidence_digest: observation.raw_evidence_digest().into(),
        source_revision: observation.source_revision(),
        cursor: page.cursor().map(DataForSeoCanaryCursorReport::from_cursor),
        next_cursor: page
            .next_cursor()
            .map(DataForSeoCanaryCursorReport::from_cursor),
    }
}

fn scope_report(scope: &ConnectorScope) -> DataForSeoCanaryScopeReport {
    DataForSeoCanaryScopeReport {
        tenant_id: scope.tenant_id().into(),
        project_id: scope.project_id().into(),
        provider_id: scope.provider_id().into(),
        account_id: scope.account_id().into(),
        scopes: scope.scopes().iter().cloned().collect(),
        scope_digest: scope.digest(),
    }
}

fn required_env(name: &str, missing: &mut Vec<String>) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            missing.push(name.into());
            None
        }
    }
}

fn optional_env(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.into())
}

fn trimmed(value: &str) -> String {
    value.trim().into()
}

fn parse_value<T>(name: &str, value: &str) -> Result<T, DataForSeoCanaryError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    value.trim().parse::<T>().map_err(|error| {
        DataForSeoCanaryError::InvalidEnvironment(format!("{name} is invalid: {error}"))
    })
}

fn parse_decimal(name: &str, value: &str) -> Result<Decimal, DataForSeoCanaryError> {
    parse_value(name, value)
}

fn parse_device(value: &str) -> Result<DataForSeoDevice, DataForSeoCanaryError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "desktop" => Ok(DataForSeoDevice::Desktop),
        "mobile" => Ok(DataForSeoDevice::Mobile),
        other => Err(DataForSeoCanaryError::InvalidEnvironment(format!(
            "DATAFORSEO_DEVICE is invalid: {other}"
        ))),
    }
}

fn optional_timestamp(name: &str) -> Result<DateTime<Utc>, DataForSeoCanaryError> {
    match env::var(name).ok().filter(|value| !value.trim().is_empty()) {
        Some(value) => DateTime::parse_from_rfc3339(value.trim())
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .map_err(|error| {
                DataForSeoCanaryError::InvalidEnvironment(format!("{name} is invalid: {error}"))
            }),
        None => Ok(Utc::now()),
    }
}

fn parse_scopes() -> Result<Vec<String>, DataForSeoCanaryError> {
    let scopes = optional_env("DATAFORSEO_SCOPES", DEFAULT_CONNECTOR_SCOPE)
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        return Err(DataForSeoCanaryError::InvalidEnvironment(
            "DATAFORSEO_SCOPES must contain at least one scope".into(),
        ));
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{ProjectId, TenantId};
    use rust_decimal::Decimal;

    use super::*;
    use crate::{
        CalendarDateRange, LanguageCode, MarketCode,
        dataforseo::{DataForSeoWorldScenario, FakeDataForSeoTransport},
        parse_date,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time")
    }

    fn config() -> DataForSeoCanaryConfig {
        let scope = ReadScope::new(
            TenantId::from("tenant-canary"),
            ProjectId::from("project-canary"),
            MarketCode::new("DE").expect("market"),
            LanguageCode::new("de").expect("language"),
            CalendarDateRange::new(
                parse_date("2026-08-01").expect("date"),
                parse_date("2026-08-07").expect("date"),
            )
            .expect("window"),
        );
        let request = DataForSeoSearchRequest::new(
            scope.clone(),
            "canary keyword",
            2276,
            DataForSeoDevice::Desktop,
            10,
            DataForSeoMode::Live,
            Decimal::new(10, 2),
            Some(Decimal::new(20, 2)),
        )
        .expect("request");
        DataForSeoCanaryConfig::new(scope, "dataforseo-account", request, 2, now()).expect("config")
    }

    #[test]
    fn authenticated_report_is_estimate_only_and_carries_scope_quota_cost_freshness_and_evidence() {
        let report = run_with_transport(
            &config(),
            FakeDataForSeoTransport::new(DataForSeoWorldScenario::PaginatedResults),
        )
        .expect("canary report");
        assert_eq!(report.account_scope().account_id(), "dataforseo-account");
        assert_eq!(report.pages().len(), 2);
        assert_eq!(report.total_item_count(), 3);
        assert_eq!(report.charged_page_count(), 1);
        assert_eq!(report.charged_cost_usd(), Decimal::new(10, 2));
        assert_eq!(report.pages()[0].item_count(), 2);
        assert_eq!(report.pages()[1].item_count(), 1);
        assert!(report.pages()[0].charged());
        assert!(report.pages()[1].replayed());
        assert_eq!(report.pages()[0].rate_limit.remaining(), Some(59));
        assert_eq!(report.pages()[0].raw_evidence_digest().len(), 64);
        assert_ne!(report.pages()[0].source_revision(), 0);
        assert_eq!(
            report.pages()[0].next_cursor().expect("cursor").sequence(),
            2
        );
        assert_eq!(
            report.pages()[1].cursor.as_ref().expect("cursor").offset(),
            2
        );
        assert!(!report.first_party);
        assert_eq!(
            report.classification,
            EvidenceClassification::ProviderEstimate
        );
    }

    #[test]
    fn canary_scope_reuses_sdk_scope_validation_and_redacts_credentials() {
        let credentials =
            DataForSeoCanaryCredentials::new("login", "password").expect("credentials");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("password"));
        let scope = config().connector_scope().expect("scope");
        assert_eq!(scope.provider_id(), DATAFORSEO_PROVIDER_ID);
        assert_eq!(
            scope.scopes(),
            &std::collections::BTreeSet::from(["serp.read".into()])
        );
        let _reference = SecretReference::new("secret-ref-canary-test", scope, 1).expect("secret");
    }

    #[test]
    fn blocked_env_is_a_distinct_non_success_state() {
        let error = DataForSeoCanaryError::BlockedEnv {
            missing: vec!["DATAFORSEO_LOGIN".into(), "DATAFORSEO_PASSWORD".into()],
        };
        assert!(error.to_string().starts_with("BLOCKED_ENV:"));
    }
}
