use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::model::{
    AggregateMeasure, AggregateRow, AggregateValue, Digest, Dimension, DimensionValue, Metric,
    MetricEvidence, ProviderErrorKind, ProviderProvenance, RedactionSummary, ResultStatus,
    SecretReference,
};
use crate::query::ClarityDataExportGetRequest;
use crate::{
    CLARITY_DATA_EXPORT_METHOD, CLARITY_DATA_EXPORT_PATH, CLARITY_MAX_DIMENSIONS,
    CLARITY_MAX_REQUESTS_PER_PROJECT_PER_DAY, CLARITY_MAX_RESPONSE_BYTES,
    CLARITY_MAX_RESPONSE_ROWS, CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT,
    CLARITY_UX_RESULT_PROVIDER_ID,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityProviderDefinition {
    pub id: String,
    pub version: String,
    pub method: String,
    pub path: String,
    pub read_only: bool,
    pub native: bool,
    pub https_transport: bool,
    pub readback: bool,
    pub max_days: u8,
    pub max_dimensions: usize,
    pub max_rows: u16,
    pub max_response_bytes: usize,
    pub max_requests_per_project_per_day: u8,
    pub paginated: bool,
}

impl ClarityProviderDefinition {
    pub fn new() -> Self {
        Self {
            id: CLARITY_UX_RESULT_PROVIDER_ID.to_owned(),
            version: CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            method: CLARITY_DATA_EXPORT_METHOD.to_owned(),
            path: CLARITY_DATA_EXPORT_PATH.to_owned(),
            read_only: true,
            native: false,
            https_transport: false,
            readback: false,
            max_days: 3,
            max_dimensions: CLARITY_MAX_DIMENSIONS,
            max_rows: CLARITY_MAX_RESPONSE_ROWS,
            max_response_bytes: CLARITY_MAX_RESPONSE_BYTES,
            max_requests_per_project_per_day: CLARITY_MAX_REQUESTS_PER_PROJECT_PER_DAY,
            paginated: false,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected = Self::new();
        if self != &expected {
            Err(ProviderDefinitionError::DefinitionDrift)
        } else {
            Ok(())
        }
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "clarity-provider-definition/v1",
            &[
                self.id.clone(),
                self.version.clone(),
                self.method.clone(),
                self.path.clone(),
                self.read_only.to_string(),
                self.native.to_string(),
                self.https_transport.to_string(),
                self.readback.to_string(),
                self.max_days.to_string(),
                self.max_dimensions.to_string(),
                self.max_rows.to_string(),
                self.max_response_bytes.to_string(),
                self.max_requests_per_project_per_day.to_string(),
                self.paginated.to_string(),
            ],
        )
    }
}

impl Default for ClarityProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Clarity provider definition drifted from the Layer-1 contract")]
    DefinitionDrift,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClarityProviderError {
    #[error("Clarity provider definition drifted")]
    DefinitionDrift,
    #[error("Clarity request scope does not match the secret reference")]
    ScopeMismatch,
    #[error("Clarity secret reference is revoked")]
    SecretRevoked,
    #[error("Clarity request failed allowlist or digest validation")]
    InvalidRequest,
    #[error("Clarity transport is not available in Layer 1")]
    TransportUnavailable,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClarityTransportError {
    #[error("Clarity returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("Clarity request quota is exhausted")]
    QuotaExhausted,
    #[error("Clarity request is blocked in this environment")]
    BlockedEnv,
    #[error("Clarity credential is unavailable")]
    CredentialUnavailable,
    #[error("Clarity response exceeds the contract byte bound")]
    ResponseTooLarge,
    #[error("Clarity response attempted pagination")]
    NonPaginatedResponse,
    #[error("Clarity response declares truncation")]
    TruncatedResponse,
    #[error("Clarity response body is malformed")]
    MalformedResponse,
    #[error("Clarity transport failed")]
    Transport,
    #[error("Clarity time window has expired")]
    Expired,
}

impl ClarityTransportError {
    pub const fn http_status(status: u16) -> Self {
        Self::HttpStatus(status)
    }

    pub const fn unauthorized() -> Self {
        Self::HttpStatus(401)
    }

    pub const fn forbidden() -> Self {
        Self::HttpStatus(403)
    }

    pub const fn bad_request() -> Self {
        Self::HttpStatus(400)
    }

    pub const fn rate_limited() -> Self {
        Self::HttpStatus(429)
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(status) => Some(*status),
            _ => None,
        }
    }
}

/// A transport response that owns raw bytes only at the transport boundary.
/// The provider never puts `body` into an error, receipt, proposal, or digest.
#[derive(Clone, Eq, PartialEq)]
pub struct ClarityHttpResponse {
    status: u16,
    body: String,
}

impl ClarityHttpResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    pub fn ok(body: impl Into<String>) -> Self {
        Self::new(200, body)
    }

    pub const fn status(&self) -> u16 {
        self.status
    }
}

impl fmt::Debug for ClarityHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClarityHttpResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

pub trait ClarityDataExportTransport: fmt::Debug {
    fn get(
        &mut self,
        request: &ClarityDataExportGetRequest,
    ) -> Result<ClarityHttpResponse, ClarityTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityProviderEvidence {
    pub request_digest: Digest,
    pub project_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub status: ResultStatus,
    pub error: Option<ProviderErrorKind>,
    pub metrics: Vec<MetricEvidence>,
    pub redactions: RedactionSummary,
    pub response_digest: Digest,
    pub rows: u16,
}

impl ClarityProviderEvidence {
    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn validate(
        &self,
        request: &ClarityDataExportGetRequest,
        definition: &ClarityProviderDefinition,
    ) -> bool {
        if request.validate().is_err()
            || self.request_digest != *request.query_digest()
            || self.project_digest != request.project_id().digest()
            || self.scope_digest != *request.scope_digest()
            || self.provider_digest != definition.provider_digest()
            || !self.redactions.raw_api_body_dropped
            || self.rows > definition.max_rows
            || self.metrics.iter().any(|metric| {
                !request.metrics().contains(metric.metric)
                    || metric.rows.iter().any(|row| {
                        row.dimensions.len() != request.dimensions().len()
                            || row.values.is_empty()
                            || row.dimensions.iter().any(|value| !value.validate())
                            || row.values.iter().any(|value| match value.measure {
                                AggregateMeasure::PercentageBasisPoints
                                | AggregateMeasure::PagesPerSessionBasisPoints => {
                                    value.value > 10_000
                                }
                                AggregateMeasure::TotalSessions
                                | AggregateMeasure::BotSessions
                                | AggregateMeasure::DistantUsers
                                | AggregateMeasure::MetricCount
                                | AggregateMeasure::EngagementMilliseconds => false,
                            })
                    })
            })
        {
            return false;
        }
        compute_response_digest(
            &self.request_digest,
            self.provenance,
            self.status,
            self.error,
            &self.metrics,
            &self.redactions,
            self.rows,
            &self.provider_digest,
        ) == self.response_digest
    }
}

pub trait ClarityProvider: fmt::Debug {
    fn definition(&self) -> &ClarityProviderDefinition;

    fn provenance(&self) -> ProviderProvenance;

    fn get(
        &mut self,
        request: &ClarityDataExportGetRequest,
        secret: &SecretReference,
    ) -> Result<ClarityProviderEvidence, ClarityProviderError>;
}

#[derive(Clone, Debug)]
pub struct ClarityDataExportProvider<T> {
    definition: ClarityProviderDefinition,
    transport: T,
    provenance: ProviderProvenance,
    quota: BTreeMap<(String, i64), u8>,
}

impl<T> ClarityDataExportProvider<T>
where
    T: ClarityDataExportTransport,
{
    pub fn new(
        transport: T,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = ClarityProviderDefinition::new();
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
            provenance,
            quota: BTreeMap::new(),
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn quota_used(&self, project_id: &str, utc_day: i64) -> u8 {
        self.quota
            .get(&(project_id.to_owned(), utc_day))
            .copied()
            .unwrap_or(0)
    }
}

impl<T> ClarityProvider for ClarityDataExportProvider<T>
where
    T: ClarityDataExportTransport,
{
    fn definition(&self) -> &ClarityProviderDefinition {
        &self.definition
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn get(
        &mut self,
        request: &ClarityDataExportGetRequest,
        secret: &SecretReference,
    ) -> Result<ClarityProviderEvidence, ClarityProviderError> {
        self.definition
            .validate()
            .map_err(|_| ClarityProviderError::DefinitionDrift)?;
        request
            .validate()
            .map_err(|_| ClarityProviderError::InvalidRequest)?;
        if secret.is_revoked() {
            return Err(ClarityProviderError::SecretRevoked);
        }
        if secret.scope_digest() != request.scope_digest() {
            return Err(ClarityProviderError::ScopeMismatch);
        }

        let quota_key = (
            request.project_id().as_str().to_owned(),
            request.requested_at().utc_day(),
        );
        let used = self.quota.get(&quota_key).copied().unwrap_or(0);
        if used >= self.definition.max_requests_per_project_per_day {
            return Ok(error_evidence(
                request,
                &self.definition,
                self.provenance,
                ResultStatus::RateLimited,
                ProviderErrorKind::QuotaExhausted,
            ));
        }
        self.quota.insert(quota_key, used.saturating_add(1));

        let response = self.transport.get(request);
        match response {
            Ok(response) => self.normalize_response(request, response),
            Err(error) => Ok(error_evidence(
                request,
                &self.definition,
                self.provenance,
                status_for_transport_error(&error),
                kind_for_transport_error(&error),
            )),
        }
    }
}

impl<T> ClarityDataExportProvider<T>
where
    T: ClarityDataExportTransport,
{
    fn normalize_response(
        &self,
        request: &ClarityDataExportGetRequest,
        response: ClarityHttpResponse,
    ) -> Result<ClarityProviderEvidence, ClarityProviderError> {
        if response.status() != 200 {
            let error = ClarityTransportError::http_status(response.status());
            return Ok(error_evidence(
                request,
                &self.definition,
                self.provenance,
                status_for_transport_error(&error),
                kind_for_transport_error(&error),
            ));
        }
        if response.body.len() > self.definition.max_response_bytes {
            return Ok(error_evidence(
                request,
                &self.definition,
                self.provenance,
                ResultStatus::ProviderUnknown,
                ProviderErrorKind::ResponseTooLarge,
            ));
        }

        let body = response.body;
        match normalize_json_body(request, &body, &self.definition) {
            Ok((metrics, redactions, rows)) => {
                let status = status_for_metrics(request, &metrics);
                let error = None;
                let request_digest = request.query_digest().clone();
                let provider_digest = self.definition.provider_digest();
                let response_digest = compute_response_digest(
                    &request_digest,
                    self.provenance,
                    status,
                    error,
                    &metrics,
                    &redactions,
                    rows,
                    &provider_digest,
                );
                Ok(ClarityProviderEvidence {
                    request_digest,
                    project_digest: request.project_id().digest(),
                    scope_digest: request.scope_digest().clone(),
                    provider_digest,
                    provenance: self.provenance,
                    status,
                    error,
                    metrics,
                    redactions,
                    response_digest,
                    rows,
                })
            }
            Err(error) => Ok(error_evidence(
                request,
                &self.definition,
                self.provenance,
                status_for_transport_error(&error),
                kind_for_transport_error(&error),
            )),
        }
    }
}

fn error_evidence(
    request: &ClarityDataExportGetRequest,
    definition: &ClarityProviderDefinition,
    provenance: ProviderProvenance,
    status: ResultStatus,
    error: ProviderErrorKind,
) -> ClarityProviderEvidence {
    let metrics = Vec::new();
    let redactions = RedactionSummary::strict();
    let request_digest = request.query_digest().clone();
    let provider_digest = definition.provider_digest();
    let response_digest = compute_response_digest(
        &request_digest,
        provenance,
        status,
        Some(error),
        &metrics,
        &redactions,
        0,
        &provider_digest,
    );
    ClarityProviderEvidence {
        request_digest,
        project_digest: request.project_id().digest(),
        scope_digest: request.scope_digest().clone(),
        provider_digest,
        provenance,
        status,
        error: Some(error),
        metrics,
        redactions,
        response_digest,
        rows: 0,
    }
}

fn status_for_transport_error(error: &ClarityTransportError) -> ResultStatus {
    match error {
        ClarityTransportError::HttpStatus(401 | 403)
        | ClarityTransportError::CredentialUnavailable => ResultStatus::AccessLost,
        ClarityTransportError::HttpStatus(429) | ClarityTransportError::QuotaExhausted => {
            ResultStatus::RateLimited
        }
        ClarityTransportError::Expired => ResultStatus::Expired,
        _ => ResultStatus::ProviderUnknown,
    }
}

fn kind_for_transport_error(error: &ClarityTransportError) -> ProviderErrorKind {
    match error {
        ClarityTransportError::HttpStatus(401) => ProviderErrorKind::Unauthorized,
        ClarityTransportError::HttpStatus(403) => ProviderErrorKind::Forbidden,
        ClarityTransportError::HttpStatus(400) => ProviderErrorKind::BadRequest,
        ClarityTransportError::HttpStatus(429) => ProviderErrorKind::RateLimited,
        ClarityTransportError::QuotaExhausted => ProviderErrorKind::QuotaExhausted,
        ClarityTransportError::BlockedEnv => ProviderErrorKind::BlockedEnv,
        ClarityTransportError::CredentialUnavailable => ProviderErrorKind::SecretRevoked,
        ClarityTransportError::ResponseTooLarge => ProviderErrorKind::ResponseTooLarge,
        ClarityTransportError::NonPaginatedResponse => ProviderErrorKind::NonPaginatedViolation,
        ClarityTransportError::TruncatedResponse => ProviderErrorKind::TruncatedResponse,
        ClarityTransportError::MalformedResponse => ProviderErrorKind::MalformedResponse,
        ClarityTransportError::Transport => ProviderErrorKind::Transport,
        ClarityTransportError::Expired => ProviderErrorKind::Expired,
        ClarityTransportError::HttpStatus(_) => ProviderErrorKind::Unknown,
    }
}

fn status_for_metrics(
    request: &ClarityDataExportGetRequest,
    metrics: &[MetricEvidence],
) -> ResultStatus {
    let present = metrics
        .iter()
        .filter(|metric| !metric.rows.is_empty())
        .count();
    if present == 0 {
        ResultStatus::Empty
    } else if present < request.metrics().len() {
        ResultStatus::Partial
    } else {
        ResultStatus::Complete
    }
}

fn normalize_json_body(
    request: &ClarityDataExportGetRequest,
    body: &str,
    definition: &ClarityProviderDefinition,
) -> Result<(Vec<MetricEvidence>, RedactionSummary, u16), ClarityTransportError> {
    let value = serde_json::from_str::<Value>(body)
        .map_err(|_| ClarityTransportError::MalformedResponse)?;
    let mut redactions = RedactionSummary::strict();
    scan_sensitive_metadata(&value, &mut redactions);
    if contains_pagination_marker(&value) {
        return Err(ClarityTransportError::NonPaginatedResponse);
    }
    let root = value
        .as_array()
        .ok_or(ClarityTransportError::MalformedResponse)?;
    let mut by_metric = request
        .metrics()
        .iter()
        .map(|metric| (*metric, Vec::new()))
        .collect::<BTreeMap<_, Vec<_>>>();
    let mut seen_rows = 0_u16;
    let mut rows = 0_u16;
    for block in root {
        let object = block
            .as_object()
            .ok_or(ClarityTransportError::MalformedResponse)?;
        let Some(metric_name) = object.get("metricName").and_then(Value::as_str) else {
            continue;
        };
        let Ok(metric) = Metric::from_api_name(metric_name) else {
            continue;
        };
        if !request.metrics().contains(metric) {
            continue;
        }
        let Some(information) = object.get("information") else {
            continue;
        };
        let entries = information
            .as_array()
            .ok_or(ClarityTransportError::MalformedResponse)?;
        for entry in entries {
            seen_rows = seen_rows
                .checked_add(1)
                .ok_or(ClarityTransportError::TruncatedResponse)?;
            if seen_rows > definition.max_rows {
                return Err(ClarityTransportError::TruncatedResponse);
            }
            let object = entry
                .as_object()
                .ok_or(ClarityTransportError::MalformedResponse)?;
            if let Some(row) = normalize_row(object, request, &mut redactions, metric) {
                rows = rows
                    .checked_add(1)
                    .ok_or(ClarityTransportError::TruncatedResponse)?;
                by_metric.entry(metric).or_default().push(row);
            }
        }
    }
    let metrics = by_metric
        .into_iter()
        .map(|(metric, rows)| MetricEvidence { metric, rows })
        .collect::<Vec<_>>();
    Ok((metrics, redactions, rows))
}

fn normalize_row(
    object: &Map<String, Value>,
    request: &ClarityDataExportGetRequest,
    redactions: &mut RedactionSummary,
    _metric: Metric,
) -> Option<AggregateRow> {
    let dimensions = request
        .dimensions()
        .iter()
        .map(|dimension| normalize_dimension(object, *dimension, redactions))
        .collect::<Vec<_>>();
    let mut values = object
        .iter()
        .filter_map(|(key, value)| measure_for_key(key, value))
        .collect::<Vec<_>>();
    values.sort_by_key(|value| (value.measure, value.value));
    if values.is_empty() {
        None
    } else {
        Some(AggregateRow { dimensions, values })
    }
}

fn normalize_dimension(
    object: &Map<String, Value>,
    dimension: Dimension,
    redactions: &mut RedactionSummary,
) -> DimensionValue {
    let key = dimension.api_name();
    let Some(value) = object.get(key) else {
        return DimensionValue::NotAvailable;
    };
    if dimension.sensitive() {
        mark_dimension_redaction(dimension, redactions);
        return DimensionValue::Redacted;
    }
    if let Some(label) = value
        .as_str()
        .and_then(|value| DimensionValue::safe_label(value).ok())
    {
        label
    } else {
        mark_dimension_redaction(dimension, redactions);
        DimensionValue::Redacted
    }
}

fn mark_dimension_redaction(dimension: Dimension, redactions: &mut RedactionSummary) {
    match dimension {
        Dimension::Url => redactions.url_values = redactions.url_values.saturating_add(1),
        Dimension::Campaign => {
            redactions.campaign_values = redactions.campaign_values.saturating_add(1);
        }
        _ => {}
    }
}

fn measure_for_key(key: &str, value: &Value) -> Option<AggregateValue> {
    let normalized = key.to_ascii_lowercase().replace(['_', '-', ' '], "");
    let (measure, parsed) = match normalized.as_str() {
        "totalsessioncount" => (AggregateMeasure::TotalSessions, parse_count(value)?),
        "totalbotsessioncount" => (AggregateMeasure::BotSessions, parse_count(value)?),
        "distantusercount" => (AggregateMeasure::DistantUsers, parse_count(value)?),
        "pagespersessionpercentage" => (
            AggregateMeasure::PagesPerSessionBasisPoints,
            parse_percentage_basis_points(value)?,
        ),
        "engagementtime" | "totalengagementtime" => (
            AggregateMeasure::EngagementMilliseconds,
            parse_count(value)?,
        ),
        "deadclickcount"
        | "excessivescrollcount"
        | "excessivescroll"
        | "rageclickcount"
        | "quickbackclickcount"
        | "quickbackclick"
        | "scripterrorcount"
        | "errorclickcount" => (AggregateMeasure::MetricCount, parse_count(value)?),
        value_key
            if value_key.contains("percentage")
                || value_key.contains("percent")
                || value_key.contains("scrolldepth") =>
        {
            (
                AggregateMeasure::PercentageBasisPoints,
                parse_percentage_basis_points(value)?,
            )
        }
        _ => return None,
    };
    Some(AggregateValue {
        measure,
        value: parsed,
    })
}

fn parse_count(value: &Value) -> Option<u64> {
    match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse::<u64>().ok(),
        _ => None,
    }
}

fn parse_percentage_basis_points(value: &Value) -> Option<u64> {
    let raw = match value {
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        _ => return None,
    };
    let (whole, fraction) = raw.split_once('.').unwrap_or((&raw, ""));
    let whole = whole.parse::<u64>().ok()?;
    let fraction_digits = fraction
        .bytes()
        .take(2)
        .filter(u8::is_ascii_digit)
        .map(|byte| u64::from(byte - b'0'))
        .collect::<Vec<_>>();
    if fraction_digits.len() != fraction.len().min(2) || whole > 100 {
        return None;
    }
    let fraction_hundredths = match fraction_digits.as_slice() {
        [] => 0,
        [digit] => *digit * 10,
        [tens, ones] => *tens * 10 + *ones,
        _ => return None,
    };
    let result = whole
        .saturating_mul(100)
        .saturating_add(fraction_hundredths);
    (result <= 10_000).then_some(result)
}

fn scan_sensitive_metadata(value: &Value, redactions: &mut RedactionSummary) {
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| scan_sensitive_metadata(value, redactions)),
        Value::Object(object) => {
            for (key, value) in object {
                let normalized = key.to_ascii_lowercase().replace(['_', '-', ' '], "");
                let is_safe_aggregate = matches!(
                    normalized.as_str(),
                    "totalsessioncount"
                        | "totalbotsessioncount"
                        | "distantusercount"
                        | "pagespersessionpercentage"
                        | "engagementtime"
                        | "totalengagementtime"
                        | "deadclickcount"
                        | "excessivescrollcount"
                        | "excessivescroll"
                        | "rageclickcount"
                        | "quickbackclickcount"
                        | "quickbackclick"
                        | "scripterrorcount"
                        | "errorclickcount"
                );
                if !is_safe_aggregate {
                    if normalized.contains("url") {
                        redactions.url_values = redactions.url_values.saturating_add(1);
                    }
                    if normalized.contains("pagetitle") || normalized == "title" {
                        redactions.page_title_values =
                            redactions.page_title_values.saturating_add(1);
                    }
                    if normalized.contains("campaign") {
                        redactions.campaign_values = redactions.campaign_values.saturating_add(1);
                    }
                    if normalized.contains("custom") || normalized.contains("identifier") {
                        redactions.custom_identifier_values =
                            redactions.custom_identifier_values.saturating_add(1);
                    }
                    if normalized.contains("visitor") {
                        redactions.visitor_values = redactions.visitor_values.saturating_add(1);
                    }
                    if normalized.contains("sessionid") || normalized.contains("sessiontoken") {
                        redactions.session_values = redactions.session_values.saturating_add(1);
                    }
                }
                scan_sensitive_metadata(value, redactions);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn contains_pagination_marker(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_pagination_marker),
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "nextpagetoken"
                    | "pagetoken"
                    | "continuationtoken"
                    | "hasmore"
                    | "istruncated"
                    | "truncated"
                    | "offset"
                    | "page"
            ) || contains_pagination_marker(value)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn compute_response_digest(
    request_digest: &Digest,
    provenance: ProviderProvenance,
    status: ResultStatus,
    error: Option<ProviderErrorKind>,
    metrics: &[MetricEvidence],
    redactions: &RedactionSummary,
    rows: u16,
    provider_digest: &Digest,
) -> Digest {
    let safe_payload = serde_json::to_string(&(metrics, redactions))
        .expect("typed Clarity evidence is serializable");
    Digest::from_fields(
        "clarity-response/v1",
        &[
            request_digest.as_str().to_owned(),
            format!("{provenance:?}"),
            format!("{status:?}"),
            error.map_or_else(|| "none".to_owned(), |error| format!("{error:?}")),
            safe_payload,
            rows.to_string(),
            provider_digest.as_str().to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Default)]
pub struct RecordingClarityTransport {
    requests: Vec<ClarityDataExportGetRequest>,
    responses: VecDeque<Result<ClarityHttpResponse, ClarityTransportError>>,
}

impl RecordingClarityTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: Result<ClarityHttpResponse, ClarityTransportError>) {
        self.responses.push_back(response);
    }

    pub fn push_json(&mut self, body: impl Into<String>) {
        self.push_response(Ok(ClarityHttpResponse::ok(body)));
    }

    pub fn requests(&self) -> &[ClarityDataExportGetRequest] {
        &self.requests
    }

    pub const fn call_count(&self) -> usize {
        self.requests.len()
    }
}

impl ClarityDataExportTransport for RecordingClarityTransport {
    fn get(
        &mut self,
        request: &ClarityDataExportGetRequest,
    ) -> Result<ClarityHttpResponse, ClarityTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(ClarityTransportError::Transport))
    }
}

pub type FakeClarityTransport = RecordingClarityTransport;
pub type FixtureClarityTransport = RecordingClarityTransport;

#[derive(Clone, Debug)]
pub struct LoopbackClarityTransport {
    body: String,
    requests: Vec<ClarityDataExportGetRequest>,
}

impl LoopbackClarityTransport {
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[ClarityDataExportGetRequest] {
        &self.requests
    }
}

impl ClarityDataExportTransport for LoopbackClarityTransport {
    fn get(
        &mut self,
        request: &ClarityDataExportGetRequest,
    ) -> Result<ClarityHttpResponse, ClarityTransportError> {
        self.requests.push(request.clone());
        Ok(ClarityHttpResponse::ok(self.body.clone()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl ClarityDataExportTransport for BlockedEnvTransport {
    fn get(
        &mut self,
        _request: &ClarityDataExportGetRequest,
    ) -> Result<ClarityHttpResponse, ClarityTransportError> {
        Err(ClarityTransportError::BlockedEnv)
    }
}

#[cfg(test)]
mod provider_unit_tests {
    use super::parse_percentage_basis_points;
    use serde_json::json;

    #[test]
    fn percentages_are_stored_as_deterministic_basis_points() {
        assert_eq!(parse_percentage_basis_points(&json!(1.0931)), Some(109));
        assert_eq!(parse_percentage_basis_points(&json!(100)), Some(10_000));
        assert_eq!(parse_percentage_basis_points(&json!(101)), None);
    }
}
