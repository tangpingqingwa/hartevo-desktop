use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AdoptionMetric, Digest, EvidenceState, MAX_RESPONSE_BYTES, MAX_ROWS, ModelError,
    PendoAggregate, PendoAggregateBucket, PendoProductUsageScope, PendoReadProjection,
    PendoReadReceipt, PendoReportMetadata, PendoUsageRequest, ProviderErrorKind,
    ProviderProvenance, RedactionSummary, TargetKind, Timestamp, canonical_digest,
};

pub const PENDO_API_ORIGIN: &str = "https://app.pendo.io";
pub const PENDO_AGGREGATION_PATH: &str = "/api/v1/aggregation";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PendoHttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
}

impl PendoHttpMethod {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoReadRequest {
    pub origin: String,
    pub method: PendoHttpMethod,
    pub path: String,
    pub projection: PendoReadProjection,
    pub target_kind: TargetKind,
    pub target_digest: Digest,
    pub application_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub requested_at: Timestamp,
    pub body_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl PendoReadRequest {
    pub fn new(
        scope: &PendoProductUsageScope,
        request: &PendoUsageRequest,
        secret_reference_digest: Digest,
    ) -> Result<Self, ModelError> {
        request.validate(scope)?;
        if secret_reference_digest.len() != 64 {
            return Err(ModelError::InvalidDigest);
        }
        let (method, path, body_digest) = match request.projection() {
            PendoReadProjection::Aggregate { metric } => (
                PendoHttpMethod::Post,
                PENDO_AGGREGATION_PATH.to_owned(),
                Some(canonical_digest(&(
                    scope.subscription().digest(),
                    scope.application().digest(),
                    scope.account().digest(),
                    scope.visitor_kind(),
                    scope.target(),
                    scope.segment(),
                    scope.time_window(),
                    metric,
                ))),
            ),
            PendoReadProjection::ReportMetadata { target } => (
                PendoHttpMethod::Get,
                target.metadata_path().to_owned(),
                None,
            ),
        };
        let mut read_request = Self {
            origin: PENDO_API_ORIGIN.to_owned(),
            method,
            path,
            projection: request.projection().clone(),
            target_kind: scope.target().kind(),
            target_digest: scope.target().id_digest().clone(),
            application_digest: scope.application().digest().clone(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest,
            requested_at: request.requested_at(),
            body_digest,
            request_digest: String::new(),
        };
        read_request.request_digest = read_request.digest();
        Ok(read_request)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.origin,
            self.method,
            &self.path,
            &self.projection,
            self.target_kind,
            &self.target_digest,
            &self.application_digest,
            &self.scope_digest,
            &self.consent_digest,
            &self.secret_reference_digest,
            self.requested_at,
            &self.body_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        if self.origin != PENDO_API_ORIGIN || self.request_digest != self.digest() {
            return false;
        }
        match (&self.method, &self.path, &self.projection) {
            (PendoHttpMethod::Post, path, PendoReadProjection::Aggregate { metric }) => {
                path == PENDO_AGGREGATION_PATH && metric.supports(self.target_kind)
            }
            (PendoHttpMethod::Get, path, PendoReadProjection::ReportMetadata { target }) => {
                *target == self.target_kind && path == target.metadata_path()
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn receipt(
        &self,
        response_digest: Digest,
        status_code: Option<u16>,
        bytes: usize,
    ) -> PendoReadReceipt {
        PendoReadReceipt {
            method: self.method.label().to_owned(),
            path: self.path.clone(),
            request_digest: self.request_digest.clone(),
            response_digest,
            status_code,
            response_bytes: bytes,
            secret_reference_digest: self.secret_reference_digest.clone(),
            body_retained: false,
        }
    }

    #[must_use]
    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PendoHttpResponse {
    status_code: u16,
    body: String,
}

impl fmt::Debug for PendoHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendoHttpResponse")
            .field("status_code", &self.status_code)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl PendoHttpResponse {
    #[must_use]
    pub fn new(status_code: u16, body: impl Into<String>) -> Self {
        Self {
            status_code,
            body: body.into(),
        }
    }

    #[must_use]
    pub fn ok(body: impl Into<String>) -> Self {
        Self::new(200, body)
    }

    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PendoTransportError {
    #[error("native Pendo transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("recorded Pendo transport expired")]
    Expired,
    #[error("recorded Pendo transport timed out")]
    Timeout,
    #[error("Pendo transport is unavailable")]
    Unavailable,
    #[error("recorded Pendo transport has no response")]
    Exhausted,
}

pub trait PendoTransport: fmt::Debug {
    fn read(
        &mut self,
        request: &PendoReadRequest,
    ) -> Result<PendoHttpResponse, PendoTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub origin: String,
    pub allowlisted_read_paths: Vec<String>,
    pub allowlisted_writes: Vec<String>,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub raw_response_body: bool,
    pub raw_visitor_rows: bool,
    pub raw_pii: bool,
    pub guide_mutation: bool,
    pub segment_mutation: bool,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Pendo provider definition drifted from the Layer-1 allowlist")]
    Drift,
}

impl PendoProviderDefinition {
    pub fn new() -> Result<Self, ProviderDefinitionError> {
        let definition = Self {
            id: crate::PENDO_PRODUCT_USAGE_RESULT_PROVIDER_ID.to_owned(),
            version: crate::PENDO_PRODUCT_USAGE_RESULT_PROVIDER_VERSION.to_owned(),
            api_revision: crate::PENDO_PRODUCT_USAGE_RESULT_API_REVISION.to_owned(),
            origin: PENDO_API_ORIGIN.to_owned(),
            allowlisted_read_paths: vec![
                PENDO_AGGREGATION_PATH.to_owned(),
                TargetKind::Page.metadata_path().to_owned(),
                TargetKind::Feature.metadata_path().to_owned(),
                TargetKind::Guide.metadata_path().to_owned(),
            ],
            allowlisted_writes: Vec::new(),
            native: false,
            connected: false,
            first_party: false,
            raw_response_body: false,
            raw_visitor_rows: false,
            raw_pii: false,
            guide_mutation: false,
            segment_mutation: false,
        };
        if definition.allowlisted_read_paths.len() != 4
            || !definition.allowlisted_writes.is_empty()
            || definition.native
            || definition.connected
            || definition.first_party
            || definition.raw_response_body
            || definition.raw_visitor_rows
            || definition.raw_pii
            || definition.guide_mutation
            || definition.segment_mutation
        {
            return Err(ProviderDefinitionError::Drift);
        }
        Ok(definition)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PendoProviderError {
    #[error("Pendo provider definition drifted")]
    DefinitionDrift,
    #[error("Pendo request is outside the read allowlist")]
    RequestNotAllowlisted,
    #[error("Pendo response exceeded the Layer-1 response bound")]
    ResponseTooLarge { response_bytes: usize },
    #[error("Pendo response contains too many rows or buckets")]
    TooManyRows,
    #[error("Pendo response contains a forbidden visitor, PII, or event field")]
    PrivacyViolation,
    #[error("Pendo response is malformed")]
    MalformedResponse,
    #[error("Pendo returned HTTP status {status_code}")]
    HttpStatus {
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Pendo transport failed for the bounded request")]
    Transport {
        error: PendoTransportError,
        request_digest: Digest,
    },
}

impl PendoProviderError {
    #[must_use]
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::DefinitionDrift | Self::RequestNotAllowlisted | Self::MalformedResponse => {
                ProviderErrorKind::MalformedResponse
            }
            Self::ResponseTooLarge { .. } => ProviderErrorKind::ResponseTooLarge,
            Self::TooManyRows => ProviderErrorKind::TooManyRows,
            Self::PrivacyViolation => ProviderErrorKind::PrivacyViolation,
            Self::HttpStatus { status_code, .. } => match status_code {
                401 => ProviderErrorKind::Unauthorized,
                403 => ProviderErrorKind::Forbidden,
                404 => ProviderErrorKind::NotFound,
                429 => ProviderErrorKind::RateLimited,
                _ => ProviderErrorKind::MalformedResponse,
            },
            Self::Transport { error, .. } => match error {
                PendoTransportError::BlockedEnv => ProviderErrorKind::BlockedEnv,
                PendoTransportError::Expired
                | PendoTransportError::Timeout
                | PendoTransportError::Unavailable
                | PendoTransportError::Exhausted => ProviderErrorKind::Transport,
            },
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> Option<&Digest> {
        match self {
            Self::Transport { request_digest, .. } => Some(request_digest),
            _ => None,
        }
    }

    #[must_use]
    pub fn response_metadata(&self) -> Option<(u16, &Digest, usize)> {
        match self {
            Self::HttpStatus {
                status_code,
                response_digest,
                response_bytes,
            } => Some((*status_code, response_digest, *response_bytes)),
            Self::ResponseTooLarge { response_bytes } => {
                Some((0, &EMPTY_RESPONSE_DIGEST, *response_bytes))
            }
            _ => None,
        }
    }
}

static EMPTY_RESPONSE_DIGEST: Digest = String::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendoPayload {
    Aggregate(PendoAggregate),
    ReportMetadata(PendoReportMetadata),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendoProviderRead {
    pub request: PendoReadRequest,
    pub payload: PendoPayload,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub status_code: u16,
    pub redactions: RedactionSummary,
    pub as_of: Option<Timestamp>,
    pub provenance: ProviderProvenance,
}

#[derive(Debug)]
pub struct PendoProvider<T> {
    transport: T,
    definition: PendoProviderDefinition,
    provenance: ProviderProvenance,
}

impl<T: PendoTransport> PendoProvider<T> {
    pub fn new(
        transport: T,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = PendoProviderDefinition::new()?;
        if provenance == ProviderProvenance::BlockedEnv && definition.native {
            return Err(ProviderDefinitionError::Drift);
        }
        Ok(Self {
            transport,
            definition,
            provenance,
        })
    }

    pub fn read(
        &mut self,
        request: &PendoReadRequest,
    ) -> Result<PendoProviderRead, PendoProviderError> {
        if self.definition.digest()
            != PendoProviderDefinition::new()
                .map_err(|_| PendoProviderError::DefinitionDrift)?
                .digest()
        {
            return Err(PendoProviderError::DefinitionDrift);
        }
        if !request.is_allowlisted() {
            return Err(PendoProviderError::RequestNotAllowlisted);
        }
        let response =
            self.transport
                .read(request)
                .map_err(|error| PendoProviderError::Transport {
                    error,
                    request_digest: request.request_digest.clone(),
                })?;
        let response_bytes = response.body.len();
        let response_digest = crate::sha256_digest(response.body.as_bytes());
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(PendoProviderError::ResponseTooLarge { response_bytes });
        }
        if !(200..300).contains(&response.status_code) {
            return Err(PendoProviderError::HttpStatus {
                status_code: response.status_code,
                response_digest,
                response_bytes,
            });
        }
        let (payload, redactions, as_of) =
            parse_payload(&response.body, request).map_err(|error| match error {
                ParseError::TooManyRows => PendoProviderError::TooManyRows,
                ParseError::PrivacyViolation => PendoProviderError::PrivacyViolation,
                ParseError::Malformed => PendoProviderError::MalformedResponse,
            })?;
        Ok(PendoProviderRead {
            request: request.clone(),
            payload,
            response_digest,
            response_bytes,
            status_code: response.status_code,
            redactions,
            as_of,
            provenance: self.provenance,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &PendoProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    #[must_use]
    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

#[derive(Debug)]
pub struct RecordingPendoTransport {
    responses: VecDeque<Result<PendoHttpResponse, PendoTransportError>>,
    requests: Vec<PendoReadRequest>,
}

impl RecordingPendoTransport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: Result<PendoHttpResponse, PendoTransportError>) {
        self.responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[PendoReadRequest] {
        &self.requests
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.requests.len()
    }
}

impl Default for RecordingPendoTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl PendoTransport for RecordingPendoTransport {
    fn read(
        &mut self,
        request: &PendoReadRequest,
    ) -> Result<PendoHttpResponse, PendoTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(PendoTransportError::Exhausted))
    }
}

#[derive(Clone, Debug)]
pub struct FixturePendoTransport {
    response: PendoHttpResponse,
}

impl FixturePendoTransport {
    #[must_use]
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            response: PendoHttpResponse::ok(body),
        }
    }
}

impl Default for FixturePendoTransport {
    fn default() -> Self {
        Self::new(r#"{"rows":[]}"#)
    }
}

impl PendoTransport for FixturePendoTransport {
    fn read(
        &mut self,
        _request: &PendoReadRequest,
    ) -> Result<PendoHttpResponse, PendoTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Eq, PartialEq)]
pub struct LoopbackPendoTransport {
    body: String,
    requests: Vec<PendoReadRequest>,
}

impl fmt::Debug for LoopbackPendoTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackPendoTransport")
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl LoopbackPendoTransport {
    #[must_use]
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[PendoReadRequest] {
        &self.requests
    }
}

impl PendoTransport for LoopbackPendoTransport {
    fn read(
        &mut self,
        request: &PendoReadRequest,
    ) -> Result<PendoHttpResponse, PendoTransportError> {
        self.requests.push(request.clone());
        Ok(PendoHttpResponse::ok(self.body.clone()))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvPendoTransport;

impl PendoTransport for BlockedEnvPendoTransport {
    fn read(
        &mut self,
        _request: &PendoReadRequest,
    ) -> Result<PendoHttpResponse, PendoTransportError> {
        Err(PendoTransportError::BlockedEnv)
    }
}

pub type FakePendoTransport = RecordingPendoTransport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseError {
    TooManyRows,
    PrivacyViolation,
    Malformed,
}

fn parse_payload(
    body: &str,
    request: &PendoReadRequest,
) -> Result<(PendoPayload, RedactionSummary, Option<Timestamp>), ParseError> {
    let mut redactions = RedactionSummary {
        raw_response_body_dropped: true,
        ..RedactionSummary::default()
    };
    let value = if body.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str::<Value>(body).map_err(|_| ParseError::Malformed)?
    };
    reject_forbidden_fields(&value)?;
    let as_of = extract_timestamp(&value);
    match &request.projection {
        PendoReadProjection::Aggregate { metric } => {
            let aggregate = parse_aggregate(&value, metric.clone(), &mut redactions)?;
            Ok((PendoPayload::Aggregate(aggregate), redactions, as_of))
        }
        PendoReadProjection::ReportMetadata { target } => {
            let metadata = parse_metadata(
                &value,
                *target,
                &request.target_digest,
                &request.application_digest,
                &mut redactions,
            )?;
            Ok((PendoPayload::ReportMetadata(metadata), redactions, as_of))
        }
    }
}

fn parse_aggregate(
    value: &Value,
    metric: AdoptionMetric,
    redactions: &mut RedactionSummary,
) -> Result<PendoAggregate, ParseError> {
    let rows = row_values(value);
    if rows.len() > MAX_ROWS {
        return Err(ParseError::TooManyRows);
    }
    let partial = value
        .get("partial")
        .and_then(Value::as_bool)
        .or_else(|| value.get("isPartial").and_then(Value::as_bool))
        .unwrap_or(false);
    let root_rate = value
        .get("rate")
        .or_else(|| value.get("adoptionRate"))
        .map(parse_rate_bps)
        .transpose()
        .map_err(|_| ParseError::Malformed)?;
    let mut buckets = Vec::with_capacity(rows.len());
    let mut reported_rate_bps = root_rate;
    for (index, row) in rows.iter().enumerate() {
        let object = row.as_object().ok_or(ParseError::Malformed)?;
        let bucket = object
            .get("bucket")
            .or_else(|| object.get("date"))
            .or_else(|| object.get("period"))
            .or_else(|| object.get("timestamp"))
            .or_else(|| object.get("key"))
            .and_then(value_as_text)
            .unwrap_or_else(|| format!("row-{index}"));
        let value = object
            .get("value")
            .or_else(|| object.get("count"))
            .or_else(|| object.get("total"))
            .or_else(|| object.get("views"))
            .or_else(|| object.get("clicks"))
            .or_else(|| object.get("uniqueVisitors"))
            .or_else(|| object.get("uniqueAccounts"))
            .map(parse_count)
            .transpose()
            .map_err(|_| ParseError::Malformed)?
            .unwrap_or(0);
        if value == 0 && reported_rate_bps.is_none() {
            let rate = object
                .get("rate")
                .or_else(|| object.get("adoptionRate"))
                .map(parse_rate_bps)
                .transpose()
                .map_err(|_| ParseError::Malformed)?;
            reported_rate_bps = rate;
        }
        let bucket = PendoAggregateBucket::new(bucket, value).map_err(|_| ParseError::Malformed)?;
        redactions.labels_digested = redactions.labels_digested.saturating_add(1);
        buckets.push(bucket);
    }
    PendoAggregate::new(metric, buckets, reported_rate_bps, partial).map_err(|error| match error {
        ModelError::ResponseTooManyRows => ParseError::TooManyRows,
        _ => ParseError::Malformed,
    })
}

fn parse_metadata(
    value: &Value,
    target: TargetKind,
    target_digest: &Digest,
    application_digest: &Digest,
    redactions: &mut RedactionSummary,
) -> Result<PendoReportMetadata, ParseError> {
    let object = value
        .get("metadata")
        .or_else(|| value.get("result"))
        .unwrap_or(value)
        .as_object()
        .ok_or(ParseError::Malformed)?;
    if object.len() > 16 {
        return Err(ParseError::TooManyRows);
    }
    let label_digest = object
        .get("name")
        .or_else(|| object.get("label"))
        .and_then(value_as_text)
        .map(|value| {
            redactions.labels_digested = redactions.labels_digested.saturating_add(1);
            crate::sha256_digest(format!("pendo-label/v1|{value}").as_bytes())
        });
    let version_digest = object
        .get("version")
        .and_then(value_as_text)
        .map(|value| crate::sha256_digest(format!("pendo-version/v1|{value}").as_bytes()));
    let updated_at = object
        .get("updatedAt")
        .or_else(|| object.get("lastUpdatedAt"))
        .map(parse_timestamp)
        .transpose()
        .map_err(|_| ParseError::Malformed)?;
    PendoReportMetadata::new(
        target,
        target_digest.clone(),
        application_digest.clone(),
        label_digest,
        version_digest,
        updated_at,
        object.len() as u16,
    )
    .map_err(|_| ParseError::Malformed)
}

fn row_values(value: &Value) -> Vec<Value> {
    if let Some(array) = value.as_array() {
        return array.clone();
    }
    for key in ["rows", "data", "results", "items"] {
        if let Some(array) = value.get(key).and_then(Value::as_array) {
            return array.clone();
        }
    }
    if value
        .as_object()
        .is_some_and(|object| object.contains_key("value") || object.contains_key("count"))
    {
        vec![value.clone()]
    } else {
        Vec::new()
    }
}

fn reject_forbidden_fields(value: &Value) -> Result<(), ParseError> {
    if let Some(object) = value.as_object() {
        for key in object.keys() {
            let normalized = key.to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "visitor"
                    | "visitors"
                    | "visitorid"
                    | "visitor_id"
                    | "email"
                    | "emails"
                    | "accountemail"
                    | "accountid"
                    | "account_id"
                    | "userid"
                    | "user_id"
                    | "event"
                    | "events"
                    | "eventpayload"
                    | "event_payload"
                    | "rawevent"
                    | "raw_event"
            ) {
                return Err(ParseError::PrivacyViolation);
            }
        }
        for child in object.values() {
            reject_forbidden_fields(child)?;
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            reject_forbidden_fields(child)?;
        }
    }
    Ok(())
}

fn value_as_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| value.as_i64().map(|number| number.to_string()))
}

fn parse_count(value: &Value) -> Result<u64, ()> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value.as_str().ok_or(())?.parse::<u64>().map_err(|_| ())
}

fn parse_rate_bps(value: &Value) -> Result<u16, ()> {
    let rate = if let Some(number) = value.as_f64() {
        number
    } else {
        value.as_str().ok_or(())?.parse::<f64>().map_err(|_| ())?
    };
    if !rate.is_finite() || !(0.0..=1.0).contains(&rate) {
        return Err(());
    }
    let basis_points = (rate * 10_000.0).round();
    if !(0.0..=10_000.0).contains(&basis_points) {
        return Err(());
    }
    Ok(basis_points as u16)
}

fn parse_timestamp(value: &Value) -> Result<Timestamp, ()> {
    let value = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
        .ok_or(())?;
    Timestamp::new(value).map_err(|_| ())
}

fn extract_timestamp(value: &Value) -> Option<Timestamp> {
    value
        .get("asOf")
        .or_else(|| value.get("observedAt"))
        .or_else(|| value.get("updatedAt"))
        .and_then(|value| parse_timestamp(value).ok())
}

impl From<PendoProviderError> for ProviderErrorKind {
    fn from(error: PendoProviderError) -> Self {
        error.kind()
    }
}

impl From<PendoProviderError> for EvidenceState {
    fn from(error: PendoProviderError) -> Self {
        match error.kind() {
            ProviderErrorKind::BlockedEnv
            | ProviderErrorKind::Unauthorized
            | ProviderErrorKind::Forbidden => Self::AccessLost,
            ProviderErrorKind::RateLimited => Self::RateLimited,
            ProviderErrorKind::NotFound
            | ProviderErrorKind::ResponseTooLarge
            | ProviderErrorKind::TooManyRows
            | ProviderErrorKind::PrivacyViolation
            | ProviderErrorKind::MalformedResponse
            | ProviderErrorKind::Transport => Self::ProviderUnknown,
        }
    }
}
