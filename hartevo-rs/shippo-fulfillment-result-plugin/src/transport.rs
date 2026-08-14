//! Bounded GET-only transports for the Shippo read seam.

use std::{collections::VecDeque, fmt, time::Duration as StdDuration};

use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::model::{
    AccountId, CarrierCode, Digest, ProviderRevision, ProviderTrackingStatus, ShipmentId,
    ShippoObjectState, ShippoReadRequest, ShippoShipmentPayload, ShippoTrackingEventPayload,
    ShippoTrackingPayload, ShippoTransactionPayload, TrackingNumber, TransactionId,
    TransactionStatus, digest_serializable, sha256_digest, validate_api_version,
};
use crate::provider::ShippoCredential;
use crate::{
    SHIPPO_API_ORIGIN, SHIPPO_API_VERSION, SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT,
    SHIPPO_MAX_CARRIER_EVIDENCE, SHIPPO_MAX_PAGES, SHIPPO_MAX_RESPONSE_BYTES, SHIPPO_MAX_RETRIES,
    SHIPPO_MAX_TRACKING_EVENTS, SHIPPO_PROVIDER_REVISION, ShippoFulfillmentError,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    ProductionRead,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShippoTransportError {
    #[error("BLOCKED_ENV: native Shippo transport is unavailable")]
    BlockedEnv,
    #[error("Shippo credential is unavailable")]
    CredentialUnavailable,
    #[error("Shippo transport request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Shippo response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Shippo response could not be decoded: {0}")]
    Decode(String),
    #[error("Shippo transport failed: {0}")]
    Transport(String),
    #[error("Shippo access was lost")]
    AccessLost,
    #[error("Shippo rate limit requires retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("Shippo transport response queue is exhausted")]
    QueueExhausted,
    #[error("Shippo response did not match its request")]
    RequestResponseMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_tracking_events: usize,
    pub max_carrier_evidence: usize,
    pub max_pages: u16,
    pub max_retries: u8,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: SHIPPO_MAX_RESPONSE_BYTES,
            max_tracking_events: SHIPPO_MAX_TRACKING_EVENTS,
            max_carrier_evidence: SHIPPO_MAX_CARRIER_EVIDENCE,
            max_pages: SHIPPO_MAX_PAGES,
            max_retries: SHIPPO_MAX_RETRIES,
        }
    }
}

impl RequestBounds {
    pub fn from_request(request: &ShippoReadRequest) -> Result<Self, ShippoTransportError> {
        request
            .validate()
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        Ok(Self {
            max_response_bytes: SHIPPO_MAX_RESPONSE_BYTES,
            max_tracking_events: request.max_tracking_events,
            max_carrier_evidence: request.max_carrier_evidence,
            max_pages: SHIPPO_MAX_PAGES,
            max_retries: request.max_retries,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ShippoEndpoint {
    Shipment {
        shipment_id: ShipmentId,
    },
    Transaction {
        transaction_id: TransactionId,
    },
    Tracking {
        carrier: CarrierCode,
        tracking_number: TrackingNumber,
    },
}

impl ShippoEndpoint {
    pub fn shipment(shipment_id: impl Into<String>) -> Result<Self, ShippoTransportError> {
        let shipment_id = ShipmentId::parse(shipment_id.into())
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        Ok(Self::Shipment { shipment_id })
    }

    pub fn transaction(transaction_id: impl Into<String>) -> Result<Self, ShippoTransportError> {
        let transaction_id = TransactionId::parse(transaction_id.into())
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        Ok(Self::Transaction { transaction_id })
    }

    pub fn tracking(
        carrier: impl Into<String>,
        tracking_number: impl Into<String>,
    ) -> Result<Self, ShippoTransportError> {
        let carrier = CarrierCode::parse(carrier.into().to_ascii_lowercase())
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        let tracking_number = TrackingNumber::parse(tracking_number.into())
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        Ok(Self::Tracking {
            carrier,
            tracking_number,
        })
    }

    pub fn path_and_query(&self) -> Result<String, ShippoTransportError> {
        fn segment(value: &str, field: &str) -> Result<String, ShippoTransportError> {
            if value.is_empty()
                || value
                    .bytes()
                    .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'\\'))
            {
                return Err(ShippoTransportError::InvalidRequest(format!(
                    "{field} is not a safe path segment"
                )));
            }
            Ok(value.to_owned())
        }
        match self {
            Self::Shipment { shipment_id } => Ok(format!(
                "/shipments/{}/",
                segment(shipment_id.as_str(), "shipment id")?
            )),
            Self::Transaction { transaction_id } => Ok(format!(
                "/transactions/{}/",
                segment(transaction_id.as_str(), "transaction id")?
            )),
            Self::Tracking {
                carrier,
                tracking_number,
            } => Ok(format!(
                "/tracks/{}/{}",
                segment(carrier.as_str(), "carrier")?,
                segment(tracking_number.as_str(), "tracking number")?
            )),
        }
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Shipment { .. } => "shipment",
            Self::Transaction { .. } => "transaction",
            Self::Tracking { .. } => "tracking",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShippoHttpRequest {
    pub method: String,
    pub endpoint: ShippoEndpoint,
    pub api_version: String,
    pub max_response_bytes: usize,
    pub retry_index: u8,
    pub cursor_digest: Option<Digest>,
    pub window_digest: Option<Digest>,
    request_digest: Digest,
}

impl ShippoHttpRequest {
    pub fn new(
        endpoint: ShippoEndpoint,
        request: &ShippoReadRequest,
        retry_index: u8,
    ) -> Result<Self, ShippoTransportError> {
        let bounds = RequestBounds::from_request(request)?;
        if retry_index > bounds.max_retries {
            return Err(ShippoTransportError::InvalidRequest(
                "retry index exceeds the request bound".to_owned(),
            ));
        }
        let cursor_digest = request
            .cursor
            .as_ref()
            .map(|cursor| sha256_digest(cursor.as_bytes()));
        let window_digest = match (request.window_start, request.window_end) {
            (Some(start), Some(end)) => Some(
                digest_serializable(&(start, end))
                    .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?,
            ),
            (None, None) => None,
            _ => {
                return Err(ShippoTransportError::InvalidRequest(
                    "time window must contain both endpoints".to_owned(),
                ));
            }
        };
        let mut result = Self {
            method: "GET".to_owned(),
            endpoint,
            api_version: SHIPPO_API_VERSION.to_owned(),
            max_response_bytes: bounds.max_response_bytes,
            retry_index,
            cursor_digest,
            window_digest,
            request_digest: sha256_digest(b"uninitialized"),
        };
        result.request_digest = digest_serializable(&(
            &result.method,
            &result.endpoint,
            &result.api_version,
            result.max_response_bytes,
            result.retry_index,
            &result.cursor_digest,
            &result.window_digest,
        ))
        .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        Ok(result)
    }

    pub fn path_and_query(&self) -> Result<String, ShippoTransportError> {
        self.endpoint.path_and_query()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShippoResponseBody {
    Shipment(ShippoShipmentPayload),
    Transaction(ShippoTransactionPayload),
    Tracking(ShippoTrackingPayload),
    Empty,
}

impl ShippoResponseBody {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Shipment(_) => "shipment",
            Self::Transaction(_) => "transaction",
            Self::Tracking(_) => "tracking",
            Self::Empty => "empty",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShippoHttpResponse {
    pub status: u16,
    pub api_version: String,
    pub body: ShippoResponseBody,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub retry_after_seconds: Option<u64>,
    request_digest: Digest,
}

impl ShippoHttpResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ShippoHttpRequest,
        status: u16,
        api_version: impl Into<String>,
        body: ShippoResponseBody,
        response_size: usize,
        response_digest: Digest,
        provider_revision: ProviderRevision,
        retry_after_seconds: Option<u64>,
    ) -> Result<Self, ShippoTransportError> {
        if response_size > request.max_response_bytes {
            return Err(ShippoTransportError::ResponseTooLarge {
                size: response_size,
            });
        }
        if response_digest.as_str().len() != 64 {
            return Err(ShippoTransportError::InvalidRequest(
                "response digest is not SHA-256".to_owned(),
            ));
        }
        Ok(Self {
            status,
            api_version: api_version.into(),
            body,
            response_size,
            response_digest,
            provider_revision,
            retry_after_seconds,
            request_digest: request.request_digest.clone(),
        })
    }

    pub fn from_body(
        request: &ShippoHttpRequest,
        status: u16,
        body: ShippoResponseBody,
        response_size: usize,
        body_digest: Digest,
    ) -> Result<Self, ShippoTransportError> {
        let provider_revision = ProviderRevision::parse(SHIPPO_PROVIDER_REVISION)
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        Self::new(
            request,
            status,
            SHIPPO_API_VERSION,
            body,
            response_size,
            body_digest,
            provider_revision,
            None,
        )
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

pub trait ShippoTransport: fmt::Debug {
    fn execute(
        &mut self,
        credential: &ShippoCredential,
        request: &ShippoHttpRequest,
    ) -> Result<ShippoHttpResponse, ShippoTransportError>;

    fn provenance(&self) -> TransportProvenance;
}

pub struct RecordingShippoTransport {
    responses: VecDeque<Result<ShippoHttpResponse, ShippoTransportError>>,
    requests: Vec<ShippoHttpRequest>,
    provenance: TransportProvenance,
}

impl fmt::Debug for RecordingShippoTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingShippoTransport")
            .field("remaining_responses", &self.responses.len())
            .field("requests", &self.requests.len())
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl RecordingShippoTransport {
    pub fn new<I>(responses: I, provenance: TransportProvenance) -> Self
    where
        I: IntoIterator<Item = Result<ShippoHttpResponse, ShippoTransportError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance,
        }
    }

    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<ShippoHttpResponse, ShippoTransportError>>,
    {
        Self::new(responses, TransportProvenance::Fixture)
    }

    pub fn recording<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<ShippoHttpResponse, ShippoTransportError>>,
    {
        Self::new(responses, TransportProvenance::Recording)
    }

    pub fn loopback<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<ShippoHttpResponse, ShippoTransportError>>,
    {
        Self::new(responses, TransportProvenance::Loopback)
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(&mut self, response: Result<ShippoHttpResponse, ShippoTransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[ShippoHttpRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl ShippoTransport for RecordingShippoTransport {
    fn execute(
        &mut self,
        credential: &ShippoCredential,
        request: &ShippoHttpRequest,
    ) -> Result<ShippoHttpResponse, ShippoTransportError> {
        if credential.as_str().is_empty() {
            return Err(ShippoTransportError::CredentialUnavailable);
        }
        if request.method != "GET" || request.api_version != SHIPPO_API_VERSION {
            return Err(ShippoTransportError::InvalidRequest(
                "recording transport accepts only Shippo GET requests at the pinned API version"
                    .to_owned(),
            ));
        }
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(ShippoTransportError::QueueExhausted)??;
        if response.request_digest() != request.request_digest() {
            return Err(ShippoTransportError::RequestResponseMismatch);
        }
        Ok(response)
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

pub type FakeShippoTransport = RecordingShippoTransport;
pub type LoopbackShippoTransport = RecordingShippoTransport;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl ShippoTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _credential: &ShippoCredential,
        _request: &ShippoHttpRequest,
    ) -> Result<ShippoHttpResponse, ShippoTransportError> {
        Err(ShippoTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

/// Production read transport.  It can issue only the three GET endpoint
/// shapes represented by ShippoEndpoint; it never creates or mutates a
/// Shippo object and never retains the provider JSON after normalization.
pub struct ProductionShippoTransport {
    origin: String,
    agent: ureq::Agent,
}

impl fmt::Debug for ProductionShippoTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionShippoTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl ProductionShippoTransport {
    pub fn new(origin: impl Into<String>) -> Result<Self, ShippoFulfillmentError> {
        let origin = origin.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&origin).map_err(|error| {
            ShippoFulfillmentError::InvalidInput(format!("Shippo origin is invalid: {error}"))
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != ""
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ShippoFulfillmentError::InvalidInput(
                "Shippo origin must be HTTPS without credentials, path, or query".to_owned(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent(format!(
                "hartevo-shippo-fulfillment-result/{SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT}"
            ))
            .timeout_global(Some(StdDuration::from_secs(30)))
            .build()
            .into();
        Ok(Self { origin, agent })
    }

    pub fn shippo() -> Result<Self, ShippoFulfillmentError> {
        Self::new(SHIPPO_API_ORIGIN)
    }

    fn endpoint_url(&self, endpoint: &ShippoEndpoint) -> Result<String, ShippoTransportError> {
        let mut url = Url::parse(&self.origin)
            .map_err(|error| ShippoTransportError::Transport(error.to_string()))?;
        let relative = endpoint.path_and_query()?;
        let relative = Url::parse(&format!("https://placeholder.invalid{relative}"))
            .map_err(|error| ShippoTransportError::Transport(error.to_string()))?;
        url.set_path(relative.path());
        url.set_query(relative.query());
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        credential: &ShippoCredential,
        request: &ShippoHttpRequest,
    ) -> Result<ShippoHttpResponse, ShippoTransportError> {
        let url = self.endpoint_url(&request.endpoint)?;
        let response = self
            .agent
            .get(&url)
            .header(
                "Authorization",
                format!("ShippoToken {}", credential.as_str()),
            )
            .header("Accept", "application/json")
            .header("SHIPPO-API-VERSION", &request.api_version)
            .call()
            .map_err(classify_ureq_error)?;
        let status = response.status().as_u16();
        let response_limit = u64::try_from(request.max_response_bytes)
            .map_err(|error| ShippoTransportError::Transport(error.to_string()))?
            .saturating_add(1);
        let mut response = response;
        let body = response
            .body_mut()
            .with_config()
            .limit(response_limit)
            .read_to_string()
            .map_err(classify_ureq_error)?;
        let response_size = body.len();
        if response_size > request.max_response_bytes {
            return Err(ShippoTransportError::ResponseTooLarge {
                size: response_size,
            });
        }
        let response_digest = sha256_digest(body.as_bytes());
        let value = serde_json::from_str::<Value>(&body)
            .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
        let normalized_body = decode_body(&request.endpoint, &value)?;
        let provider_revision = ProviderRevision::parse(SHIPPO_PROVIDER_REVISION)
            .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
        let retry_after_seconds = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        ShippoHttpResponse::new(
            request,
            status,
            request.api_version.clone(),
            normalized_body,
            response_size,
            response_digest,
            provider_revision,
            retry_after_seconds,
        )
    }
}

impl ShippoTransport for ProductionShippoTransport {
    fn execute(
        &mut self,
        credential: &ShippoCredential,
        request: &ShippoHttpRequest,
    ) -> Result<ShippoHttpResponse, ShippoTransportError> {
        if credential.as_str().trim().is_empty()
            || credential.as_str().chars().any(char::is_control)
        {
            return Err(ShippoTransportError::CredentialUnavailable);
        }
        if request.method != "GET" {
            return Err(ShippoTransportError::InvalidRequest(
                "Shippo Layer 1 allows GET only".to_owned(),
            ));
        }
        validate_api_version(&request.api_version)
            .map_err(|error| ShippoTransportError::InvalidRequest(error.to_string()))?;
        self.get_json(credential, request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::ProductionRead
    }
}

fn classify_ureq_error(error: ureq::Error) -> ShippoTransportError {
    match error {
        ureq::Error::StatusCode(401 | 403) => ShippoTransportError::AccessLost,
        ureq::Error::StatusCode(429) => ShippoTransportError::RateLimited {
            retry_after_seconds: 1,
        },
        ureq::Error::StatusCode(status) => {
            ShippoTransportError::Transport(format!("Shippo returned HTTP status {status}"))
        }
        other => ShippoTransportError::Transport(other.to_string()),
    }
}

fn decode_body(
    endpoint: &ShippoEndpoint,
    value: &Value,
) -> Result<ShippoResponseBody, ShippoTransportError> {
    match endpoint {
        ShippoEndpoint::Shipment { .. } => parse_shipment(value).map(ShippoResponseBody::Shipment),
        ShippoEndpoint::Transaction { .. } => {
            parse_transaction(value).map(ShippoResponseBody::Transaction)
        }
        ShippoEndpoint::Tracking { .. } => parse_tracking(value).map(ShippoResponseBody::Tracking),
    }
}

fn parse_shipment(value: &Value) -> Result<ShippoShipmentPayload, ShippoTransportError> {
    let shipment_id = required_text(value, "object_id")?;
    let shipment_id = ShipmentId::parse(shipment_id)
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let account_id = optional_text(value, "account_id")?
        .map(AccountId::parse)
        .transpose()
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let object_state = optional_text(value, "object_state")?
        .or(optional_text(value, "status")?)
        .map(|status| match status.to_ascii_uppercase().as_str() {
            "VALID" | "SUCCESS" => ShippoObjectState::Valid,
            "INVALID" | "ERROR" => ShippoObjectState::Invalid,
            "PENDING" | "QUEUED" | "WAITING" => ShippoObjectState::Pending,
            _ => ShippoObjectState::Unknown,
        });
    let parcel_count = value
        .get("parcels")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if parcel_count > SHIPPO_MAX_TRACKING_EVENTS {
        return Err(ShippoTransportError::InvalidRequest(
            "shipment parcel count exceeds the bounded projection".to_owned(),
        ));
    }
    Ok(ShippoShipmentPayload {
        shipment_id,
        account_id,
        object_state,
        parcel_count,
        has_origin_address: value.get("address_from").is_some_and(Value::is_object),
        has_destination_address: value.get("address_to").is_some_and(Value::is_object),
        has_customs_data: value.get("customs_declaration").is_some()
            || value.get("customs_items").is_some(),
        revision: positive_revision(value),
    })
}

fn parse_transaction(value: &Value) -> Result<ShippoTransactionPayload, ShippoTransportError> {
    let transaction_id = required_text(value, "object_id")?;
    let transaction_id = TransactionId::parse(transaction_id)
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let account_id = optional_text(value, "account_id")?
        .map(AccountId::parse)
        .transpose()
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let shipment_id = optional_text(value, "shipment")?
        .or(optional_text(value, "shipment_id")?)
        .map(ShipmentId::parse)
        .transpose()
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let status = optional_text(value, "status")?.map_or(TransactionStatus::Unknown, |status| {
        match status.to_ascii_uppercase().as_str() {
            "WAITING" => TransactionStatus::Waiting,
            "QUEUED" => TransactionStatus::Queued,
            "SUCCESS" => TransactionStatus::Success,
            "ERROR" => TransactionStatus::Error,
            "REFUNDED" => TransactionStatus::Refunded,
            "REFUNDPENDING" => TransactionStatus::RefundPending,
            "REFUNDREJECTED" => TransactionStatus::RefundRejected,
            _ => TransactionStatus::Unknown,
        }
    });
    let tracking_number = optional_text(value, "tracking_number")?
        .map(TrackingNumber::parse)
        .transpose()
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let tracking_status = optional_tracking_status(value.get("tracking_status"));
    Ok(ShippoTransactionPayload {
        transaction_id,
        account_id,
        shipment_id,
        status,
        tracking_number,
        tracking_status,
        revision: positive_revision(value),
    })
}

fn parse_tracking(value: &Value) -> Result<ShippoTrackingPayload, ShippoTransportError> {
    let carrier = required_text(value, "carrier")?;
    let carrier = CarrierCode::parse(carrier.to_ascii_lowercase())
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let tracking_number = required_text(value, "tracking_number")?;
    let tracking_number = TrackingNumber::parse(tracking_number)
        .map_err(|error| ShippoTransportError::Decode(error.to_string()))?;
    let history = value
        .get("tracking_history")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ShippoTransportError::Decode("tracking_history is not an array".to_owned())
        })?;
    if history.len() > SHIPPO_MAX_TRACKING_EVENTS {
        return Err(ShippoTransportError::InvalidRequest(
            "tracking history exceeds the bounded projection".to_owned(),
        ));
    }
    let events = history
        .iter()
        .map(parse_tracking_event)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ShippoTrackingPayload {
        carrier,
        tracking_number,
        latest_status: optional_tracking_status(value.get("tracking_status")),
        events,
        eta: optional_date(value, "eta")?,
        original_eta: optional_date(value, "original_eta")?,
        has_sender_address: value.get("address_from").is_some_and(Value::is_object),
        has_recipient_address: value.get("address_to").is_some_and(Value::is_object),
        service_level_present: value.get("servicelevel").is_some_and(Value::is_object),
        revision: positive_revision(value),
    })
}

fn parse_tracking_event(value: &Value) -> Result<ShippoTrackingEventPayload, ShippoTransportError> {
    let status = optional_text(value, "status")?
        .map_or(ProviderTrackingStatus::Unknown, |status| {
            ProviderTrackingStatus::parse(&status)
        });
    let status_at = optional_date(value, "status_date")?;
    let location_present = value.get("location").is_some_and(Value::is_object);
    let status_detail_present = value
        .get("status_details")
        .and_then(Value::as_str)
        .is_some_and(|detail| !detail.is_empty());
    let action_required = value
        .get("substatus")
        .and_then(Value::as_object)
        .and_then(|substatus| substatus.get("action_required"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(ShippoTrackingEventPayload {
        status,
        status_at,
        location_present,
        status_detail_present,
        action_required,
    })
}

fn required_text(value: &Value, field: &str) -> Result<String, ShippoTransportError> {
    optional_text(value, field)?
        .ok_or_else(|| ShippoTransportError::Decode(format!("Shippo response is missing {field}")))
}

fn optional_text(value: &Value, field: &str) -> Result<Option<String>, ShippoTransportError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| ShippoTransportError::Decode(format!("{field} is not a string"))),
    }
}

fn optional_tracking_status(value: Option<&Value>) -> Option<ProviderTrackingStatus> {
    match value {
        Some(Value::String(status)) => Some(ProviderTrackingStatus::parse(status)),
        Some(Value::Object(object)) => object
            .get("status")
            .and_then(Value::as_str)
            .map(ProviderTrackingStatus::parse),
        _ => None,
    }
}

fn optional_date(
    value: &Value,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, ShippoTransportError> {
    let Some(value) = value.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(ShippoTransportError::Decode(format!(
            "{field} is not an RFC3339 string"
        )));
    };
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| Some(date.with_timezone(&chrono::Utc)))
        .map_err(|error| ShippoTransportError::Decode(format!("{field}: {error}")))
}

fn positive_revision(value: &Value) -> u64 {
    value
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision > 0)
        .unwrap_or(1)
}
