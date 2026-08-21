//! Redacting, bounded transport seams for Chargebee reads.
//!
//! These transports are fixtures and test seams only. They retain typed
//! requests and sanitized responses; raw provider bytes are parsed and then
//! dropped. No transport in this crate can claim a connected or native
//! provider.

use std::{collections::VecDeque, fmt};

use serde_json::Value;
use thiserror::Error;

use crate::{
    ChargebeeHttpRequest, ChargebeeHttpResponse, ChargebeeModelError, ChargebeeReadOperation,
    ChargebeeReadRequest, ChargebeeResponseBody, ChargebeeTransportProvenance, CustomerId,
    EntitlementId, EntitlementObservation, EntitlementStatus, InvoiceId, InvoiceObservation,
    InvoiceStatus, PlanId, ProviderRevision, Revision, SiteId, SubscriptionId,
    SubscriptionObservation, SubscriptionStatus, UsageMetadata,
};

/// Metadata-only transport failures. Raw provider bodies, URLs, PII, and
/// credential material are intentionally absent.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChargebeeTransportError {
    #[error("Chargebee request timed out")]
    Timeout,
    #[error("Chargebee provider returned HTTP {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
        response_digest: crate::Digest,
    },
    #[error("Chargebee request was rate limited; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("Chargebee access was lost")]
    AccessLost { status: u16 },
    #[error("Chargebee request was denied")]
    Denied,
    #[error("Chargebee resource was absent")]
    Absent,
    #[error("Chargebee resource or observation expired")]
    Expired,
    #[error("Chargebee transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Chargebee provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Chargebee response could not be decoded")]
    Decode,
    #[error("Chargebee transport response did not match the request")]
    RequestMismatch,
    #[error("Chargebee fixture has no response for the bounded request")]
    FixtureExhausted,
}

impl From<ChargebeeModelError> for ChargebeeTransportError {
    fn from(_error: ChargebeeModelError) -> Self {
        Self::Decode
    }
}

/// The only transport capability exported by this Layer-1 root.
pub trait ChargebeeTransport: fmt::Debug {
    fn provenance(&self) -> ChargebeeTransportProvenance;

    fn send(
        &mut self,
        request: &ChargebeeHttpRequest,
    ) -> Result<ChargebeeHttpResponse, ChargebeeTransportError>;
}

/// Queue-backed typed transport used for fixtures, recordings, fakes, and
/// loopbacks. It never performs network I/O.
#[derive(Clone, Debug)]
pub struct QueueChargebeeTransport {
    responses: VecDeque<Result<ChargebeeHttpResponse, ChargebeeTransportError>>,
    requests: Vec<ChargebeeHttpRequest>,
    provenance: ChargebeeTransportProvenance,
}

impl QueueChargebeeTransport {
    pub fn new(provenance: ChargebeeTransportProvenance) -> Self {
        Self {
            responses: VecDeque::new(),
            requests: Vec::new(),
            provenance,
        }
    }

    pub fn fixture() -> Self {
        Self::new(ChargebeeTransportProvenance::Fixture)
    }

    pub fn recording() -> Self {
        Self::new(ChargebeeTransportProvenance::Recording)
    }

    pub fn fake() -> Self {
        Self::new(ChargebeeTransportProvenance::Fake)
    }

    pub fn loopback() -> Self {
        Self::new(ChargebeeTransportProvenance::Loopback)
    }

    pub fn queue(&mut self, response: Result<ChargebeeHttpResponse, ChargebeeTransportError>) {
        self.responses.push_back(response);
    }

    pub fn queue_ok(&mut self, response: ChargebeeHttpResponse) {
        self.queue(Ok(response));
    }

    pub fn queue_error(&mut self, error: ChargebeeTransportError) {
        self.queue(Err(error));
    }

    pub fn requests(&self) -> &[ChargebeeHttpRequest] {
        &self.requests
    }

    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }
}

impl ChargebeeTransport for QueueChargebeeTransport {
    fn provenance(&self) -> ChargebeeTransportProvenance {
        self.provenance
    }

    fn send(
        &mut self,
        request: &ChargebeeHttpRequest,
    ) -> Result<ChargebeeHttpResponse, ChargebeeTransportError> {
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(ChargebeeTransportError::FixtureExhausted)??;
        if response.operation != request.operation
            || response.receipt.request_digest != request.request_digest
        {
            return Err(ChargebeeTransportError::RequestMismatch);
        }
        Ok(response)
    }
}

/// Fixture transport alias.
pub type FixtureChargebeeTransport = QueueChargebeeTransport;
/// Recording transport alias.
pub type RecordingChargebeeTransport = QueueChargebeeTransport;
/// Fake transport alias.
pub type FakeChargebeeTransport = QueueChargebeeTransport;
/// Loopback transport alias.
pub type LoopbackChargebeeTransport = QueueChargebeeTransport;

/// BLOCKED_ENV transport. It cannot accidentally become connected/native.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvChargebeeTransport;

impl ChargebeeTransport for BlockedEnvChargebeeTransport {
    fn provenance(&self) -> ChargebeeTransportProvenance {
        ChargebeeTransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &ChargebeeHttpRequest,
    ) -> Result<ChargebeeHttpResponse, ChargebeeTransportError> {
        Err(ChargebeeTransportError::BlockedEnv)
    }
}

impl ChargebeeHttpResponse {
    /// Parse a bounded allowlisted provider response and discard the raw JSON.
    pub fn from_json(
        request: &ChargebeeHttpRequest,
        status: u16,
        raw: &[u8],
        provider_revision: ProviderRevision,
        has_more: bool,
        retry_after_seconds: Option<u64>,
    ) -> Result<Self, ChargebeeTransportError> {
        if status != 200 {
            let response_digest = crate::Digest::from_bytes(raw);
            return match status {
                401 => Err(ChargebeeTransportError::AccessLost { status }),
                403 => Err(ChargebeeTransportError::Denied),
                404 => Err(ChargebeeTransportError::Absent),
                410 => Err(ChargebeeTransportError::Expired),
                429 => Err(ChargebeeTransportError::RateLimited {
                    retry_after_seconds: retry_after_seconds.unwrap_or(60),
                }),
                500..=599 => Err(ChargebeeTransportError::ProviderUnknown),
                _ => Err(ChargebeeTransportError::HttpStatus {
                    status,
                    retry_after_seconds,
                    response_digest,
                }),
            };
        }
        if raw.len() > crate::MAX_RESPONSE_BYTES {
            return Err(ChargebeeTransportError::Decode);
        }
        let value =
            serde_json::from_slice::<Value>(raw).map_err(|_| ChargebeeTransportError::Decode)?;
        let body = parse_body(request.operation, &value, request)?;
        let mut response = Self::from_body(request, body, provider_revision, has_more)
            .map_err(ChargebeeTransportError::from)?;
        response.receipt.retry_after_seconds = retry_after_seconds;
        Ok(response)
    }
}

fn parse_body(
    operation: ChargebeeReadOperation,
    value: &Value,
    request: &ChargebeeHttpRequest,
) -> Result<ChargebeeResponseBody, ChargebeeTransportError> {
    match operation {
        ChargebeeReadOperation::Subscription => Ok(ChargebeeResponseBody::Subscription(
            parse_subscription(value, request)?,
        )),
        ChargebeeReadOperation::Entitlements => {
            let values = list_value(value)?
                .iter()
                .map(|item| parse_entitlement(item, request))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ChargebeeResponseBody::Entitlements(values))
        }
        ChargebeeReadOperation::Invoices => {
            let values = list_value(value)?
                .iter()
                .map(|item| parse_invoice(item, request))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ChargebeeResponseBody::Invoices(values))
        }
        ChargebeeReadOperation::Usage => Ok(ChargebeeResponseBody::Usage(parse_usage(value)?)),
    }
}

fn list_value(value: &Value) -> Result<&Vec<Value>, ChargebeeTransportError> {
    value
        .as_array()
        .or_else(|| value.get("list").and_then(Value::as_array))
        .ok_or(ChargebeeTransportError::Decode)
}

fn required_string(value: &Value, keys: &[&str]) -> Result<String, ChargebeeTransportError> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
        .ok_or(ChargebeeTransportError::Decode)
}

fn optional_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn nested_optional_string(value: &Value, object_key: &str, keys: &[&str]) -> Option<String> {
    value
        .get(object_key)
        .and_then(Value::as_object)
        .and_then(|object| {
            keys.iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_owned))
        })
        .or_else(|| optional_string(value, keys))
}

fn number(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn boolean(value: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn bounded_optional(
    value: Option<String>,
    max: usize,
) -> Result<Option<String>, ChargebeeTransportError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ChargebeeTransportError::Decode);
    }
    Ok(Some(value))
}

fn revision(value: &Value, keys: &[&str]) -> Result<Revision, ChargebeeTransportError> {
    Revision::new(
        number(value, keys).ok_or(ChargebeeTransportError::Decode)?,
        "provider revision",
    )
    .map_err(ChargebeeTransportError::from)
}

fn quantity(value: &Value) -> Result<u32, ChargebeeTransportError> {
    u32::try_from(number(value, &["quantity", "qty"]).unwrap_or(0))
        .map_err(|_| ChargebeeTransportError::Decode)
}

fn parse_subscription(
    value: &Value,
    _request: &ChargebeeHttpRequest,
) -> Result<SubscriptionObservation, ChargebeeTransportError> {
    let usage = value.get("usage").map(parse_usage).transpose()?;
    Ok(SubscriptionObservation {
        id: SubscriptionId::new(required_string(value, &["id", "subscription_id"])?)?,
        site_id: SiteId::new(required_string(value, &["site_id", "site"])?)?,
        customer_id: CustomerId::new(required_string(value, &["customer_id", "customer"])?)?,
        plan_id: PlanId::new(required_string(value, &["plan_id", "plan"])?)?,
        revision: revision(value, &["revision", "version", "subscription_revision"])?,
        status: SubscriptionStatus::from_wire(
            optional_string(value, &["status", "state"]).as_deref(),
        ),
        quantity: quantity(value)?,
        current_term_start: bounded_optional(
            optional_string(value, &["current_term_start", "current_term_start_at"]),
            64,
        )?,
        current_term_end: bounded_optional(
            optional_string(value, &["current_term_end", "current_term_end_at"]),
            64,
        )?,
        cancel_at_end: boolean(value, &["cancel_at_end", "cancelled_at_end"]),
        usage,
    })
}

fn parse_entitlement(
    value: &Value,
    _request: &ChargebeeHttpRequest,
) -> Result<EntitlementObservation, ChargebeeTransportError> {
    let feature = nested_optional_string(value, "feature", &["id", "feature_id"])
        .or_else(|| optional_string(value, &["feature_id"]))
        .unwrap_or_else(|| "unknown-feature".to_owned());
    Ok(EntitlementObservation {
        id: EntitlementId::new(required_string(value, &["id", "entitlement_id"])?)?,
        site_id: SiteId::new(required_string(value, &["site_id", "site"])?)?,
        customer_id: CustomerId::new(required_string(value, &["customer_id", "customer"])?)?,
        subscription_id: SubscriptionId::new(required_string(
            value,
            &["subscription_id", "subscription"],
        )?)?,
        plan_id: PlanId::new(required_string(value, &["plan_id", "plan"])?)?,
        revision: revision(value, &["revision", "version", "entitlement_revision"])?,
        status: EntitlementStatus::from_wire(
            optional_string(value, &["status", "state"]).as_deref(),
        ),
        feature_digest: crate::Digest::from_text(feature),
    })
}

fn parse_invoice(
    value: &Value,
    _request: &ChargebeeHttpRequest,
) -> Result<InvoiceObservation, ChargebeeTransportError> {
    Ok(InvoiceObservation {
        id: InvoiceId::new(required_string(value, &["id", "invoice_id"])?)?,
        site_id: SiteId::new(required_string(value, &["site_id", "site"])?)?,
        customer_id: CustomerId::new(required_string(value, &["customer_id", "customer"])?)?,
        subscription_id: SubscriptionId::new(required_string(
            value,
            &["subscription_id", "subscription"],
        )?)?,
        revision: revision(value, &["revision", "version", "invoice_revision"])?,
        status: InvoiceStatus::from_wire(optional_string(value, &["status", "state"]).as_deref()),
        due_at: bounded_optional(optional_string(value, &["due_at", "due_date"]), 64)?,
        paid_at: bounded_optional(optional_string(value, &["paid_at", "paid_date"]), 64)?,
    })
}

fn parse_usage(value: &Value) -> Result<UsageMetadata, ChargebeeTransportError> {
    let metric = required_string(value, &["metric", "metric_name", "id"])?;
    UsageMetadata::new(
        metric,
        number(value, &["quantity", "usage", "count"]).unwrap_or(0),
        bounded_optional(optional_string(value, &["period_start", "from"]), 64)?,
        bounded_optional(optional_string(value, &["period_end", "to"]), 64)?,
    )
    .map_err(ChargebeeTransportError::from)
}

/// Convert a typed request and already-sanitized JSON response into a response.
pub fn response_from_json(
    request: &ChargebeeReadRequest,
    status: u16,
    raw: &[u8],
    provider_revision: ProviderRevision,
    has_more: bool,
    retry_after_seconds: Option<u64>,
) -> Result<ChargebeeHttpResponse, ChargebeeTransportError> {
    ChargebeeHttpResponse::from_json(
        &request.http_request(),
        status,
        raw,
        provider_revision,
        has_more,
        retry_after_seconds,
    )
}
