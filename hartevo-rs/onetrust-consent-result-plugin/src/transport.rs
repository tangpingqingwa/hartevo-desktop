//! Bounded OneTrust HTTP seams and deterministic non-native transports.
//!
//! The transport receives only a typed request containing an opaque subject
//! hash. It never receives a raw subject identifier, bearer token, JWT, or raw
//! preference payload. The optional JSON decoder below projects only the
//! allowlisted consent fields before the response reaches the provider.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    CollectionPointId, ConsentEvidenceStatus, Digest, OneTrustConsentObservation, OneTrustEndpoint,
    OneTrustHttpRequest, OneTrustHttpResponse, OneTrustModelError, OneTrustProviderErrorEvidence,
    OneTrustProviderErrorKind, OneTrustResponseBody, OpaqueCursor, PolicyRevision,
    ProviderRevision, PurposeId, PurposeVersion,
};
use crate::{ONETRUST_MAX_OBSERVATIONS, ONETRUST_MAX_RESPONSE_BYTES};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OneTrustTransportError {
    #[error("BLOCKED_ENV: OneTrust native credential and network authority is unavailable")]
    BlockedEnv,
    #[error("OneTrust transport timed out")]
    Timeout,
    #[error("OneTrust transport queue is exhausted")]
    QueueExhausted,
    #[error("OneTrust transport request is invalid: {0}")]
    InvalidRequest(String),
    #[error("OneTrust transport response is invalid: {0}")]
    InvalidResponse(String),
    #[error("OneTrust transport failed: {0}")]
    Failed(String),
}

/// Abstract HTTPS/auth transport seam owned by the provider. Layer 1 ships
/// deterministic fixture, recording, loopback, and BLOCKED_ENV adapters only.
pub trait OneTrustTransport: fmt::Debug {
    fn provenance(&self) -> crate::TransportProvenance;

    fn send(
        &mut self,
        request: &OneTrustHttpRequest,
    ) -> Result<OneTrustHttpResponse, OneTrustTransportError>;
}

/// A deterministic response queue used by fixtures, recordings, and loopback
/// simulations. It records typed request receipts, never raw bodies.
pub struct RecordingOneTrustTransport {
    provenance: crate::TransportProvenance,
    responses: VecDeque<Result<OneTrustHttpResponse, OneTrustTransportError>>,
    requests: Vec<OneTrustHttpRequest>,
}

impl fmt::Debug for RecordingOneTrustTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingOneTrustTransport")
            .field("provenance", &self.provenance)
            .field("queued_responses", &self.responses.len())
            .field("recorded_requests", &self.requests.len())
            .finish()
    }
}

impl RecordingOneTrustTransport {
    pub fn new<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<OneTrustHttpResponse, OneTrustTransportError>>,
    {
        Self {
            provenance: crate::TransportProvenance::Recording,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<OneTrustHttpResponse, OneTrustTransportError>>,
    {
        let mut transport = Self::new(responses);
        transport.provenance = crate::TransportProvenance::Fixture;
        transport
    }

    pub fn loopback<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = Result<OneTrustHttpResponse, OneTrustTransportError>>,
    {
        let mut transport = Self::new(responses);
        transport.provenance = crate::TransportProvenance::Loopback;
        transport
    }

    pub fn requests(&self) -> &[OneTrustHttpRequest] {
        &self.requests
    }

    pub fn provenance(&self) -> crate::TransportProvenance {
        self.provenance
    }
}

impl OneTrustTransport for RecordingOneTrustTransport {
    fn provenance(&self) -> crate::TransportProvenance {
        self.provenance
    }

    fn send(
        &mut self,
        request: &OneTrustHttpRequest,
    ) -> Result<OneTrustHttpResponse, OneTrustTransportError> {
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(OneTrustTransportError::QueueExhausted)??;
        if response.receipt.request_digest != request.request_digest {
            return Err(OneTrustTransportError::InvalidResponse(
                "response request digest does not match the typed request".to_owned(),
            ));
        }
        Ok(response)
    }
}

pub type FixtureOneTrustTransport = RecordingOneTrustTransport;
pub type LoopbackOneTrustTransport = RecordingOneTrustTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvOneTrustTransport;

impl OneTrustTransport for BlockedEnvOneTrustTransport {
    fn provenance(&self) -> crate::TransportProvenance {
        crate::TransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &OneTrustHttpRequest,
    ) -> Result<OneTrustHttpResponse, OneTrustTransportError> {
        Err(OneTrustTransportError::BlockedEnv)
    }
}

impl OneTrustHttpResponse {
    /// Decode a bounded provider response into the allowlisted shape. The raw
    /// bytes are hashed for the receipt and then dropped; unknown fields,
    /// including PII, JWTs, and raw preference payloads, are never retained.
    pub fn from_json(
        request: &OneTrustHttpRequest,
        status_code: u16,
        raw: &[u8],
        provider_revision: ProviderRevision,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, OneTrustModelError> {
        if raw.len() > ONETRUST_MAX_RESPONSE_BYTES {
            return Err(OneTrustModelError::TooLong {
                field: "provider response",
            });
        }
        let value = serde_json::from_slice::<Value>(raw)
            .map_err(|error| OneTrustModelError::InvalidResponse(error.to_string()))?;
        let source_digest = Digest::from_bytes(raw);
        let observations = parse_observations(&value, request, &source_digest)?;
        let body = OneTrustResponseBody::new(observations)?;
        Ok(Self {
            status_code,
            body,
            next_cursor,
            receipt: crate::OneTrustResponseReceipt {
                status_code,
                response_size_bytes: raw.len(),
                response_digest: Digest::from_bytes(raw),
                request_digest: request.request_digest.clone(),
                provider_revision,
                raw_provider_payload_retained: false,
                raw_preference_payload_retained: false,
                raw_pii_retained: false,
                raw_jwt_retained: false,
            },
        })
    }
}

fn record_values(root: &Value) -> Vec<&Value> {
    match root {
        Value::Array(values) => values.iter().collect(),
        Value::Object(object) => {
            for key in [
                "data",
                "results",
                "items",
                "preferences",
                "transactions",
                "consents",
            ] {
                if let Some(value) = object.get(key) {
                    return record_values(value);
                }
            }
            vec![root]
        }
        _ => Vec::new(),
    }
}

fn first_string<'a>(object: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

fn parse_timestamp(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<DateTime<Utc>> {
    first_string(object, keys)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn parse_status(value: Option<&str>) -> ConsentEvidenceStatus {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "granted" | "consented" | "accepted" | "allow" | "allowed" | "opt_in" | "opt-in" => {
            ConsentEvidenceStatus::Granted
        }
        "denied" | "rejected" | "declined" | "blocked" | "opt_out" | "opt-out" => {
            ConsentEvidenceStatus::Denied
        }
        "pending" | "unknown_pending" => ConsentEvidenceStatus::Pending,
        "withdrawn" | "revoked" | "withdraw" => ConsentEvidenceStatus::Withdrawn,
        "expired" | "expiry" => ConsentEvidenceStatus::Expired,
        "" => ConsentEvidenceStatus::NoRecord,
        _ => ConsentEvidenceStatus::ProviderUnknown,
    }
}

fn parse_identifier<T>(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
    fallback: &T,
    field: &'static str,
) -> Result<T, OneTrustModelError>
where
    T: Clone + FromStrLike,
{
    match first_string(object, keys) {
        Some(value) => T::from_str_like(value).map_err(|_| OneTrustModelError::Invalid { field }),
        None => Ok(fallback.clone()),
    }
}

trait FromStrLike: Sized {
    fn from_str_like(value: &str) -> Result<Self, OneTrustModelError>;
}

macro_rules! impl_from_str_like {
    ($($name:ty),+ $(,)?) => {
        $(impl FromStrLike for $name {
            fn from_str_like(value: &str) -> Result<Self, OneTrustModelError> {
                <$name>::new(value)
            }
        })+
    };
}

impl_from_str_like!(PurposeId, PurposeVersion, CollectionPointId, PolicyRevision);

fn parse_observations(
    root: &Value,
    request: &OneTrustHttpRequest,
    source_digest: &Digest,
) -> Result<Vec<OneTrustConsentObservation>, OneTrustModelError> {
    let values = record_values(root);
    let mut observations = Vec::new();
    for value in values {
        let Some(object) = value.as_object() else {
            continue;
        };
        let purpose_id = parse_identifier(
            object,
            &["purposeId", "purposeID", "purpose"],
            &request.purpose_id,
            "purpose id",
        )?;
        let purpose_version = parse_identifier(
            object,
            &["purposeVersion", "purposeRevision", "version"],
            &request.purpose_version,
            "purpose version",
        )?;
        let collection_point = parse_identifier(
            object,
            &["collectionPoint", "collectionPointId", "collectionPointID"],
            &request.collection_point,
            "collection point",
        )?;
        let policy_revision = parse_identifier(
            object,
            &["policyRevision", "policyVersion", "policy"],
            &request.policy_revision,
            "policy revision",
        )?;
        let status = parse_status(first_string(
            object,
            &["status", "consentStatus", "preference", "value"],
        ));
        let transaction_id = first_string(object, &["transactionId", "transactionID", "id"])
            .map(|value| Digest::from_fields(["hartevo-onetrust-transaction-v1", value]));
        observations.push(OneTrustConsentObservation::new(
            purpose_id,
            purpose_version,
            status,
            parse_timestamp(object, &["consentTimestamp", "consentedAt", "consentDate"]),
            parse_timestamp(
                object,
                &["withdrawalTimestamp", "withdrawnAt", "withdrawalDate"],
            ),
            parse_timestamp(object, &["expiryTimestamp", "expiresAt", "expirationDate"]),
            collection_point,
            transaction_id,
            policy_revision,
            request.subject_reference.clone(),
            source_digest.clone(),
        ));
        if observations.len() > ONETRUST_MAX_OBSERVATIONS {
            return Err(OneTrustModelError::TooMany {
                field: "consent observations",
            });
        }
    }
    Ok(observations)
}

/// Convert a typed provider error into redacted evidence. This helper is kept
/// public for host-side recording adapters that need the same normalization.
pub fn provider_error_evidence(
    endpoint: OneTrustEndpoint,
    kind: OneTrustProviderErrorKind,
    status_code: Option<u16>,
    detail: impl AsRef<str>,
    retry_after_seconds: Option<u64>,
) -> OneTrustProviderErrorEvidence {
    OneTrustProviderErrorEvidence::new(
        endpoint.operation_name(),
        kind,
        status_code,
        detail,
        retry_after_seconds,
    )
}
