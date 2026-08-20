use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::blocking::Client;
use thiserror::Error;
use url::Url;

use crate::error::TwilioHandoffError;
use crate::model::{
    EvidenceSource, SecretMaterial, TwilioAccountSid, TwilioMessageSid, TwilioReadRequest,
};

/// Layer 1 exposes only the typed GET seam for Message-resource readback.
/// There is intentionally no executable POST/send method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwilioHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwilioHttpOperation {
    ReadMessage,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TwilioHttpRequest {
    pub method: TwilioHttpMethod,
    pub operation: TwilioHttpOperation,
    pub url: Url,
    pub account_id: TwilioAccountSid,
    pub provider_message_sid: TwilioMessageSid,
}

impl TwilioHttpRequest {
    pub fn read_message(
        base_url: &Url,
        request: &TwilioReadRequest,
    ) -> Result<Self, TwilioHandoffError> {
        let mut url = base_url.clone();
        {
            let mut segments =
                url.path_segments_mut()
                    .map_err(|()| TwilioHandoffError::InvalidInput {
                        field: "Twilio API base URL",
                        reason: "must accept path segments",
                    })?;
            segments
                .pop_if_empty()
                .push("Accounts")
                .push(request.account_id.as_str())
                .push("Messages");
            let message_segment = format!("{}.json", request.provider_message_sid.as_str());
            segments.push(&message_segment);
        }
        Ok(Self {
            method: TwilioHttpMethod::Get,
            operation: TwilioHttpOperation::ReadMessage,
            url,
            account_id: request.account_id.clone(),
            provider_message_sid: request.provider_message_sid.clone(),
        })
    }
}

impl fmt::Debug for TwilioHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwilioHttpRequest")
            .field("method", &self.method)
            .field("operation", &self.operation)
            .field("url", &"<redacted-twilio-resource-url>")
            .field("account_id", &"<redacted-account>")
            .field("provider_message_sid", &self.provider_message_sid)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TwilioHttpResponse {
    pub status: u16,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl TwilioHttpResponse {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: std::collections::BTreeMap::from([(
                String::from("content-type"),
                String::from("application/json"),
            )]),
            body: body.as_bytes().to_vec(),
        }
    }
}

impl fmt::Debug for TwilioHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwilioHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &"<redacted-provider-payload>")
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TwilioTransportError {
    #[error("Twilio HTTPS request failed")]
    Request,
    #[error("Twilio HTTPS response exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("Twilio HTTPS request timed out")]
    Timeout,
    #[error("Twilio HTTPS provider returned HTTP 429")]
    RateLimited { retry_after_ms: Option<u64> },
    #[error("Twilio HTTPS provider returned an ambiguous response")]
    AmbiguousResponse,
}

impl From<TwilioTransportError> for TwilioHandoffError {
    fn from(error: TwilioTransportError) -> Self {
        match error {
            TwilioTransportError::Request => Self::Transport,
            TwilioTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            TwilioTransportError::Timeout => Self::Timeout,
            TwilioTransportError::RateLimited { retry_after_ms } => {
                Self::RateLimited { retry_after_ms }
            }
            TwilioTransportError::AmbiguousResponse => Self::AmbiguousResponse,
        }
    }
}

/// The transport consumes a typed secret for one read operation.  It never
/// receives or returns an untyped JSON escape hatch, and Layer 1 has no write
/// operation on this trait.
pub trait TwilioHttpsTransport: Send + Sync {
    fn read_message(
        &self,
        secret: &SecretMaterial,
        request: &TwilioHttpRequest,
    ) -> Result<TwilioHttpResponse, TwilioTransportError>;

    fn evidence_source(&self) -> EvidenceSource;

    fn is_native(&self) -> bool {
        false
    }
}

pub struct ReqwestTwilioHttpsTransport {
    client: Client,
    base_url: Url,
    max_response_bytes: usize,
    native: bool,
}

impl fmt::Debug for ReqwestTwilioHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReqwestTwilioHttpsTransport")
            .field("base_url", &"<redacted-twilio-api-url>")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("native", &self.native)
            .finish_non_exhaustive()
    }
}

impl ReqwestTwilioHttpsTransport {
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 512 * 1024;
    pub const TWILIO_API_BASE_URL: &'static str = "https://api.twilio.com/2010-04-01/";

    pub(crate) fn production() -> Result<Self, TwilioTransportError> {
        let base_url =
            Url::parse(Self::TWILIO_API_BASE_URL).map_err(|_| TwilioTransportError::Request)?;
        let client = Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| TwilioTransportError::Request)?;
        Ok(Self {
            client,
            base_url,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
            native: true,
        })
    }

    pub fn loopback(base_url: impl AsRef<str>) -> Result<Self, TwilioHandoffError> {
        let base_url =
            Url::parse(base_url.as_ref()).map_err(|_| TwilioHandoffError::InvalidInput {
                field: "loopback API base URL",
                reason: "must be localhost HTTP",
            })?;
        let is_loopback = base_url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]"));
        if base_url.scheme() != "http" || !is_loopback {
            return Err(TwilioHandoffError::InvalidInput {
                field: "loopback API base URL",
                reason: "must be localhost HTTP",
            });
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| TwilioHandoffError::Transport)?;
        Ok(Self {
            client,
            base_url,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
            native: false,
        })
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }

    pub fn request_for(
        &self,
        request: &TwilioReadRequest,
    ) -> Result<TwilioHttpRequest, TwilioHandoffError> {
        TwilioHttpRequest::read_message(&self.base_url, request)
    }
}

impl TwilioHttpsTransport for ReqwestTwilioHttpsTransport {
    fn read_message(
        &self,
        secret: &SecretMaterial,
        request: &TwilioHttpRequest,
    ) -> Result<TwilioHttpResponse, TwilioTransportError> {
        let password =
            std::str::from_utf8(secret.as_bytes()).map_err(|_| TwilioTransportError::Request)?;
        let response = self
            .client
            .get(request.url.clone())
            .basic_auth(request.account_id.as_str(), Some(password))
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    TwilioTransportError::Timeout
                } else {
                    TwilioTransportError::Request
                }
            })?;
        let status = response.status().as_u16();
        if status == 429 {
            return Err(TwilioTransportError::RateLimited {
                retry_after_ms: None,
            });
        }
        if !(200..300).contains(&status) {
            return Err(TwilioTransportError::AmbiguousResponse);
        }
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let body = response
            .bytes()
            .map_err(|_| TwilioTransportError::Request)?
            .to_vec();
        if body.len() > self.max_response_bytes {
            return Err(TwilioTransportError::ResponseTooLarge);
        }
        Ok(TwilioHttpResponse {
            status,
            headers,
            body,
        })
    }

    fn evidence_source(&self) -> EvidenceSource {
        if self.native {
            EvidenceSource::NativeHttps
        } else {
            EvidenceSource::Loopback
        }
    }

    fn is_native(&self) -> bool {
        self.native
    }
}

/// Deterministic transport for fixture and loopback tests.  It records typed
/// read requests and never performs network I/O.
#[derive(Clone)]
pub struct RecordingTwilioHttpsTransport {
    responses: Arc<Mutex<VecDeque<Result<TwilioHttpResponse, TwilioTransportError>>>>,
    requests: Arc<Mutex<Vec<TwilioHttpRequest>>>,
    evidence_source: EvidenceSource,
}

impl fmt::Debug for RecordingTwilioHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingTwilioHttpsTransport")
            .field("evidence_source", &self.evidence_source)
            .field("requests", &self.requests().len())
            .field("remaining_responses", &self.remaining_responses())
            .finish_non_exhaustive()
    }
}

impl RecordingTwilioHttpsTransport {
    pub fn fixture(
        responses: impl IntoIterator<Item = Result<TwilioHttpResponse, TwilioTransportError>>,
    ) -> Self {
        Self::new(EvidenceSource::Fixture, responses)
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<TwilioHttpResponse, TwilioTransportError>>,
    ) -> Self {
        Self::new(EvidenceSource::Loopback, responses)
    }

    pub fn new(
        evidence_source: EvidenceSource,
        responses: impl IntoIterator<Item = Result<TwilioHttpResponse, TwilioTransportError>>,
    ) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
            evidence_source,
        }
    }

    pub fn requests(&self) -> Vec<TwilioHttpRequest> {
        self.requests
            .lock()
            .map_or_else(|_| Vec::new(), |requests| requests.clone())
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.lock().map_or(0, |responses| responses.len())
    }
}

impl TwilioHttpsTransport for RecordingTwilioHttpsTransport {
    fn read_message(
        &self,
        secret: &SecretMaterial,
        request: &TwilioHttpRequest,
    ) -> Result<TwilioHttpResponse, TwilioTransportError> {
        if secret.as_bytes().is_empty() {
            return Err(TwilioTransportError::Request);
        }
        self.requests
            .lock()
            .map_err(|_| TwilioTransportError::Request)?
            .push(request.clone());
        self.responses
            .lock()
            .map_err(|_| TwilioTransportError::Request)?
            .pop_front()
            .ok_or(TwilioTransportError::Request)?
    }

    fn evidence_source(&self) -> EvidenceSource {
        self.evidence_source
    }
}
