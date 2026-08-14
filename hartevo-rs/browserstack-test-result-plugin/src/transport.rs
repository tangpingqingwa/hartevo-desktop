//! GET-only BrowserStack Automate/App Automate transport.
//!
//! The production transport reads a bounded JSON body, normalizes only the
//! fields allowed by the contract, and drops the provider JSON before the
//! response is returned. It has no method for upload, launch, mutation, or
//! debugging-media download.

use std::{collections::VecDeque, fmt, time::Duration as StdDuration};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use crate::model::{
    BrowserStackBuildPayload, BrowserStackMatrixEntry, BrowserStackProduct,
    BrowserStackResponseBody, BrowserStackResponseReceipt, BrowserStackSessionPayload, Digest,
    OutcomeCounts, RequestBounds, Revision, TransportProvenance, digest_serializable,
    sha256_digest,
};
use crate::provider::BrowserStackCredentialLease;
use crate::{
    BROWSERSTACK_AUTOMATE_API_ORIGIN, BROWSERSTACK_MAX_RESPONSE_BYTES,
    BROWSERSTACK_PROVIDER_REVISION, BrowserStackTestResultError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrowserStackTransportError {
    #[error("BrowserStack credential is unavailable")]
    CredentialUnavailable,
    #[error("BLOCKED_ENV: BrowserStack transport is disabled")]
    BlockedEnv,
    #[error("BrowserStack returned HTTP status {status}")]
    Status {
        status: u16,
        retryable: bool,
        diagnostic_digest: Digest,
    },
    #[error("BrowserStack request is invalid: {0}")]
    InvalidRequest(String),
    #[error("BrowserStack response body is unexpected for the endpoint")]
    UnexpectedBody,
    #[error("BrowserStack response could not be decoded: {0}")]
    Decode(String),
    #[error("BrowserStack HTTPS transport failed: {detail}")]
    Transport {
        detail: String,
        retryable: bool,
        timeout: bool,
        diagnostic_digest: Digest,
    },
}

impl BrowserStackTransportError {
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Self::Status { retryable, .. } | Self::Transport { retryable, .. } => *retryable,
            Self::BlockedEnv
            | Self::CredentialUnavailable
            | Self::InvalidRequest(_)
            | Self::UnexpectedBody
            | Self::Decode(_) => false,
        }
    }

    pub fn timeout(&self) -> bool {
        matches!(self, Self::Transport { timeout: true, .. })
    }

    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Status {
                diagnostic_digest, ..
            }
            | Self::Transport {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::BlockedEnv => Digest::from_text("BLOCKED_ENV"),
            Self::CredentialUnavailable => Digest::from_text("credential-unavailable"),
            Self::InvalidRequest(value) | Self::Decode(value) => Digest::from_text(value),
            Self::UnexpectedBody => Digest::from_text("unexpected-body"),
        }
    }

    pub fn status(status: u16) -> Self {
        Self::Status {
            status,
            retryable: matches!(status, 409 | 429 | 500..=599),
            diagnostic_digest: Digest::from_text(format!("http-{status}")),
        }
    }
}

impl From<BrowserStackTransportError> for BrowserStackTestResultError {
    fn from(error: BrowserStackTransportError) -> Self {
        match error {
            BrowserStackTransportError::BlockedEnv => Self::BlockedEnv,
            BrowserStackTransportError::CredentialUnavailable => {
                Self::Credential("credential unavailable".to_owned())
            }
            BrowserStackTransportError::Status { status, .. } => Self::UnexpectedStatus { status },
            BrowserStackTransportError::InvalidRequest(detail)
            | BrowserStackTransportError::Decode(detail)
            | BrowserStackTransportError::Transport { detail, .. } => Self::Transport(detail),
            BrowserStackTransportError::UnexpectedBody => {
                Self::Decode("unexpected BrowserStack response body".to_owned())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrowserStackEndpoint {
    Build {
        product: BrowserStackProduct,
        project_id: String,
        build_id: String,
    },
    Sessions {
        product: BrowserStackProduct,
        project_id: String,
        build_id: String,
        offset: u32,
        limit: u16,
    },
    Session {
        product: BrowserStackProduct,
        project_id: String,
        build_id: String,
        session_id: String,
    },
}

impl BrowserStackEndpoint {
    pub fn product(&self) -> BrowserStackProduct {
        match self {
            Self::Build { product, .. }
            | Self::Sessions { product, .. }
            | Self::Session { product, .. } => *product,
        }
    }

    pub fn offset(&self) -> Option<u32> {
        match self {
            Self::Sessions { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    pub fn limit(&self) -> Option<u16> {
        match self {
            Self::Sessions { limit, .. } => Some(*limit),
            _ => None,
        }
    }

    pub fn kind(&self) -> BrowserStackEndpointKind {
        match self {
            Self::Build { .. } => BrowserStackEndpointKind::Build,
            Self::Sessions { .. } => BrowserStackEndpointKind::Sessions,
            Self::Session { .. } => BrowserStackEndpointKind::Session,
        }
    }

    pub fn path_and_query(&self) -> Result<String, BrowserStackTransportError> {
        let mut url = Url::parse(self.product().api_origin())
            .map_err(|error| BrowserStackTransportError::InvalidRequest(error.to_string()))?;
        let area = self.product().api_area();
        match self {
            Self::Build {
                project_id,
                build_id,
                ..
            } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    BrowserStackTransportError::InvalidRequest(
                        "BrowserStack API origin cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push(area)
                    .push("builds")
                    .push(build_id)
                    .push(".json");
                drop(segments);
                url.query_pairs_mut().append_pair("projectId", project_id);
            }
            Self::Sessions {
                project_id,
                build_id,
                offset,
                limit,
                ..
            } => {
                if *limit == 0 || *limit > crate::BROWSERSTACK_MAX_PAGE_SIZE {
                    return Err(BrowserStackTransportError::InvalidRequest(
                        "session page limit is outside the official API bound".to_owned(),
                    ));
                }
                let mut segments = url.path_segments_mut().map_err(|()| {
                    BrowserStackTransportError::InvalidRequest(
                        "BrowserStack API origin cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push(area)
                    .push("builds")
                    .push(build_id)
                    .push("sessions.json");
                drop(segments);
                url.query_pairs_mut()
                    .append_pair("projectId", project_id)
                    .append_pair("limit", &limit.to_string())
                    .append_pair("offset", &offset.to_string());
            }
            Self::Session { session_id, .. } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    BrowserStackTransportError::InvalidRequest(
                        "BrowserStack API origin cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push(area)
                    .push("sessions")
                    .push(session_id)
                    .push(".json");
                drop(segments);
            }
        }
        Ok(url.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserStackEndpointKind {
    Build,
    Sessions,
    Session,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserStackHttpRequest {
    pub endpoint: BrowserStackEndpoint,
    pub api_revision: String,
    pub max_response_bytes: usize,
    pub observed_at: DateTime<Utc>,
}

impl BrowserStackHttpRequest {
    pub fn new(
        endpoint: BrowserStackEndpoint,
        observed_at: DateTime<Utc>,
        max_response_bytes: usize,
    ) -> Result<Self, BrowserStackTransportError> {
        if max_response_bytes == 0 || max_response_bytes > BROWSERSTACK_MAX_RESPONSE_BYTES {
            return Err(BrowserStackTransportError::InvalidRequest(
                "response bound is outside the Layer-1 maximum".to_owned(),
            ));
        }
        endpoint.path_and_query()?;
        Ok(Self {
            endpoint,
            api_revision: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
            max_response_bytes,
            observed_at,
        })
    }

    pub fn path_and_query(&self) -> Result<String, BrowserStackTransportError> {
        self.endpoint.path_and_query()
    }

    pub fn digest(&self) -> Result<Digest, BrowserStackTransportError> {
        let canonical = json!({
            "endpoint": self.path_and_query()?,
            "apiRevision": self.api_revision,
            "maxResponseBytes": self.max_response_bytes,
        });
        digest_serializable(&canonical)
            .map_err(|error| BrowserStackTransportError::InvalidRequest(error.to_string()))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserStackHttpResponse {
    body: Option<BrowserStackResponseBody>,
    receipt: BrowserStackResponseReceipt,
}

impl fmt::Debug for BrowserStackHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserStackHttpResponse")
            .field("body_kind", &self.body.as_ref().map(response_body_kind))
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl BrowserStackHttpResponse {
    /// Normalize one bounded provider JSON body and drop the input bytes
    /// before returning. The bytes are used only for response-size/digest
    /// metadata; no raw provider payload is retained.
    pub fn from_json(
        request: &BrowserStackHttpRequest,
        bytes: &[u8],
    ) -> Result<Self, BrowserStackTransportError> {
        if bytes.len() > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "BrowserStack response exceeds the configured bound".to_owned(),
            ));
        }
        let value = serde_json::from_slice::<Value>(bytes)
            .map_err(|error| BrowserStackTransportError::Decode(error.to_string()))?;
        let body = decode_body(&request.endpoint, &value)?;
        Self::new(request, 200, Some(body), bytes.len(), sha256_digest(bytes))
    }

    pub fn from_body(
        request: &BrowserStackHttpRequest,
        body: BrowserStackResponseBody,
    ) -> Result<Self, BrowserStackTransportError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| BrowserStackTransportError::InvalidRequest(error.to_string()))?;
        Self::new(request, 200, Some(body), bytes.len(), sha256_digest(&bytes))
    }

    pub fn from_status(
        request: &BrowserStackHttpRequest,
        status: u16,
    ) -> Result<Self, BrowserStackTransportError> {
        Self::new(
            request,
            status,
            None,
            0,
            Digest::from_text(format!("http-{status}")),
        )
    }

    pub fn new(
        request: &BrowserStackHttpRequest,
        status: u16,
        body: Option<BrowserStackResponseBody>,
        response_size: usize,
        response_digest: Digest,
    ) -> Result<Self, BrowserStackTransportError> {
        if response_size > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "response exceeds the request bound".to_owned(),
            ));
        }
        let receipt = BrowserStackResponseReceipt {
            request_digest: request.digest()?,
            response_digest,
            endpoint: request.path_and_query()?,
            product: request.endpoint.product(),
            status,
            response_size,
            provider_revision: request.api_revision.clone(),
            offset: request.endpoint.offset(),
            limit: request.endpoint.limit(),
            raw_payload_retained: false,
            raw_logs_retained: false,
            raw_network_retained: false,
            raw_har_retained: false,
            raw_video_retained: false,
            raw_screenshots_retained: false,
            arbitrary_capabilities_retained: false,
            credential_material_retained: false,
            observed_at: request.observed_at,
        };
        receipt.validate().map_err(model_decode_error)?;
        Ok(Self { body, receipt })
    }

    pub fn body(&self) -> Option<&BrowserStackResponseBody> {
        self.body.as_ref()
    }

    pub fn receipt(&self) -> &BrowserStackResponseReceipt {
        &self.receipt
    }

    pub fn status(&self) -> u16 {
        self.receipt.status
    }
}

/// A narrow GET-only authenticated transport. The credential lease is
/// borrowed for the call and is never copied into the request or response.
pub trait BrowserStackTransport: fmt::Debug {
    fn execute(
        &mut self,
        credential: &BrowserStackCredentialLease,
        request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError>;

    fn provenance(&self) -> TransportProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingBrowserStackTransport {
    responses: VecDeque<Result<BrowserStackHttpResponse, BrowserStackTransportError>>,
    requests: Vec<BrowserStackHttpRequest>,
    provenance: TransportProvenance,
}

impl RecordingBrowserStackTransport {
    pub fn new(
        responses: impl IntoIterator<
            Item = Result<BrowserStackHttpResponse, BrowserStackTransportError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<
            Item = Result<BrowserStackHttpResponse, BrowserStackTransportError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Fixture,
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<
            Item = Result<BrowserStackHttpResponse, BrowserStackTransportError>,
        >,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Loopback,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(
        &mut self,
        response: Result<BrowserStackHttpResponse, BrowserStackTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[BrowserStackHttpRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl BrowserStackTransport for RecordingBrowserStackTransport {
    fn execute(
        &mut self,
        credential: &BrowserStackCredentialLease,
        request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError> {
        if credential.username().is_empty() || credential.access_key().is_empty() {
            return Err(BrowserStackTransportError::CredentialUnavailable);
        }
        if request.api_revision != BROWSERSTACK_PROVIDER_REVISION {
            return Err(BrowserStackTransportError::InvalidRequest(
                "recording request used an unsupported BrowserStack provider revision".to_owned(),
            ));
        }
        request.path_and_query()?;
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .ok_or_else(|| BrowserStackTransportError::Transport {
                detail: "recording response queue exhausted".to_owned(),
                retryable: false,
                timeout: false,
                diagnostic_digest: Digest::from_text("recording-queue-exhausted"),
            })?
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

pub type FakeBrowserStackTransport = RecordingBrowserStackTransport;
pub type LoopbackBrowserStackTransport = RecordingBrowserStackTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl BrowserStackTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _credential: &BrowserStackCredentialLease,
        _request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError> {
        Err(BrowserStackTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

/// Production read transport for the official Automate and App Automate
/// JSON endpoints. It remains Layer-1 evidence and never grants Connected or
/// native authority.
pub struct UreqBrowserStackTransport {
    origin: Option<String>,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqBrowserStackTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqBrowserStackTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl UreqBrowserStackTransport {
    pub fn new(origin: impl Into<String>) -> Result<Self, BrowserStackTestResultError> {
        let origin = origin.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&origin).map_err(|error| {
            BrowserStackTestResultError::InvalidInput(format!(
                "BrowserStack origin is invalid: {error}"
            ))
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != ""
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(BrowserStackTestResultError::InvalidInput(
                "BrowserStack origin must be HTTPS without credentials, path, or query".to_owned(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-browserstack-test-result/1")
            .timeout_global(Some(StdDuration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            origin: Some(origin),
            agent,
        })
    }

    pub fn for_product(product: BrowserStackProduct) -> Result<Self, BrowserStackTestResultError> {
        Self::new(product.api_origin())
    }

    pub fn browserstack() -> Result<Self, BrowserStackTestResultError> {
        Self::new(BROWSERSTACK_AUTOMATE_API_ORIGIN)
    }

    fn endpoint_url(
        &self,
        endpoint: &BrowserStackEndpoint,
    ) -> Result<String, BrowserStackTransportError> {
        let origin = self.origin.as_deref().ok_or_else(|| {
            BrowserStackTransportError::InvalidRequest("transport origin is unavailable".to_owned())
        })?;
        let mut url =
            Url::parse(origin).map_err(|error| BrowserStackTransportError::Transport {
                detail: error.to_string(),
                retryable: false,
                timeout: false,
                diagnostic_digest: Digest::from_text(error.to_string()),
            })?;
        let relative = Url::parse(&endpoint.path_and_query()?).map_err(|error| {
            BrowserStackTransportError::Transport {
                detail: error.to_string(),
                retryable: false,
                timeout: false,
                diagnostic_digest: Digest::from_text(error.to_string()),
            }
        })?;
        url.set_path(relative.path());
        url.set_query(relative.query());
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        credential: &BrowserStackCredentialLease,
        request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError> {
        let url = self.endpoint_url(&request.endpoint)?;
        let auth_value = format!("{}:{}", credential.username(), credential.access_key());
        let authorization = format!("Basic {}", BASE64_STANDARD.encode(auth_value.as_bytes()));
        let mut response = self
            .agent
            .get(&url)
            .header("Authorization", authorization)
            .header("Accept", "application/json")
            .call()
            .map_err(classify_ureq_error)?;
        let status = response.status().as_u16();
        let response_limit = u64::try_from(request.max_response_bytes)
            .map_err(|error| BrowserStackTransportError::InvalidRequest(error.to_string()))?
            .saturating_add(1);
        let body = response
            .body_mut()
            .with_config()
            .limit(response_limit)
            .read_to_string()
            .map_err(classify_ureq_error)?;
        let response_size = body.len();
        if response_size > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "BrowserStack response exceeds the configured bound".to_owned(),
            ));
        }
        let response_digest = sha256_digest(body.as_bytes());
        let value = serde_json::from_str::<Value>(&body)
            .map_err(|error| BrowserStackTransportError::Decode(error.to_string()))?;
        let normalized_body = decode_body(&request.endpoint, &value)?;
        BrowserStackHttpResponse::new(
            request,
            status,
            Some(normalized_body),
            response_size,
            response_digest,
        )
    }
}

impl BrowserStackTransport for UreqBrowserStackTransport {
    fn execute(
        &mut self,
        credential: &BrowserStackCredentialLease,
        request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError> {
        if credential.username().trim().is_empty()
            || credential.access_key().trim().is_empty()
            || credential.username().chars().any(char::is_control)
            || credential.access_key().chars().any(char::is_control)
        {
            return Err(BrowserStackTransportError::CredentialUnavailable);
        }
        if request.api_revision != BROWSERSTACK_PROVIDER_REVISION {
            return Err(BrowserStackTransportError::InvalidRequest(
                "BrowserStack provider revision is unsupported".to_owned(),
            ));
        }
        self.get_json(credential, request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::ProductionRead
    }
}

fn classify_ureq_error(error: ureq::Error) -> BrowserStackTransportError {
    match error {
        ureq::Error::StatusCode(status) => BrowserStackTransportError::status(status),
        other => {
            let detail = other.to_string();
            let timeout = detail.to_ascii_lowercase().contains("timeout");
            BrowserStackTransportError::Transport {
                retryable: true,
                timeout,
                diagnostic_digest: Digest::from_text(&detail),
                detail,
            }
        }
    }
}

fn decode_body(
    endpoint: &BrowserStackEndpoint,
    value: &Value,
) -> Result<BrowserStackResponseBody, BrowserStackTransportError> {
    match endpoint.kind() {
        BrowserStackEndpointKind::Build => {
            parse_build(value, endpoint.product()).map(BrowserStackResponseBody::Build)
        }
        BrowserStackEndpointKind::Sessions => {
            let build_id = match endpoint {
                BrowserStackEndpoint::Sessions { build_id, .. } => build_id.as_str(),
                _ => unreachable!("endpoint kind and variant agree"),
            };
            parse_sessions(value, endpoint.product(), build_id)
                .map(BrowserStackResponseBody::Sessions)
        }
        BrowserStackEndpointKind::Session => {
            let build_id = match endpoint {
                BrowserStackEndpoint::Session { build_id, .. } => Some(build_id.as_str()),
                _ => unreachable!("endpoint kind and variant agree"),
            };
            parse_session(value, endpoint.product(), build_id)
                .map(BrowserStackResponseBody::Session)
        }
    }
}

fn parse_build(
    value: &Value,
    product: BrowserStackProduct,
) -> Result<BrowserStackBuildPayload, BrowserStackTransportError> {
    let value = unwrap_object(value, &["automation_build", "app_automate_build", "build"])
        .or_else(|| {
            value
                .as_array()
                .and_then(|values| values.first())
                .and_then(|item| {
                    unwrap_object(item, &["automation_build", "app_automate_build", "build"])
                })
        })
        .ok_or(BrowserStackTransportError::UnexpectedBody)?;
    let id = required_text(value, &["hashed_id", "build_hashed_id", "id"], "build id")?;
    let status =
        optional_text(value, &["status", "status_label"]).unwrap_or_else(|| "unknown".to_owned());
    let revision = optional_positive_u64(value, &["revision", "build_revision"]).unwrap_or(1);
    let mut payload =
        BrowserStackBuildPayload::new(id, product, status, revision).map_err(model_decode_error)?;
    payload.project_id = optional_text(value, &["project_id", "projectId", "project_name"]);
    payload.name = optional_text(value, &["name", "build_name"]);
    payload.duration_seconds = optional_u64(value, &["duration", "duration_seconds"]);
    payload.started_at = optional_datetime(value, &["start_time", "started_at", "created_at"])?;
    payload.finished_at = optional_datetime(value, &["end_time", "finished_at", "updated_at"])?;
    payload.commit = optional_safe_identifier(value, &["commit_hash", "commit", "source_version"]);
    payload.artifact = optional_artifact(value);
    payload.session_count = optional_u64(value, &["session_count", "sessions_count"])
        .and_then(|count| u32::try_from(count).ok());
    payload.validate().map_err(model_decode_error)?;
    Ok(payload)
}

fn parse_sessions(
    value: &Value,
    product: BrowserStackProduct,
    build_id: &str,
) -> Result<Vec<BrowserStackSessionPayload>, BrowserStackTransportError> {
    let values = value
        .as_array()
        .or_else(|| value.get("sessions").and_then(Value::as_array))
        .ok_or(BrowserStackTransportError::UnexpectedBody)?;
    if values.len() > crate::BROWSERSTACK_MAX_PAGE_SIZE as usize {
        return Err(BrowserStackTransportError::InvalidRequest(
            "BrowserStack session page exceeds the official page bound".to_owned(),
        ));
    }
    values
        .iter()
        .map(|item| parse_session(item, product, Some(build_id)))
        .collect()
}

fn parse_session(
    value: &Value,
    product: BrowserStackProduct,
    context_build_id: Option<&str>,
) -> Result<BrowserStackSessionPayload, BrowserStackTransportError> {
    let value = unwrap_object(
        value,
        &["automation_session", "app_automate_session", "session"],
    )
    .unwrap_or(value);
    let id = required_text(value, &["hashed_id", "session_id", "id"], "session id")?;
    let build_id = context_build_id
        .map(str::to_owned)
        .or_else(|| {
            required_text(
                value,
                &["build_hashed_id", "build_id", "buildId"],
                "session build id",
            )
            .ok()
        })
        .unwrap_or_else(|| "unknown-build".to_owned());
    let status =
        optional_text(value, &["status", "status_label"]).unwrap_or_else(|| "unknown".to_owned());
    let revision = optional_positive_u64(value, &["revision", "session_revision"]).unwrap_or(1);
    let matrix = BrowserStackMatrixEntry::new(
        optional_text(value, &["device", "device_name"]),
        optional_text(value, &["browser", "browser_name"]),
        optional_text(value, &["browser_version"]),
        optional_text(value, &["os", "os_name", "platform"]),
        optional_text(value, &["os_version", "platform_version"]),
    )
    .map_err(model_decode_error)?;
    let outcomes = parse_outcomes(value)?;
    let mut payload =
        BrowserStackSessionPayload::new(id, build_id, product, status, revision, matrix, outcomes)
            .map_err(model_decode_error)?;
    payload.project_id = optional_text(value, &["project_id", "projectId", "project_name"]);
    payload.name = optional_text(value, &["name", "test_name"]);
    payload.duration_seconds = optional_u64(value, &["duration", "duration_seconds"]);
    payload.started_at = optional_datetime(value, &["start_time", "started_at", "created_at"])?;
    payload.finished_at = optional_datetime(value, &["end_time", "finished_at", "updated_at"])?;
    payload.commit = optional_safe_identifier(value, &["commit_hash", "commit", "source_version"]);
    payload.artifact = optional_artifact(value);
    payload.validate().map_err(model_decode_error)?;
    Ok(payload)
}

fn parse_outcomes(value: &Value) -> Result<OutcomeCounts, BrowserStackTransportError> {
    let summary = value
        .get("test_results")
        .or_else(|| value.get("testcases_summary"))
        .or_else(|| value.get("test_cases_summary"));
    if let Some(summary) = summary.and_then(Value::as_object) {
        let counts = OutcomeCounts::new(
            bounded_count(summary.get("total")),
            bounded_count(summary.get("passed")),
            bounded_count(summary.get("failed")),
            bounded_count(summary.get("skipped")),
            bounded_count(summary.get("timed_out").or_else(|| summary.get("timeout"))),
            bounded_count(summary.get("unknown")),
        )
        .map_err(model_decode_error)?;
        return Ok(counts);
    }
    let cases = value
        .get("testcases")
        .or_else(|| value.get("test_cases"))
        .and_then(Value::as_array);
    let Some(cases) = cases else {
        return Ok(OutcomeCounts::default());
    };
    if cases.len() > crate::BROWSERSTACK_MAX_OUTCOME_COUNT as usize {
        return Err(BrowserStackTransportError::InvalidRequest(
            "BrowserStack test outcome count exceeds the Layer-1 bound".to_owned(),
        ));
    }
    let mut counts = OutcomeCounts {
        total: u32::try_from(cases.len())
            .map_err(|error| BrowserStackTransportError::InvalidRequest(error.to_string()))?,
        ..OutcomeCounts::default()
    };
    for case in cases {
        match optional_text(case, &["status", "result"])
            .unwrap_or_else(|| "unknown".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "passed" | "pass" | "done" => counts.passed += 1,
            "failed" | "fail" => counts.failed += 1,
            "skipped" | "skip" => counts.skipped += 1,
            "timeout" | "timed_out" | "timedout" => counts.timed_out += 1,
            _ => counts.unknown += 1,
        }
    }
    counts.validate().map_err(model_decode_error)?;
    Ok(counts)
}

fn bounded_count(value: Option<&Value>) -> u32 {
    value
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0)
        .min(crate::BROWSERSTACK_MAX_OUTCOME_COUNT)
}

fn unwrap_object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let object = value.as_object()?;
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(|value| value.as_object().map(|_| value))
}

fn required_text(
    value: &Value,
    keys: &[&str],
    field: &'static str,
) -> Result<String, BrowserStackTransportError> {
    optional_text(value, keys)
        .ok_or_else(|| BrowserStackTransportError::Decode(format!("missing or invalid {field}")))
}

fn optional_text(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= crate::model::MAX_IDENTIFIER_BYTES
                        && value.chars().all(|character| !character.is_control())
                })
                .map(str::to_owned)
                .or_else(|| value.as_u64().map(|value| value.to_string()))
        })
    })
}

fn optional_safe_identifier(value: &Value, keys: &[&str]) -> Option<String> {
    optional_text(value, keys).filter(|value| {
        value.len() <= crate::model::MAX_IDENTIFIER_BYTES
            && !value.contains("://")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-' || byte == b'_')
    })
}

fn optional_artifact(value: &Value) -> Option<String> {
    optional_text(
        value,
        &["artifact_id", "artifact_hash", "app_hash", "artifact_name"],
    )
}

fn optional_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
    })
}

fn optional_positive_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    optional_u64(value, keys).filter(|value| *value > 0)
}

fn optional_datetime(
    value: &Value,
    keys: &[&str],
) -> Result<Option<DateTime<Utc>>, BrowserStackTransportError> {
    let Some(value) = optional_text(value, keys) else {
        return Ok(None);
    };
    if value.len() > crate::model::MAX_TIMESTAMP_BYTES {
        return Err(BrowserStackTransportError::Decode(
            "BrowserStack timestamp exceeds the evidence bound".to_owned(),
        ));
    }
    DateTime::parse_from_rfc3339(&value)
        .map(|value| Some(value.with_timezone(&Utc)))
        .map_err(|error| BrowserStackTransportError::Decode(error.to_string()))
}

#[allow(clippy::needless_pass_by_value)]
fn model_decode_error(error: crate::model::ModelError) -> BrowserStackTransportError {
    BrowserStackTransportError::Decode(error.to_string())
}

fn response_body_kind(body: &BrowserStackResponseBody) -> &'static str {
    match body {
        BrowserStackResponseBody::Build(_) => "build",
        BrowserStackResponseBody::Sessions(_) => "sessions",
        BrowserStackResponseBody::Session(_) => "session",
    }
}

// Keep these imports and the public safe request shape close to the transport
// implementation so future API additions cannot accidentally introduce a
// raw-capability or media endpoint.
#[allow(dead_code)]
fn _bounded_request_shape(bounds: RequestBounds, revision: Revision) -> (RequestBounds, Revision) {
    (bounds, revision)
}
