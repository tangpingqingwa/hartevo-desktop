//! GET-only BrowserStack Automate/App Automate transport.
//!
//! Fixture, recording, loopback, and blocked-environment transports normalize
//! only the fields allowed by the contract. Layer-2 secret resolution and live
//! HTTPS reads are intentionally outside this root.

use std::{any::Any, collections::VecDeque, fmt};

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
    BROWSERSTACK_MAX_RESPONSE_BYTES, BROWSERSTACK_PROVIDER_REVISION, BrowserStackTestResultError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrowserStackTransportError {
    #[error("BrowserStack credential is unavailable")]
    CredentialUnavailable,
    #[error("BrowserStack transport provenance is not trusted for Layer 1")]
    Unattested,
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
    #[error("BrowserStack response receipt does not match its normalized response")]
    ResponseIntegrityMismatch,
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
            | Self::Unattested
            | Self::InvalidRequest(_)
            | Self::UnexpectedBody
            | Self::ResponseIntegrityMismatch
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
            Self::Unattested => Digest::from_text("unattested-transport"),
            Self::ResponseIntegrityMismatch => Digest::from_text("response-integrity-mismatch"),
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
            BrowserStackTransportError::Unattested => Self::UnattestedTransport,
            BrowserStackTransportError::Status { status, .. } => Self::UnexpectedStatus { status },
            BrowserStackTransportError::InvalidRequest(detail)
            | BrowserStackTransportError::Decode(detail)
            | BrowserStackTransportError::Transport { detail, .. } => Self::Transport(detail),
            BrowserStackTransportError::UnexpectedBody => {
                Self::Decode("unexpected BrowserStack response body".to_owned())
            }
            BrowserStackTransportError::ResponseIntegrityMismatch => Self::StaleEvidence,
        }
    }
}

/// A process-local, non-native transport attestation. Its fields are private
/// so external transports cannot manufacture a trusted provenance claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserStackTransportAttestation {
    provenance: TransportProvenance,
    native_io: bool,
}

impl BrowserStackTransportAttestation {
    fn trusted(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            native_io: false,
        }
    }

    pub const fn provenance(self) -> TransportProvenance {
        self.provenance
    }

    pub const fn native_io(self) -> bool {
        self.native_io
    }

    fn validate(self) -> Result<Self, BrowserStackTransportError> {
        if self.native_io {
            Err(BrowserStackTransportError::Unattested)
        } else {
            Ok(self)
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
        let request = Self {
            endpoint,
            api_revision: BROWSERSTACK_PROVIDER_REVISION.to_owned(),
            max_response_bytes,
            observed_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), BrowserStackTransportError> {
        if self.api_revision != BROWSERSTACK_PROVIDER_REVISION
            || self.max_response_bytes == 0
            || self.max_response_bytes > BROWSERSTACK_MAX_RESPONSE_BYTES
        {
            return Err(BrowserStackTransportError::InvalidRequest(
                "BrowserStack request identity or response bound is invalid".to_owned(),
            ));
        }
        self.endpoint.path_and_query()?;
        Ok(())
    }

    pub fn path_and_query(&self) -> Result<String, BrowserStackTransportError> {
        self.endpoint.path_and_query()
    }

    pub fn digest(&self) -> Result<Digest, BrowserStackTransportError> {
        let canonical = json!({
            "schemaVersion": crate::BROWSERSTACK_SCHEMA_VERSION,
            "serviceId": crate::BROWSERSTACK_SERVICE_ID,
            "providerId": crate::BROWSERSTACK_PROVIDER_ID,
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
        request.validate()?;
        if bytes.len() > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "BrowserStack response exceeds the configured bound".to_owned(),
            ));
        }
        let value = serde_json::from_slice::<Value>(bytes)
            .map_err(|error| BrowserStackTransportError::Decode(error.to_string()))?;
        let body = decode_body(&request.endpoint, &value)?;
        let normalized = normalized_body_bytes(Some(&body))?;
        if normalized.len() > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "normalized BrowserStack response exceeds the configured bound".to_owned(),
            ));
        }
        let response_digest =
            canonical_response_digest(request, 200, normalized.len(), &normalized)?;
        Self::new(request, 200, Some(body), normalized.len(), &response_digest)
    }

    pub fn from_body(
        request: &BrowserStackHttpRequest,
        body: BrowserStackResponseBody,
    ) -> Result<Self, BrowserStackTransportError> {
        let normalized = normalized_body_bytes(Some(&body))?;
        let response_digest =
            canonical_response_digest(request, 200, normalized.len(), &normalized)?;
        Self::new(request, 200, Some(body), normalized.len(), &response_digest)
    }

    pub fn from_status(
        request: &BrowserStackHttpRequest,
        status: u16,
    ) -> Result<Self, BrowserStackTransportError> {
        let response_digest = canonical_response_digest(request, status, 0, &[])?;
        Self::new(request, status, None, 0, &response_digest)
    }

    fn new(
        request: &BrowserStackHttpRequest,
        status: u16,
        body: Option<BrowserStackResponseBody>,
        response_size: usize,
        response_digest: &Digest,
    ) -> Result<Self, BrowserStackTransportError> {
        validate_response_shape(request, status, body.as_ref())?;
        let normalized = normalized_body_bytes(body.as_ref())?;
        if normalized.len() > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "normalized BrowserStack response exceeds the request bound".to_owned(),
            ));
        }
        let expected_digest =
            canonical_response_digest(request, status, normalized.len(), &normalized)?;
        if response_size != normalized.len() || response_digest != &expected_digest {
            return Err(BrowserStackTransportError::ResponseIntegrityMismatch);
        }
        let receipt = BrowserStackResponseReceipt {
            request_digest: request.digest()?,
            response_digest: expected_digest,
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

    pub fn validate_against(
        &self,
        request: &BrowserStackHttpRequest,
    ) -> Result<(), BrowserStackTransportError> {
        validate_response_shape(request, self.receipt.status, self.body.as_ref())?;
        let normalized = normalized_body_bytes(self.body.as_ref())?;
        if normalized.len() > request.max_response_bytes {
            return Err(BrowserStackTransportError::InvalidRequest(
                "normalized BrowserStack response exceeds the request bound".to_owned(),
            ));
        }
        let expected_digest =
            canonical_response_digest(request, self.receipt.status, normalized.len(), &normalized)?;
        if self.receipt.request_digest != request.digest()?
            || self.receipt.endpoint != request.path_and_query()?
            || self.receipt.product != request.endpoint.product()
            || self.receipt.provider_revision != request.api_revision
            || self.receipt.response_size != normalized.len()
            || self.receipt.response_digest != expected_digest
            || self.receipt.offset != request.endpoint.offset()
            || self.receipt.limit != request.endpoint.limit()
        {
            return Err(BrowserStackTransportError::ResponseIntegrityMismatch);
        }
        self.receipt.validate().map_err(model_decode_error)
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

fn normalized_body_bytes(
    body: Option<&BrowserStackResponseBody>,
) -> Result<Vec<u8>, BrowserStackTransportError> {
    body.map(serde_json::to_vec)
        .transpose()
        .map_err(|error| BrowserStackTransportError::InvalidRequest(error.to_string()))
        .map(Option::unwrap_or_default)
}

fn canonical_response_digest(
    request: &BrowserStackHttpRequest,
    status: u16,
    normalized_size: usize,
    normalized_body: &[u8],
) -> Result<Digest, BrowserStackTransportError> {
    let body_digest = sha256_digest(normalized_body);
    Ok(Digest::from_fields(
        "browserstack-response/v2",
        &[
            request.digest()?.as_str().to_owned(),
            request.path_and_query()?,
            request.api_revision.clone(),
            format!("{:?}", request.endpoint.product()),
            status.to_string(),
            normalized_size.to_string(),
            body_digest.as_str().to_owned(),
        ],
    ))
}

fn validate_response_shape(
    request: &BrowserStackHttpRequest,
    status: u16,
    body: Option<&BrowserStackResponseBody>,
) -> Result<(), BrowserStackTransportError> {
    if (status == 200) != body.is_some() {
        return Err(BrowserStackTransportError::UnexpectedBody);
    }
    let Some(body) = body else {
        return Ok(());
    };
    match (&request.endpoint, body) {
        (
            BrowserStackEndpoint::Build {
                product,
                project_id,
                build_id,
            },
            BrowserStackResponseBody::Build(payload),
        ) => {
            payload.validate().map_err(model_decode_error)?;
            if payload.product != *product
                || payload.id != *build_id
                || payload
                    .project_id
                    .as_deref()
                    .is_some_and(|value| value != project_id)
            {
                return Err(BrowserStackTransportError::UnexpectedBody);
            }
        }
        (
            BrowserStackEndpoint::Sessions {
                product,
                project_id,
                build_id,
                limit,
                ..
            },
            BrowserStackResponseBody::Sessions(payloads),
        ) => {
            if payloads.len() > *limit as usize {
                return Err(BrowserStackTransportError::InvalidRequest(
                    "session page exceeds its requested bound".to_owned(),
                ));
            }
            for payload in payloads {
                payload.validate().map_err(model_decode_error)?;
                if payload.product != *product
                    || payload.build_id != *build_id
                    || payload
                        .project_id
                        .as_deref()
                        .is_some_and(|value| value != project_id)
                {
                    return Err(BrowserStackTransportError::UnexpectedBody);
                }
            }
        }
        (
            BrowserStackEndpoint::Session {
                product,
                project_id,
                build_id,
                session_id,
            },
            BrowserStackResponseBody::Session(payload),
        ) => {
            payload.validate().map_err(model_decode_error)?;
            if payload.product != *product
                || payload.id != *session_id
                || payload.build_id != *build_id
                || payload
                    .project_id
                    .as_deref()
                    .is_some_and(|value| value != project_id)
            {
                return Err(BrowserStackTransportError::UnexpectedBody);
            }
        }
        _ => return Err(BrowserStackTransportError::UnexpectedBody),
    }
    Ok(())
}

/// A narrow GET-only authenticated transport. The credential lease is
/// borrowed for the call and is never copied into the request or response.
pub trait BrowserStackTransport: Any + fmt::Debug {
    fn execute(
        &mut self,
        credential: &BrowserStackCredentialLease,
        request: &BrowserStackHttpRequest,
    ) -> Result<BrowserStackHttpResponse, BrowserStackTransportError>;

    /// Untrusted diagnostic metadata. Provider authority is derived from the
    /// concrete built-in transport type, never from this caller-controlled claim.
    fn provenance(&self) -> TransportProvenance;

    /// Untrusted diagnostic metadata. Layer 1 never uses this to establish
    /// native or connected authority.
    fn is_native(&self) -> bool {
        false
    }
}

pub(crate) fn trusted_transport_attestation<T: BrowserStackTransport>(
    transport: &T,
) -> Result<BrowserStackTransportAttestation, BrowserStackTransportError> {
    let transport = transport as &dyn Any;
    if let Some(recording) = transport.downcast_ref::<RecordingBrowserStackTransport>() {
        return recording.trusted_attestation();
    }
    if transport.is::<BlockedEnvTransport>() {
        return BrowserStackTransportAttestation::trusted(TransportProvenance::BlockedEnv)
            .validate();
    }
    Err(BrowserStackTransportError::Unattested)
}

#[derive(Clone, Debug)]
pub struct RecordingBrowserStackTransport {
    responses: VecDeque<Result<BrowserStackHttpResponse, BrowserStackTransportError>>,
    requests: Vec<BrowserStackHttpRequest>,
    provenance: TransportProvenance,
    provenance_override: Option<TransportProvenance>,
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
            provenance_override: None,
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
            provenance_override: None,
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
            provenance_override: None,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance_override = Some(provenance);
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

impl RecordingBrowserStackTransport {
    fn trusted_attestation(
        &self,
    ) -> Result<BrowserStackTransportAttestation, BrowserStackTransportError> {
        if self
            .provenance_override
            .is_some_and(|claimed| claimed != self.provenance)
        {
            return Err(BrowserStackTransportError::Unattested);
        }
        BrowserStackTransportAttestation::trusted(self.provenance).validate()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_request(max_response_bytes: usize) -> BrowserStackHttpRequest {
        BrowserStackHttpRequest::new(
            BrowserStackEndpoint::Build {
                product: BrowserStackProduct::Automate,
                project_id: "project".to_owned(),
                build_id: "build".to_owned(),
            },
            Utc::now(),
            max_response_bytes,
        )
        .expect("request")
    }

    fn build_body() -> BrowserStackResponseBody {
        BrowserStackResponseBody::Build(
            BrowserStackBuildPayload::new("build", BrowserStackProduct::Automate, "done", 1)
                .expect("build"),
        )
    }

    #[test]
    fn response_ingress_rejects_reported_size_digest_and_bound_drift() {
        let request = build_request(BROWSERSTACK_MAX_RESPONSE_BYTES);
        let body = build_body();
        let normalized = normalized_body_bytes(Some(&body)).expect("normalized body");
        let digest = canonical_response_digest(&request, 200, normalized.len(), &normalized)
            .expect("canonical digest");

        assert!(
            BrowserStackHttpResponse::new(
                &request,
                200,
                Some(body.clone()),
                normalized.len() + 1,
                &digest,
            )
            .is_err()
        );
        assert!(
            BrowserStackHttpResponse::new(
                &request,
                200,
                Some(body.clone()),
                normalized.len(),
                &Digest::from_text("caller-reported"),
            )
            .is_err()
        );

        let tiny_request = build_request(1);
        assert!(BrowserStackHttpResponse::from_body(&tiny_request, body).is_err());
        assert!(BrowserStackHttpResponse::from_json(&tiny_request, br"{}").is_err());

        let mut forged_request = request;
        forged_request.api_revision = "caller-controlled-revision".to_owned();
        assert!(BrowserStackHttpResponse::from_status(&forged_request, 404).is_err());
    }

    #[test]
    fn response_receipt_is_canonical_and_revalidates_against_request() {
        let request = build_request(BROWSERSTACK_MAX_RESPONSE_BYTES);
        let body = build_body();
        let normalized = normalized_body_bytes(Some(&body)).expect("normalized body");
        let response = BrowserStackHttpResponse::from_body(&request, body).expect("response");

        assert_eq!(response.receipt().response_size, normalized.len());
        assert_eq!(response.validate_against(&request), Ok(()));
        assert_ne!(
            response.receipt().response_digest,
            sha256_digest(&normalized)
        );
    }
}
