use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    EvidenceState, ModelError, TailscaleOperation, TailscaleRateLimitReceipt, TailscaleReadRequest,
    TailscaleResponse, TransportProvenance,
};
use crate::{
    BLOCKED_ENV, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION,
    TAILSCALE_API_DOCUMENTATION, canonical_digest, provider_manifest_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleCall {
    pub operation: TailscaleOperation,
    pub path: String,
    pub request_digest: String,
    pub scope_digest: String,
    pub revision_fence_digest: String,
    pub response_digest: Option<String>,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type RecordedRequest = TailscaleReadRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub documentation_url: String,
    pub provider_digest: String,
    pub operations: Vec<String>,
    pub max_response_bytes: usize,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl TailscaleProviderDefinition {
    #[must_use]
    pub fn baseline() -> Self {
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            documentation_url: TAILSCALE_API_DOCUMENTATION.to_owned(),
            provider_digest: provider_manifest_digest(),
            operations: vec![
                TailscaleOperation::Devices.path().to_owned(),
                TailscaleOperation::DevicePosture.path().to_owned(),
                TailscaleOperation::AclPolicy.path().to_owned(),
                TailscaleOperation::Grants.path().to_owned(),
            ],
            max_response_bytes: MAX_RESPONSE_BYTES,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn validate(&self) -> Result<(), TailscaleProviderError> {
        if self != &Self::baseline() {
            Err(TailscaleProviderError::ProviderDrift)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("Tailscale native transport is unavailable: {BLOCKED_ENV}")]
    BlockedEnv,
    #[error("Tailscale transport timed out")]
    Timeout,
    #[error("Tailscale access was denied or the session was unavailable")]
    Denied,
    #[error("Tailscale credential or access grant expired")]
    Expired,
    #[error("Tailscale transport returned a partial response")]
    Partial,
    #[error("Tailscale transport was rate limited")]
    RateLimited { retry_after_seconds: u32 },
    #[error("Tailscale provider returned an unknown transport failure")]
    ProviderUnknown,
}

impl TransportError {
    #[must_use]
    pub const fn evidence_state(&self) -> EvidenceState {
        match self {
            Self::BlockedEnv | Self::Timeout | Self::ProviderUnknown => {
                EvidenceState::ProviderUnknown
            }
            Self::Denied => EvidenceState::Denied,
            Self::Expired => EvidenceState::Expired,
            Self::Partial => EvidenceState::Partial,
            Self::RateLimited { .. } => EvidenceState::RateLimited,
        }
    }
}

pub trait TailscaleTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TransportError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TailscaleProviderError {
    #[error("Tailscale request is outside the exact registered scope")]
    ScopeMismatch,
    #[error("Tailscale provider definition drifted")]
    ProviderDrift,
    #[error("Tailscale request is not on the Layer-1 read allowlist")]
    NotAllowlisted,
    #[error("Tailscale rate-limit receipt is invalid")]
    InvalidRateLimitReceipt,
    #[error("Tailscale response exceeded the Layer-1 response bound")]
    ResponseTooLarge {
        request: TailscaleReadRequest,
        response_digest: String,
        response_bytes: usize,
    },
    #[error("Tailscale response returned HTTP status {status_code}")]
    HttpStatus {
        request: TailscaleReadRequest,
        status_code: u16,
        response_digest: String,
        response_bytes: usize,
    },
    #[error("Tailscale response is malformed")]
    MalformedResponse {
        request: TailscaleReadRequest,
        response_digest: String,
        response_bytes: usize,
    },
    #[error("Tailscale request was rate limited")]
    RateLimited {
        request: TailscaleReadRequest,
        response_digest: String,
        response_bytes: usize,
        rate_limit: TailscaleRateLimitReceipt,
    },
    #[error("Tailscale response failed the scope or revision fence")]
    ResponseTamper {
        request: TailscaleReadRequest,
        response_digest: String,
        response_bytes: usize,
    },
    #[error("Tailscale transport failed")]
    Transport {
        request: TailscaleReadRequest,
        error: TransportError,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl TailscaleProviderError {
    #[must_use]
    pub const fn evidence_state(&self) -> Option<EvidenceState> {
        match self {
            Self::RateLimited { .. } => Some(EvidenceState::RateLimited),
            Self::ResponseTamper { .. } => Some(EvidenceState::Tamper),
            Self::Transport { error, .. } => Some(error.evidence_state()),
            Self::HttpStatus { status_code, .. } => match status_code {
                401 | 403 => Some(EvidenceState::Denied),
                404 | 410 => Some(EvidenceState::Expired),
                429 => Some(EvidenceState::RateLimited),
                206 => Some(EvidenceState::Partial),
                _ => Some(EvidenceState::ProviderUnknown),
            },
            Self::ResponseTooLarge { .. } | Self::MalformedResponse { .. } => {
                Some(EvidenceState::ProviderUnknown)
            }
            Self::ScopeMismatch
            | Self::ProviderDrift
            | Self::NotAllowlisted
            | Self::InvalidRateLimitReceipt
            | Self::Model(_) => None,
        }
    }

    #[must_use]
    pub fn request(&self) -> Option<&TailscaleReadRequest> {
        match self {
            Self::ResponseTooLarge { request, .. }
            | Self::HttpStatus { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::RateLimited { request, .. }
            | Self::ResponseTamper { request, .. }
            | Self::Transport { request, .. } => Some(request),
            Self::ScopeMismatch
            | Self::ProviderDrift
            | Self::NotAllowlisted
            | Self::InvalidRateLimitReceipt
            | Self::Model(_) => None,
        }
    }
}

pub struct TailscaleProvider<T: TailscaleTransport> {
    transport: T,
    definition: TailscaleProviderDefinition,
    calls: Vec<TailscaleCall>,
}

impl<T: TailscaleTransport> fmt::Debug for TailscaleProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TailscaleProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .field("call_count", &self.calls.len())
            .finish()
    }
}

impl<T: TailscaleTransport> TailscaleProvider<T> {
    pub fn new(transport: T) -> Result<Self, TailscaleProviderError> {
        let definition = TailscaleProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            calls: Vec::new(),
        })
    }

    #[must_use]
    pub fn definition(&self) -> &TailscaleProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn calls(&self) -> &[TailscaleCall] {
        &self.calls
    }

    pub fn read(
        &mut self,
        request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TailscaleProviderError> {
        if !request.operation.is_allowlisted() {
            return Err(TailscaleProviderError::NotAllowlisted);
        }
        let provenance = self.provenance();
        let result = self.transport.execute(request);
        match result {
            Ok(response) => {
                let response_digest = response.response_digest();
                let response_bytes = response.response_bytes();
                self.calls.push(TailscaleCall {
                    operation: request.operation,
                    path: request.operation.path().to_owned(),
                    request_digest: request.request_digest(),
                    scope_digest: request.scope_digest.clone(),
                    revision_fence_digest: request.revision_fence_digest.clone(),
                    response_digest: Some(response_digest.clone()),
                    response_bytes,
                    provenance,
                    connected: false,
                    native: false,
                    first_party: false,
                });
                response
                    .rate_limit()
                    .validate()
                    .map_err(|_| TailscaleProviderError::InvalidRateLimitReceipt)?;
                if response_bytes > MAX_RESPONSE_BYTES {
                    return Err(TailscaleProviderError::ResponseTooLarge {
                        request: request.clone(),
                        response_digest,
                        response_bytes,
                    });
                }
                if response.rate_limit().exhausted {
                    return Err(TailscaleProviderError::RateLimited {
                        request: request.clone(),
                        response_digest,
                        response_bytes,
                        rate_limit: response.rate_limit().clone(),
                    });
                }
                if !(200..=299).contains(&response.status()) {
                    return Err(TailscaleProviderError::HttpStatus {
                        request: request.clone(),
                        status_code: response.status(),
                        response_digest,
                        response_bytes,
                    });
                }
                Ok(response)
            }
            Err(error) => {
                self.calls.push(TailscaleCall {
                    operation: request.operation,
                    path: request.operation.path().to_owned(),
                    request_digest: request.request_digest(),
                    scope_digest: request.scope_digest.clone(),
                    revision_fence_digest: request.revision_fence_digest.clone(),
                    response_digest: None,
                    response_bytes: 0,
                    provenance,
                    connected: false,
                    native: false,
                    first_party: false,
                });
                Err(TailscaleProviderError::Transport {
                    request: request.clone(),
                    error,
                })
            }
        }
    }
}

impl Default for TailscaleProvider<BlockedEnvTailscaleTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTailscaleTransport).expect("baseline blocked provider")
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTailscaleTransport {
    response: TailscaleResponse,
}

impl FixtureTailscaleTransport {
    #[must_use]
    pub const fn new(response: TailscaleResponse) -> Self {
        Self { response }
    }

    #[must_use]
    pub fn for_scope(scope: &crate::TailscaleNetworkPostureScope) -> Self {
        let payload = serde_json::json!({
            "devices": [{
                "id": scope.device.id.as_str(),
                "tags": [scope.tag.id.as_str()],
                "posture": "compliant",
                "revision": scope.device.revision.get()
            }],
            "acls": [{"revision": scope.acl.revision.get()}],
            "grants": [{"decision": "allow", "revision": scope.grant.revision.get()}],
            "revision": scope.scope_revision.get()
        });
        Self::new(TailscaleResponse::json(200, &payload))
    }
}

impl TailscaleTransport for FixtureTailscaleTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTailscaleTransport {
    response: TailscaleResponse,
    requests: Vec<TailscaleReadRequest>,
}

impl RecordingTailscaleTransport {
    #[must_use]
    pub const fn new(response: TailscaleResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[TailscaleReadRequest] {
        &self.requests
    }
}

impl TailscaleTransport for RecordingTailscaleTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeTailscaleTransport {
    responses: VecDeque<Result<TailscaleResponse, TransportError>>,
    requests: Vec<TailscaleReadRequest>,
}

impl FakeTailscaleTransport {
    #[must_use]
    pub fn new(response: TailscaleResponse) -> Self {
        let mut transport = Self::default();
        transport.push_response(response);
        transport
    }

    pub fn push_response(&mut self, response: TailscaleResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: TransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[TailscaleReadRequest] {
        &self.requests
    }
}

impl TailscaleTransport for FakeTailscaleTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn execute(
        &mut self,
        request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTailscaleTransport {
    response: TailscaleResponse,
}

impl LoopbackTailscaleTransport {
    #[must_use]
    pub const fn new(response: TailscaleResponse) -> Self {
        Self { response }
    }
}

impl TailscaleTransport for LoopbackTailscaleTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTailscaleTransport;

impl TailscaleTransport for BlockedEnvTailscaleTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &TailscaleReadRequest,
    ) -> Result<TailscaleResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub type FixtureTransport = FixtureTailscaleTransport;
pub type RecordingTransport = RecordingTailscaleTransport;
pub type FakeTransport = FakeTailscaleTransport;
pub type LoopbackTransport = LoopbackTailscaleTransport;
pub type BlockedEnvTransport = BlockedEnvTailscaleTransport;

pub type BlockedEnvTransportError = TransportError;
