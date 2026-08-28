//! Optional transport seam. Layer 1 exposes the allowlisted request shape,
//! but native credential resolution and live HTTPS execution remain blocked.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    model::{
        ANTHROPIC_API_VERSION, ANTHROPIC_MESSAGES_METHOD, ANTHROPIC_MESSAGES_PATH,
        AnthropicMessageRequest, AnthropicScope, Digest, ProviderProvenance,
    },
    provider::BlockedEnvCode,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnthropicHttpRequest {
    pub method: String,
    pub path: String,
    pub api_version: String,
    pub request_id_digest: Digest,
    pub body_bytes: usize,
}

/// Owned transport response. The service projects and drops the body before
/// constructing evidence; this type is not serializable and its Debug output
/// exposes only response size and digest.
#[derive(Clone)]
pub enum TransportOutcome {
    Http {
        status: u16,
        body: Vec<u8>,
        provider_request_id: Option<String>,
        retry_after_seconds: Option<u64>,
    },
    Timeout,
    TransportUnavailable,
    BlockedEnv {
        code: BlockedEnvCode,
    },
}

impl fmt::Debug for TransportOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http {
                status,
                body,
                provider_request_id,
                retry_after_seconds,
            } => formatter
                .debug_struct("Http")
                .field("status", status)
                .field("response_bytes", &body.len())
                .field("response_digest", &Digest::from_bytes(body))
                .field(
                    "provider_request_id_present",
                    &provider_request_id.is_some(),
                )
                .field("retry_after_seconds", retry_after_seconds)
                .finish(),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::TransportUnavailable => formatter.write_str("TransportUnavailable"),
            Self::BlockedEnv { code } => formatter
                .debug_struct("BlockedEnv")
                .field("code", code)
                .finish(),
        }
    }
}

impl TransportOutcome {
    pub fn http(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Http {
            status,
            body: body.into(),
            provider_request_id: None,
            retry_after_seconds: None,
        }
    }

    pub fn success(body: impl Into<Vec<u8>>) -> Self {
        Self::http(200, body)
    }

    pub const fn timeout() -> Self {
        Self::Timeout
    }

    pub const fn transport_unavailable() -> Self {
        Self::TransportUnavailable
    }

    pub const fn blocked_env(code: BlockedEnvCode) -> Self {
        Self::BlockedEnv { code }
    }

    #[must_use]
    pub fn with_provider_request_id(mut self, value: impl Into<String>) -> Self {
        if let Self::Http {
            provider_request_id,
            ..
        } = &mut self
        {
            *provider_request_id = Some(value.into());
        }
        self
    }

    #[must_use]
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        if let Self::Http {
            retry_after_seconds,
            ..
        } = &mut self
        {
            *retry_after_seconds = Some(seconds);
        }
        self
    }
}

/// Exactly one allowlisted method/path is exposed. There is no method for
/// model creation, registry administration, file upload, batches, or tools.
pub trait AnthropicTransport: fmt::Debug + Send {
    fn post_messages(
        &mut self,
        request: &AnthropicMessageRequest,
        scope: &AnthropicScope,
    ) -> TransportOutcome;

    fn provenance(&self) -> ProviderProvenance;
}

pub fn allowlisted_request(request: &AnthropicMessageRequest) -> AnthropicHttpRequest {
    AnthropicHttpRequest {
        method: ANTHROPIC_MESSAGES_METHOD.to_owned(),
        path: ANTHROPIC_MESSAGES_PATH.to_owned(),
        api_version: ANTHROPIC_API_VERSION.to_owned(),
        request_id_digest: Digest::from_text(request.request_id().as_str()),
        body_bytes: request.wire_body().len(),
    }
}

/// Native transport is an explicit Layer-2 seam, not a live client.
#[derive(Clone, Debug, Default)]
pub struct NativeAnthropicTransport;

impl AnthropicTransport for NativeAnthropicTransport {
    fn post_messages(
        &mut self,
        _request: &AnthropicMessageRequest,
        _scope: &AnthropicScope,
    ) -> TransportOutcome {
        TransportOutcome::blocked_env(BlockedEnvCode::NativeTransportUnavailable)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAnthropicTransport;

impl AnthropicTransport for BlockedEnvAnthropicTransport {
    fn post_messages(
        &mut self,
        _request: &AnthropicMessageRequest,
        _scope: &AnthropicScope,
    ) -> TransportOutcome {
        TransportOutcome::blocked_env(BlockedEnvCode::NativeCredentialResolutionUnavailable)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug, Default)]
struct RecordingState {
    outcome: Option<TransportOutcome>,
    requests: Vec<AnthropicHttpRequest>,
}

/// Deterministic fixture/fake/recording/loopback transport. All variants are
/// explicitly non-connected and non-native; provenance describes test origin.
#[derive(Clone)]
pub struct RecordingAnthropicTransport {
    state: Arc<Mutex<RecordingState>>,
    provenance: ProviderProvenance,
}

impl fmt::Debug for RecordingAnthropicTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingAnthropicTransport")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl RecordingAnthropicTransport {
    pub fn new(provenance: ProviderProvenance, outcome: TransportOutcome) -> Self {
        Self {
            state: Arc::new(Mutex::new(RecordingState {
                outcome: Some(outcome),
                requests: Vec::new(),
            })),
            provenance,
        }
    }

    pub fn recording(body: impl Into<Vec<u8>>) -> Self {
        Self::new(
            ProviderProvenance::Recording,
            TransportOutcome::success(body),
        )
    }

    pub fn fixture(body: impl Into<Vec<u8>>) -> Self {
        Self::new(ProviderProvenance::Fixture, TransportOutcome::success(body))
    }

    pub fn fake(body: impl Into<Vec<u8>>) -> Self {
        Self::new(ProviderProvenance::Fake, TransportOutcome::success(body))
    }

    pub fn loopback(body: impl Into<Vec<u8>>) -> Self {
        Self::new(
            ProviderProvenance::Loopback,
            TransportOutcome::success(body),
        )
    }

    pub fn blocked_env() -> Self {
        Self::new(
            ProviderProvenance::BlockedEnv,
            TransportOutcome::blocked_env(BlockedEnvCode::NativeTransportUnavailable),
        )
    }

    pub fn set_outcome(&self, outcome: TransportOutcome) {
        self.state.lock().expect("recording transport lock").outcome = Some(outcome);
    }

    pub fn seen_requests(&self) -> Vec<AnthropicHttpRequest> {
        self.state
            .lock()
            .expect("recording transport lock")
            .requests
            .clone()
    }
}

impl AnthropicTransport for RecordingAnthropicTransport {
    fn post_messages(
        &mut self,
        request: &AnthropicMessageRequest,
        _scope: &AnthropicScope,
    ) -> TransportOutcome {
        let mut state = self.state.lock().expect("recording transport lock");
        state.requests.push(allowlisted_request(request));
        state
            .outcome
            .clone()
            .unwrap_or_else(TransportOutcome::transport_unavailable)
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

pub type FixtureAnthropicTransport = RecordingAnthropicTransport;
pub type FakeAnthropicTransport = RecordingAnthropicTransport;
pub type LoopbackAnthropicTransport = RecordingAnthropicTransport;
