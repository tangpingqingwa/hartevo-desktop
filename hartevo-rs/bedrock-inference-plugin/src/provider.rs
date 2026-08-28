use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::sync::{Arc, Mutex};

use crate::error::{BedrockError, Result};
use crate::model::{
    DestinationEvidence, GuardrailProjection, InvocationProposal, Layer1Provenance, ModelTarget,
    StopReason, TokenUsage,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransportErrorClass {
    AccessDenied,
    ResourceMissing,
    Validation,
    Throttled,
    Timeout,
    ServiceUnavailable,
}

impl TransportErrorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::ResourceMissing => "resource_missing",
            Self::Validation => "validation",
            Self::Throttled => "throttled",
            Self::Timeout => "timeout",
            Self::ServiceUnavailable => "service_unavailable",
        }
    }
}

/// Layer 2 may provide a least-privilege SigV4 implementation of this seam.
/// Layer 1 intentionally ships no live implementation.
pub trait SigV4ConverseTransport: ConverseTransport {}

pub trait ConverseTransport: Debug + Send + Sync {
    fn provenance(&self) -> Layer1Provenance;
    fn invoke_converse(&self, proposal: &InvocationProposal) -> Result<ProviderResponse>;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderContentBlock {
    Text {
        content_digest: crate::Digest,
    },
    ToolUse {
        tool_use_digest: crate::Digest,
        tool_name_digest: crate::Digest,
        input_digest: crate::Digest,
    },
    Unknown {
        block_digest: crate::Digest,
    },
}

impl ProviderContentBlock {
    pub const fn text(content_digest: crate::Digest) -> Self {
        Self::Text { content_digest }
    }

    pub const fn tool_use(
        tool_use_digest: crate::Digest,
        tool_name_digest: crate::Digest,
        input_digest: crate::Digest,
    ) -> Self {
        Self::ToolUse {
            tool_use_digest,
            tool_name_digest,
            input_digest,
        }
    }

    pub const fn unknown(block_digest: crate::Digest) -> Self {
        Self::Unknown { block_digest }
    }

    fn canonical(&self) -> String {
        match self {
            Self::Text { content_digest } => format!("text:{content_digest}"),
            Self::ToolUse {
                tool_use_digest,
                tool_name_digest,
                input_digest,
            } => format!("tool_use:{tool_use_digest}:{tool_name_digest}:{input_digest}"),
            Self::Unknown { block_digest } => format!("unknown:{block_digest}"),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderResponse {
    aws_request_id: Option<String>,
    model_identity: Option<ModelTarget>,
    stop_reason: StopReason,
    usage: TokenUsage,
    latency_ms: u64,
    safety: GuardrailProjection,
    content: Vec<ProviderContentBlock>,
    destination: DestinationEvidence,
    provenance: Layer1Provenance,
}

impl ProviderResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aws_request_id: Option<String>,
        model_identity: Option<ModelTarget>,
        stop_reason: StopReason,
        usage: TokenUsage,
        latency_ms: u64,
        safety: GuardrailProjection,
        content: Vec<ProviderContentBlock>,
        destination: DestinationEvidence,
        provenance: Layer1Provenance,
    ) -> Result<Self> {
        if let Some(request_id) = &aws_request_id {
            if request_id.is_empty()
                || request_id.len() > 256
                || request_id.bytes().any(|byte| byte.is_ascii_whitespace())
            {
                return Err(BedrockError::InvalidProviderResponse);
            }
        }
        if content.len() > 256 || latency_ms > 86_400_000 {
            return Err(BedrockError::InvalidProviderResponse);
        }
        if let DestinationEvidence::ProviderVerified { region } = &destination {
            if region.as_str().is_empty() {
                return Err(BedrockError::InvalidProviderResponse);
            }
        }
        Ok(Self {
            aws_request_id,
            model_identity,
            stop_reason,
            usage,
            latency_ms,
            safety,
            content,
            destination,
            provenance,
        })
    }

    pub fn aws_request_id(&self) -> Option<&str> {
        self.aws_request_id.as_deref()
    }

    pub const fn model_identity(&self) -> Option<&ModelTarget> {
        self.model_identity.as_ref()
    }

    pub const fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    pub const fn usage(&self) -> &TokenUsage {
        &self.usage
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub const fn safety(&self) -> &GuardrailProjection {
        &self.safety
    }

    pub fn content(&self) -> &[ProviderContentBlock] {
        &self.content
    }

    pub const fn destination(&self) -> &DestinationEvidence {
        &self.destination
    }

    pub const fn provenance(&self) -> Layer1Provenance {
        self.provenance
    }

    pub fn response_digest(&self) -> crate::Digest {
        crate::Digest::of_str(&self.canonical())
    }

    pub fn content_digest(&self) -> crate::Digest {
        let canonical = self
            .content
            .iter()
            .map(ProviderContentBlock::canonical)
            .collect::<Vec<_>>()
            .join("|");
        crate::Digest::of_str(&canonical)
    }

    pub fn with_provenance(mut self, provenance: Layer1Provenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn with_usage(mut self, usage: TokenUsage) -> Self {
        self.usage = usage;
        self
    }

    pub fn with_model_identity(mut self, model_identity: Option<ModelTarget>) -> Self {
        self.model_identity = model_identity;
        self
    }

    pub fn with_destination(mut self, destination: DestinationEvidence) -> Self {
        self.destination = destination;
        self
    }

    pub fn with_stop_reason(mut self, stop_reason: StopReason) -> Self {
        self.stop_reason = stop_reason;
        self
    }

    pub fn with_safety(mut self, safety: GuardrailProjection) -> Self {
        self.safety = safety;
        self
    }

    fn canonical(&self) -> String {
        let request_id = self.aws_request_id.as_deref().unwrap_or("none");
        let model = self
            .model_identity
            .as_ref()
            .map_or_else(|| "none".to_owned(), ModelTarget::canonical);
        let content = self
            .content
            .iter()
            .map(ProviderContentBlock::canonical)
            .collect::<Vec<_>>()
            .join("|");
        let destination = match &self.destination {
            DestinationEvidence::NotDisclosed => "not_disclosed".to_owned(),
            DestinationEvidence::ProviderVerified { region } => {
                format!("provider_verified:{}", region.as_str())
            }
        };
        format!(
            "request_id={request_id};model={model};stop={};usage={}/{}/{};latency={};safety={:?};content={content};destination={destination};provenance={}",
            self.stop_reason.as_str(),
            self.usage.input_tokens(),
            self.usage.output_tokens(),
            self.usage.total_tokens(),
            self.latency_ms,
            self.safety,
            self.provenance.label(),
        )
    }
}

pub struct BedrockConverseProvider {
    transport: Box<dyn ConverseTransport>,
}

impl BedrockConverseProvider {
    pub fn new<T>(transport: T) -> Self
    where
        T: ConverseTransport + 'static,
    {
        Self {
            transport: Box::new(transport),
        }
    }

    pub fn fake(response: ProviderResponse) -> Self {
        Self::new(FakeTransport::new(response))
    }

    pub fn recording(response: ProviderResponse) -> Self {
        Self::new(RecordingTransport::new(response))
    }

    pub fn with_recording_transport(response: ProviderResponse) -> (Self, RecordingTransport) {
        let transport = RecordingTransport::new(response);
        let provider = Self::new(transport.clone());
        (provider, transport)
    }

    pub fn loopback(response: ProviderResponse) -> Self {
        Self::new(LoopbackTransport::new(response))
    }

    pub fn blocked_env() -> Self {
        Self::new(BlockedEnvTransport)
    }

    pub fn provenance(&self) -> Layer1Provenance {
        self.transport.provenance()
    }

    pub fn invoke_converse(&self, proposal: &InvocationProposal) -> Result<ProviderResponse> {
        if proposal.operation() != crate::BEDROCK_CONVERSE_OPERATION || proposal.streaming() {
            return Err(BedrockError::InvalidProviderResponse);
        }
        if proposal.request().config().max_tokens().is_none() {
            return Err(BedrockError::MaxTokensRequired);
        }
        let provenance = self.transport.provenance();
        if provenance.is_live()
            || provenance.claims_connected()
            || provenance.claims_native()
            || provenance.claims_first_party()
        {
            return Err(BedrockError::LiveTransportRejected);
        }
        let response = self.transport.invoke_converse(proposal)?;
        if response.provenance().is_live()
            || response.provenance().claims_connected()
            || response.provenance().claims_native()
            || response.provenance().claims_first_party()
        {
            return Err(BedrockError::LiveTransportRejected);
        }
        Ok(response.with_provenance(provenance))
    }
}

impl Debug for BedrockConverseProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_struct("BedrockConverseProvider")
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    response: Option<ProviderResponse>,
    error: Option<TransportErrorClass>,
}

impl FakeTransport {
    pub fn new(response: ProviderResponse) -> Self {
        Self {
            response: Some(response.with_provenance(Layer1Provenance::Fixture)),
            error: None,
        }
    }

    pub fn error(error: TransportErrorClass) -> Self {
        Self {
            response: None,
            error: Some(error),
        }
    }
}

impl ConverseTransport for FakeTransport {
    fn provenance(&self) -> Layer1Provenance {
        Layer1Provenance::Fixture
    }

    fn invoke_converse(&self, _proposal: &InvocationProposal) -> Result<ProviderResponse> {
        if let Some(error) = self.error {
            return Err(BedrockError::Transport {
                class: error.as_str(),
            });
        }
        self.response
            .clone()
            .ok_or(BedrockError::InvalidProviderResponse)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    response: ProviderResponse,
    seen_request_digests: Arc<Mutex<Vec<crate::Digest>>>,
}

impl RecordingTransport {
    pub fn new(response: ProviderResponse) -> Self {
        Self {
            response: response.with_provenance(Layer1Provenance::Recording),
            seen_request_digests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn seen_request_digests(&self) -> Vec<crate::Digest> {
        self.seen_request_digests
            .lock()
            .map_or_else(|_| Vec::new(), |digests| digests.clone())
    }
}

impl ConverseTransport for RecordingTransport {
    fn provenance(&self) -> Layer1Provenance {
        Layer1Provenance::Recording
    }

    fn invoke_converse(&self, proposal: &InvocationProposal) -> Result<ProviderResponse> {
        self.seen_request_digests
            .lock()
            .map_err(|_| BedrockError::Transport {
                class: "recording_lock",
            })?
            .push(proposal.request_digest());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    response: ProviderResponse,
}

impl LoopbackTransport {
    pub fn new(response: ProviderResponse) -> Self {
        Self {
            response: response.with_provenance(Layer1Provenance::Loopback),
        }
    }
}

impl ConverseTransport for LoopbackTransport {
    fn provenance(&self) -> Layer1Provenance {
        Layer1Provenance::Loopback
    }

    fn invoke_converse(&self, _proposal: &InvocationProposal) -> Result<ProviderResponse> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl ConverseTransport for BlockedEnvTransport {
    fn provenance(&self) -> Layer1Provenance {
        Layer1Provenance::BlockedEnv
    }

    fn invoke_converse(&self, _proposal: &InvocationProposal) -> Result<ProviderResponse> {
        Err(BedrockError::BlockedEnv)
    }
}
