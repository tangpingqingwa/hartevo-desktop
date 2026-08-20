//! Provider definition and deterministic transport boundary.
//!
//! There is intentionally no native HTTP or SigV4 implementation in this
//! Layer-1 crate.  Scripted fixture, recording, loopback, and BLOCKED_ENV
//! transports make provenance explicit and keep provider behavior testable.

use std::{collections::VecDeque, fmt};

use thiserror::Error;

use crate::{
    AWS_SYNTHETICS_API_REVISION, AWS_SYNTHETICS_PROVIDER_ID, AWS_SYNTHETICS_PROVIDER_VERSION,
    model::{
        AwsSyntheticsReadRequest, CanaryReadOperation, CanaryRunPage, Digest, ModelError,
        ProviderErrorEvidence, ProviderErrorKind, ProviderId, ProviderRevision,
        TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS Synthetics provider definition model error: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl AwsSyntheticsProviderIdentity {
    pub fn layer_one(provenance: TransportProvenance) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_SYNTHETICS_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_SYNTHETICS_API_REVISION)?;
        let api_digest = Digest::from_parts(
            "hartevo-aws-synthetics-api/v1",
            &[
                "GetCanaryRuns".to_owned(),
                "POST".to_owned(),
                AWS_SYNTHETICS_API_REVISION.to_owned(),
                "bounded-page-read".to_owned(),
            ],
        );
        let provider_digest = Digest::from_parts(
            "hartevo-aws-synthetics-provider/v1",
            &[
                provider_id.to_string(),
                AWS_SYNTHETICS_PROVIDER_VERSION.to_owned(),
                api_revision.to_string(),
                api_digest.to_string(),
                "fixture-recording-loopback-blocked-env".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: AWS_SYNTHETICS_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
        })
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("provider access denied")]
    AccessDenied,
    #[error("provider object not found")]
    NotFound,
    #[error("provider throttled")]
    Throttled,
    #[error("provider request timed out")]
    Timeout,
    #[error("native AWS environment is unavailable")]
    BlockedEnv,
    #[error("provider response was malformed")]
    Malformed,
    #[error("provider recording was exhausted or replayed")]
    Replay,
    #[error("provider revision did not match the registered revision")]
    RevisionMismatch,
}

impl TransportError {
    pub const fn kind(self) -> ProviderErrorKind {
        match self {
            Self::AccessDenied => ProviderErrorKind::AccessDenied,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Throttled => ProviderErrorKind::Throttled,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnv => ProviderErrorKind::BlockedEnv,
            Self::Malformed => ProviderErrorKind::Malformed,
            Self::Replay => ProviderErrorKind::Replay,
            Self::RevisionMismatch => ProviderErrorKind::RevisionMismatch,
        }
    }

    pub const fn retryable(self) -> bool {
        self.kind().retryable()
    }

    pub const fn is_access_loss(self) -> bool {
        self.kind().is_access_loss()
    }

    pub fn evidence(
        self,
        provenance: TransportProvenance,
        provider_revision: ProviderRevision,
    ) -> ProviderErrorEvidence {
        ProviderErrorEvidence::new(self.kind(), provenance, provider_revision)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSyntheticsProviderError {
    #[error("AWS Synthetics transport error: {0}")]
    Transport(TransportError),
    #[error("AWS Synthetics provider operation is not allowlisted")]
    UnsupportedOperation,
    #[error("AWS Synthetics page was malformed or tampered")]
    MalformedPage,
    #[error("AWS Synthetics page provider revision drifted")]
    RevisionMismatch,
}

#[derive(Clone, Debug)]
pub struct RecordingAwsSyntheticsTransport {
    provenance: TransportProvenance,
    responses: VecDeque<Result<CanaryRunPage, TransportError>>,
}

impl Default for RecordingAwsSyntheticsTransport {
    fn default() -> Self {
        Self::recording()
    }
}

impl RecordingAwsSyntheticsTransport {
    pub fn recording() -> Self {
        Self::with_provenance(TransportProvenance::Recording)
    }

    pub fn fixture(page: CanaryRunPage) -> Self {
        let mut transport = Self::with_provenance(TransportProvenance::Fixture);
        transport.push_response(Ok(page));
        transport
    }

    pub fn loopback() -> Self {
        Self::with_provenance(TransportProvenance::Loopback)
    }

    pub fn with_provenance(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
        }
    }

    pub fn push_response(&mut self, response: Result<CanaryRunPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn push_page(&mut self, page: CanaryRunPage) {
        self.push_response(Ok(page));
    }

    pub const fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

impl AwsSyntheticsTransport for RecordingAwsSyntheticsTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read(
        &mut self,
        _request: &AwsSyntheticsReadRequest,
    ) -> Result<CanaryRunPage, TransportError> {
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Replay))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsSyntheticsTransport;

impl AwsSyntheticsTransport for BlockedEnvAwsSyntheticsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &AwsSyntheticsReadRequest,
    ) -> Result<CanaryRunPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub trait AwsSyntheticsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn read(&mut self, request: &AwsSyntheticsReadRequest)
    -> Result<CanaryRunPage, TransportError>;
}

#[derive(Clone)]
pub struct AwsSyntheticsProvider<T>
where
    T: AwsSyntheticsTransport,
{
    identity: AwsSyntheticsProviderIdentity,
    transport: T,
}

impl<T> fmt::Debug for AwsSyntheticsProvider<T>
where
    T: AwsSyntheticsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSyntheticsProvider")
            .field("identity", &self.identity)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> AwsSyntheticsProvider<T>
where
    T: AwsSyntheticsTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsSyntheticsProviderIdentity::layer_one(transport.provenance())?;
        Ok(Self {
            identity,
            transport,
        })
    }

    pub fn identity(&self) -> &AwsSyntheticsProviderIdentity {
        &self.identity
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.identity.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &AwsSyntheticsReadRequest,
    ) -> Result<CanaryRunPage, AwsSyntheticsProviderError> {
        if request.operation != CanaryReadOperation::GetCanaryRuns {
            return Err(AwsSyntheticsProviderError::UnsupportedOperation);
        }
        let page = self
            .transport
            .read(request)
            .map_err(AwsSyntheticsProviderError::Transport)?;
        if page.provider_revision != self.identity.api_revision {
            return Err(AwsSyntheticsProviderError::RevisionMismatch);
        }
        page.validate()
            .map_err(|_| AwsSyntheticsProviderError::MalformedPage)?;
        Ok(page)
    }
}

pub type FixtureAwsSyntheticsTransport = RecordingAwsSyntheticsTransport;
pub type LoopbackAwsSyntheticsTransport = RecordingAwsSyntheticsTransport;
pub type FakeAwsSyntheticsTransport = RecordingAwsSyntheticsTransport;
pub type BlockedEnvTransport = BlockedEnvAwsSyntheticsTransport;
pub type ProviderProvenance = TransportProvenance;
pub type AwsSyntheticsProviderDefinition = AwsSyntheticsProviderIdentity;
pub type AwsSyntheticsTransportError = TransportError;

pub fn is_access_loss(error: &TransportError) -> bool {
    error.is_access_loss()
}
