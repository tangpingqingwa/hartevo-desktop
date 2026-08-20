//! Read-only Slack conversations provider boundary.
//!
//! Only typed, already-redacted pages can cross this boundary. There is no
//! HTTP client, token resolver, raw Slack payload, message search escape hatch,
//! or provider mutation operation in the Layer-1 provider.

use std::{collections::VecDeque, fmt};

use thiserror::Error;

use crate::{
    SLACK_DECISION_API_REVISION, SLACK_DECISION_PROVIDER_ID, SLACK_DECISION_PROVIDER_VERSION,
    model::{
        Digest, ModelError, ProviderErrorKind, ProviderId, ProviderRevision, SlackReadPage,
        SlackReadRequest, TransportError, TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Slack provider identity is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("Slack provider API revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl SlackProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(SLACK_DECISION_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(SLACK_DECISION_API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "hartevo-slack-provider/v1",
            &[
                provider_id.to_string(),
                SLACK_DECISION_PROVIDER_VERSION.to_owned(),
                api_revision.to_string(),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-slack-conversations-api-allowlist/v1",
            &[
                "conversations.history".to_owned(),
                "conversations.replies".to_owned(),
                "GET".to_owned(),
                "cursor".to_owned(),
                "oldest".to_owned(),
                "latest".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: SLACK_DECISION_PROVIDER_VERSION.to_owned(),
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

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SlackProviderError {
    #[error("Slack provider request is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("Slack provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("Slack provider page binding or digest is invalid")]
    PageBinding,
    #[error("Slack provider page was not redacted")]
    RedactionLoss,
    #[error("Slack provider page is outside the registered retention window")]
    RetentionLoss,
}

/// Layer-1 transports are fixture, recording, loopback, or BLOCKED_ENV only.
pub trait SlackTransport: Send + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_page(&mut self, request: &SlackReadRequest) -> Result<SlackReadPage, TransportError>;
}

/// Provider seam over a non-native transport.
pub struct SlackProvider<T> {
    transport: T,
    identity: SlackProviderIdentity,
}

impl<T> fmt::Debug for SlackProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackProvider")
            .field("transport", &self.transport)
            .field("identity", &self.identity)
            .finish()
    }
}

impl<T> SlackProvider<T>
where
    T: SlackTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = SlackProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &SlackProviderIdentity {
        &self.identity
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read_page(
        &mut self,
        request: &SlackReadRequest,
    ) -> Result<SlackReadPage, SlackProviderError> {
        let page = self.transport.read_page(request)?;
        if page.operation != request.operation
            || page.request_digest != *request.digest()
            || page.provenance != self.identity.provenance
        {
            return Err(SlackProviderError::PageBinding);
        }
        page.validate()
            .map_err(|_| SlackProviderError::PageBinding)?;
        if !page.redaction.is_safe() {
            return Err(SlackProviderError::RedactionLoss);
        }
        if !page.retention.is_safe() {
            return Err(SlackProviderError::RetentionLoss);
        }
        Ok(page)
    }

    pub fn read(
        &mut self,
        request: &SlackReadRequest,
    ) -> Result<SlackReadPage, SlackProviderError> {
        self.read_page(request)
    }

    pub fn is_native(&self) -> bool {
        self.identity.native()
    }

    pub fn is_connected(&self) -> bool {
        self.identity.connected()
    }

    pub fn is_first_party(&self) -> bool {
        self.identity.first_party()
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureSlackTransport {
    responses: VecDeque<Result<SlackReadPage, TransportError>>,
}

impl FixtureSlackTransport {
    pub fn from_pages<I>(pages: I) -> Self
    where
        I: IntoIterator<Item = SlackReadPage>,
    {
        Self {
            responses: pages.into_iter().map(Ok).collect(),
        }
    }

    pub fn push_response(&mut self, response: Result<SlackReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn pending_responses(&self) -> usize {
        self.responses.len()
    }
}

impl SlackTransport for FixtureSlackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_page(&mut self, _request: &SlackReadRequest) -> Result<SlackReadPage, TransportError> {
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Provider(
                ProviderErrorKind::ProviderUnknown,
            )))
    }
}

pub type FakeSlackTransport = FixtureSlackTransport;

#[derive(Clone, Debug, Default)]
pub struct RecordingSlackTransport {
    responses: VecDeque<Result<SlackReadPage, TransportError>>,
}

impl RecordingSlackTransport {
    pub fn from_pages<I>(pages: I) -> Self
    where
        I: IntoIterator<Item = SlackReadPage>,
    {
        Self {
            responses: pages.into_iter().map(Ok).collect(),
        }
    }

    pub fn push_response(&mut self, response: Result<SlackReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn pending_responses(&self) -> usize {
        self.responses.len()
    }
}

impl SlackTransport for RecordingSlackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_page(&mut self, _request: &SlackReadRequest) -> Result<SlackReadPage, TransportError> {
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Provider(
                ProviderErrorKind::ProviderUnknown,
            )))
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackSlackTransport {
    responses: VecDeque<Result<SlackReadPage, TransportError>>,
}

impl LoopbackSlackTransport {
    pub fn from_pages<I>(pages: I) -> Self
    where
        I: IntoIterator<Item = SlackReadPage>,
    {
        Self {
            responses: pages.into_iter().map(Ok).collect(),
        }
    }

    pub fn push_response(&mut self, response: Result<SlackReadPage, TransportError>) {
        self.responses.push_back(response);
    }
}

impl SlackTransport for LoopbackSlackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_page(&mut self, _request: &SlackReadRequest) -> Result<SlackReadPage, TransportError> {
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Provider(
                ProviderErrorKind::ProviderUnknown,
            )))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvSlackTransport;

pub type BlockedEnvTransport = BlockedEnvSlackTransport;

impl SlackTransport for BlockedEnvSlackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_page(&mut self, _request: &SlackReadRequest) -> Result<SlackReadPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub const fn is_access_loss(kind: ProviderErrorKind) -> bool {
    matches!(
        kind,
        ProviderErrorKind::PermissionDenied
            | ProviderErrorKind::RetentionUnavailable
            | ProviderErrorKind::Revoked
    )
}
