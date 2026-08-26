use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{MailgunProviderError, MailgunTransportError, ModelError, ProviderResult};
use crate::model::{
    BackoffReceipt, Cursor, Digest, MailgunDeliveryEvent, MailgunDeliveryResultScope,
    MailgunEventSelector, MailgunWebhookEnvelope, MailgunWebhookEvidence, RateLimitReceipt,
    SecretReference, SuppressionMetadata, TransportProvenance, WebhookVerificationState,
    canonical_digest,
};
use crate::{
    MAX_EVENTS_PER_PAGE, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    MailgunDeliveryResultContract, PROVIDER_API_REVISION, PROVIDER_ID, api_digest, contract_digest,
    plugin_version_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailgunOperation {
    ListEvents,
    GetEvent,
    ReadSuppressionMetadata,
    VerifyWebhookEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunEventsRequest {
    pub operation: MailgunOperation,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub revision_digest: Digest,
    pub event_selector_digest: Digest,
    pub cursor: Option<Cursor>,
    pub page: u16,
    pub page_size: u16,
    pub idempotency_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl MailgunEventsRequest {
    pub fn new(
        scope: &MailgunDeliveryResultScope,
        cursor: Option<Cursor>,
        page: u16,
        page_size: u16,
        idempotency_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if page == 0 || page > MAX_PAGES || page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidScope("pagination request"));
        }
        let event_selector_digest = canonical_digest(&scope.event);
        let mut request = Self {
            operation: if matches!(scope.event, MailgunEventSelector::EventIdDigest(_)) {
                MailgunOperation::GetEvent
            } else {
                MailgunOperation::ListEvents
            },
            scope_digest: scope.scope_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            event_selector_digest,
            cursor,
            page,
            page_size,
            idempotency_digest,
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        Ok(request)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "mailgun-events-request/v1",
            &self.operation,
            &self.scope_digest,
            &self.consent_digest,
            &self.revision_digest,
            &self.event_selector_digest,
            &self.cursor,
            self.page,
            self.page_size,
            &self.idempotency_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page == 0
            || self.page > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.request_digest != self.digest()
        {
            return Err(ModelError::InvalidScope("events request"));
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunSuppressionRequest {
    pub operation: MailgunOperation,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub revision_digest: Digest,
    pub recipient_fingerprint_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl MailgunSuppressionRequest {
    pub fn new(scope: &MailgunDeliveryResultScope) -> Self {
        let mut request = Self {
            operation: MailgunOperation::ReadSuppressionMetadata,
            scope_digest: scope.scope_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            recipient_fingerprint_digest: scope
                .recipient
                .as_ref()
                .map(|value| value.digest().clone()),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "mailgun-suppression-request/v1",
            &self.operation,
            &self.scope_digest,
            &self.consent_digest,
            &self.revision_digest,
            &self.recipient_fingerprint_digest,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookVerificationRequest {
    pub operation: MailgunOperation,
    pub scope_digest: Digest,
    pub envelope_digest: Digest,
    pub now_seconds: u64,
    pub request_digest: Digest,
}

impl WebhookVerificationRequest {
    pub fn new(
        scope: &MailgunDeliveryResultScope,
        envelope: &MailgunWebhookEnvelope,
        now_seconds: u64,
    ) -> Self {
        let mut request = Self {
            operation: MailgunOperation::VerifyWebhookEvent,
            scope_digest: scope.scope_digest().clone(),
            envelope_digest: envelope.digest(),
            now_seconds,
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "mailgun-webhook-verification-request/v1",
            &self.operation,
            &self.scope_digest,
            &self.envelope_digest,
            self.now_seconds,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunEventPage {
    pub events: Vec<MailgunDeliveryEvent>,
    pub next_cursor: Option<Cursor>,
    pub suppression: Vec<SuppressionMetadata>,
    pub response_bytes: usize,
    pub status_code: u16,
    pub rate_limit: RateLimitReceipt,
    pub response_digest: Digest,
}

impl MailgunEventPage {
    pub fn new(
        events: Vec<MailgunDeliveryEvent>,
        next_cursor: Option<Cursor>,
        suppression: Vec<SuppressionMetadata>,
        response_bytes: usize,
        rate_limit: RateLimitReceipt,
    ) -> Result<Self, ModelError> {
        Self::with_status(
            events,
            next_cursor,
            suppression,
            response_bytes,
            200,
            rate_limit,
        )
    }

    pub fn with_status(
        events: Vec<MailgunDeliveryEvent>,
        next_cursor: Option<Cursor>,
        suppression: Vec<SuppressionMetadata>,
        response_bytes: usize,
        status_code: u16,
        rate_limit: RateLimitReceipt,
    ) -> Result<Self, ModelError> {
        if events.len() > MAX_EVENTS_PER_PAGE
            || suppression.len() > MAX_EVENTS_PER_PAGE
            || response_bytes > MAX_RESPONSE_BYTES
            || events.iter().any(|event| event.validate().is_err())
            || suppression.iter().any(|value| value.validate().is_err())
            || rate_limit.validate().is_err()
        {
            return Err(ModelError::InvalidEvent);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate()?;
        }
        let response_digest = canonical_digest(&(
            "mailgun-event-page/v1",
            &events,
            &next_cursor,
            &suppression,
            response_bytes,
            status_code,
            &rate_limit,
        ));
        Ok(Self {
            events,
            next_cursor,
            suppression,
            response_bytes,
            status_code,
            rate_limit,
            response_digest,
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.suppression.is_empty()
    }
}

/// A provider transport is intentionally limited to typed, bounded fixture
/// pages. This crate does not implement native HTTPS or credential
/// resolution.
pub trait MailgunTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn fetch_events(
        &mut self,
        request: &MailgunEventsRequest,
    ) -> Result<MailgunEventPage, MailgunTransportError>;

    fn fetch_suppressions(
        &mut self,
        request: &MailgunSuppressionRequest,
    ) -> Result<Vec<SuppressionMetadata>, MailgunTransportError> {
        let _ = request;
        Ok(Vec::new())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailgunProviderDefinition {
    pub id: &'static str,
    pub api_revision: &'static str,
    pub operations: Vec<MailgunOperation>,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

impl Default for MailgunProviderDefinition {
    fn default() -> Self {
        Self {
            id: PROVIDER_ID,
            api_revision: PROVIDER_API_REVISION,
            operations: vec![
                MailgunOperation::ListEvents,
                MailgunOperation::GetEvent,
                MailgunOperation::ReadSuppressionMetadata,
                MailgunOperation::VerifyWebhookEvent,
            ],
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MailgunProvider<T: MailgunTransport> {
    scope: MailgunDeliveryResultScope,
    secret_reference: SecretReference,
    transport: T,
    provider_digest: Digest,
    definition: MailgunProviderDefinition,
}

impl<T: MailgunTransport> MailgunProvider<T> {
    pub fn new(
        scope: MailgunDeliveryResultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> ProviderResult<Self> {
        scope.validate()?;
        let definition = MailgunProviderDefinition::default();
        let provider_digest = canonical_digest(&(
            "mailgun-provider/v1",
            definition.id,
            definition.api_revision,
            &scope.scope_digest,
            &scope.revision_digest,
            transport.provenance(),
        ));
        Ok(Self {
            scope,
            secret_reference,
            transport,
            provider_digest,
            definition,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &MailgunDeliveryResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
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
    pub fn provider_digest(&self) -> Digest {
        self.provider_digest.clone()
    }

    #[must_use]
    pub fn definition(&self) -> &MailgunProviderDefinition {
        &self.definition
    }

    pub fn events_page(
        &mut self,
        request: &MailgunEventsRequest,
    ) -> ProviderResult<MailgunEventPage> {
        self.validate_request(request)?;
        self.transport
            .fetch_events(request)
            .map_err(MailgunProviderError::Transport)
    }

    pub fn suppression_metadata(
        &mut self,
        request: &MailgunSuppressionRequest,
    ) -> ProviderResult<Vec<SuppressionMetadata>> {
        if self.secret_reference.is_revoked() {
            return Err(MailgunProviderError::SecretRevoked);
        }
        if request.scope_digest != self.scope.scope_digest
            || request.consent_digest != *self.scope.consent_digest()
            || request.revision_digest != self.scope.revision_digest
        {
            return Err(MailgunProviderError::ScopeMismatch);
        }
        self.transport
            .fetch_suppressions(request)
            .map_err(MailgunProviderError::Transport)
    }

    pub fn verify_webhook(
        &self,
        envelope: &MailgunWebhookEnvelope,
        now_seconds: u64,
    ) -> ProviderResult<MailgunWebhookEvidence> {
        if self.secret_reference.is_revoked() {
            return Err(MailgunProviderError::SecretRevoked);
        }
        let evidence = MailgunWebhookEvidence::from_envelope(envelope, now_seconds);
        match evidence.state {
            WebhookVerificationState::Verified => Ok(evidence),
            WebhookVerificationState::Tampered => Err(MailgunProviderError::WebhookTampered),
            WebhookVerificationState::Replay => Err(MailgunProviderError::WebhookReplay),
            WebhookVerificationState::Expired => Ok(evidence),
        }
    }

    fn validate_request(&self, request: &MailgunEventsRequest) -> ProviderResult<()> {
        request.validate()?;
        if self.secret_reference.is_revoked() {
            return Err(MailgunProviderError::SecretRevoked);
        }
        if request.scope_digest != self.scope.scope_digest {
            return Err(MailgunProviderError::ScopeMismatch);
        }
        if request.consent_digest != *self.scope.consent_digest() {
            return Err(MailgunProviderError::ConsentMismatch);
        }
        if request.revision_digest != self.scope.revision_digest {
            return Err(MailgunProviderError::RevisionMismatch);
        }
        Ok(())
    }
}

pub type MailgunDeliveryProvider<T> = MailgunProvider<T>;

#[derive(Clone, Debug)]
pub struct FixtureMailgunTransport {
    pages: VecDeque<Result<MailgunEventPage, MailgunTransportError>>,
    suppressions: VecDeque<Result<Vec<SuppressionMetadata>, MailgunTransportError>>,
}

impl FixtureMailgunTransport {
    pub fn new(page: MailgunEventPage) -> Self {
        Self::from_pages(vec![Ok(page)])
    }

    pub fn from_pages(pages: Vec<Result<MailgunEventPage, MailgunTransportError>>) -> Self {
        Self {
            pages: pages.into(),
            suppressions: VecDeque::new(),
        }
    }

    pub fn push_page(&mut self, page: Result<MailgunEventPage, MailgunTransportError>) {
        self.pages.push_back(page);
    }

    pub fn push_suppressions(
        &mut self,
        value: Result<Vec<SuppressionMetadata>, MailgunTransportError>,
    ) {
        self.suppressions.push_back(value);
    }

    fn pop_page(&mut self) -> Result<MailgunEventPage, MailgunTransportError> {
        self.pages
            .pop_front()
            .unwrap_or(Err(MailgunTransportError::ProviderUnknown))
    }
}

impl MailgunTransport for FixtureMailgunTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn fetch_events(
        &mut self,
        _request: &MailgunEventsRequest,
    ) -> Result<MailgunEventPage, MailgunTransportError> {
        self.pop_page()
    }

    fn fetch_suppressions(
        &mut self,
        _request: &MailgunSuppressionRequest,
    ) -> Result<Vec<SuppressionMetadata>, MailgunTransportError> {
        self.suppressions
            .pop_front()
            .unwrap_or_else(|| Ok(Vec::new()))
    }
}

#[derive(Clone, Debug)]
pub struct RecordingMailgunTransport {
    pages: VecDeque<Result<MailgunEventPage, MailgunTransportError>>,
    requests: Vec<MailgunEventsRequest>,
    suppression_requests: Vec<MailgunSuppressionRequest>,
}

impl RecordingMailgunTransport {
    pub fn new(page: MailgunEventPage) -> Self {
        Self::from_pages(vec![Ok(page)])
    }

    pub fn from_pages(pages: Vec<Result<MailgunEventPage, MailgunTransportError>>) -> Self {
        Self {
            pages: pages.into(),
            requests: Vec::new(),
            suppression_requests: Vec::new(),
        }
    }

    pub fn push_page(&mut self, page: Result<MailgunEventPage, MailgunTransportError>) {
        self.pages.push_back(page);
    }

    #[must_use]
    pub fn requests(&self) -> &[MailgunEventsRequest] {
        &self.requests
    }

    #[must_use]
    pub fn suppression_requests(&self) -> &[MailgunSuppressionRequest] {
        &self.suppression_requests
    }
}

impl MailgunTransport for RecordingMailgunTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn fetch_events(
        &mut self,
        request: &MailgunEventsRequest,
    ) -> Result<MailgunEventPage, MailgunTransportError> {
        self.requests.push(request.clone());
        self.pages
            .pop_front()
            .unwrap_or(Err(MailgunTransportError::ProviderUnknown))
    }

    fn fetch_suppressions(
        &mut self,
        request: &MailgunSuppressionRequest,
    ) -> Result<Vec<SuppressionMetadata>, MailgunTransportError> {
        self.suppression_requests.push(request.clone());
        Ok(Vec::new())
    }
}

#[derive(Clone, Debug)]
pub struct FakeMailgunTransport {
    pages: VecDeque<Result<MailgunEventPage, MailgunTransportError>>,
}

impl FakeMailgunTransport {
    pub fn new(page: MailgunEventPage) -> Self {
        Self {
            pages: VecDeque::from([Ok(page)]),
        }
    }

    pub fn from_pages(pages: Vec<Result<MailgunEventPage, MailgunTransportError>>) -> Self {
        Self {
            pages: pages.into(),
        }
    }
}

impl MailgunTransport for FakeMailgunTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn fetch_events(
        &mut self,
        _request: &MailgunEventsRequest,
    ) -> Result<MailgunEventPage, MailgunTransportError> {
        self.pages
            .pop_front()
            .unwrap_or(Err(MailgunTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackMailgunTransport {
    pages: VecDeque<Result<MailgunEventPage, MailgunTransportError>>,
}

impl LoopbackMailgunTransport {
    pub fn new(page: MailgunEventPage) -> Self {
        Self {
            pages: VecDeque::from([Ok(page)]),
        }
    }

    pub fn from_pages(pages: Vec<Result<MailgunEventPage, MailgunTransportError>>) -> Self {
        Self {
            pages: pages.into(),
        }
    }
}

impl MailgunTransport for LoopbackMailgunTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn fetch_events(
        &mut self,
        _request: &MailgunEventsRequest,
    ) -> Result<MailgunEventPage, MailgunTransportError> {
        self.pages
            .pop_front()
            .unwrap_or(Err(MailgunTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvMailgunTransport;

impl MailgunTransport for BlockedEnvMailgunTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn fetch_events(
        &mut self,
        _request: &MailgunEventsRequest,
    ) -> Result<MailgunEventPage, MailgunTransportError> {
        Err(MailgunTransportError::BlockedEnv)
    }

    fn fetch_suppressions(
        &mut self,
        _request: &MailgunSuppressionRequest,
    ) -> Result<Vec<SuppressionMetadata>, MailgunTransportError> {
        Err(MailgunTransportError::BlockedEnv)
    }
}

#[allow(dead_code)]
fn _provider_contract_is_machine_checked() -> bool {
    MailgunDeliveryResultContract::baseline().is_ok()
}

#[allow(dead_code)]
fn _provider_digest_inputs() -> (Digest, Digest, BackoffReceipt) {
    (
        plugin_version_digest(),
        api_digest(),
        BackoffReceipt::none(),
    )
}

#[allow(dead_code)]
fn _provider_contract_digest() -> Digest {
    contract_digest()
}
