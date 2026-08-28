use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    error::PaddleSubscriptionResultError,
    model::{
        CursorKind, MAX_EVENT_PAGE_LIMIT, MAX_TRANSACTION_PAGE_LIMIT, PaddleCursor, Revision,
        SecretReference, SubscriptionId, TransactionId,
    },
};

/// The only HTTP method representable by this transport seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaddleHttpMethod {
    Get,
}

/// A bounded request target. There is deliberately no constructor for POST,
/// checkout, capture, refund, portal-token, webhook, or mutation requests.
#[derive(Clone, Eq, PartialEq)]
pub struct PaddleGetRequest {
    path: String,
    target: String,
    kind: CursorKind,
    subscription_id: Option<SubscriptionId>,
    transaction_id: Option<TransactionId>,
    cursor_digest: Option<crate::Digest>,
    limit: Option<u32>,
}

impl fmt::Debug for PaddleGetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaddleGetRequest")
            .field("method", &PaddleHttpMethod::Get)
            .field("path", &self.path)
            .field("target", &self.target)
            .field("kind", &self.kind)
            .field("subscription_id", &self.subscription_id)
            .field("transaction_id", &self.transaction_id)
            .field("cursor_digest", &self.cursor_digest)
            .field("limit", &self.limit)
            .finish()
    }
}

impl PaddleGetRequest {
    pub(crate) fn subscription(
        subscription_id: SubscriptionId,
    ) -> Result<Self, PaddleSubscriptionResultError> {
        subscription_id.validate()?;
        Ok(Self {
            path: format!("/subscriptions/{}", subscription_id.as_str()),
            target: format!("/subscriptions/{}", subscription_id.as_str()),
            kind: CursorKind::Transactions,
            subscription_id: Some(subscription_id),
            transaction_id: None,
            cursor_digest: None,
            limit: None,
        })
    }

    pub(crate) fn transaction(
        transaction_id: TransactionId,
    ) -> Result<Self, PaddleSubscriptionResultError> {
        transaction_id.validate()?;
        Ok(Self {
            path: format!("/transactions/{}", transaction_id.as_str()),
            target: format!("/transactions/{}", transaction_id.as_str()),
            kind: CursorKind::Transactions,
            subscription_id: None,
            transaction_id: Some(transaction_id),
            cursor_digest: None,
            limit: None,
        })
    }

    pub(crate) fn transactions(
        subscription_id: SubscriptionId,
        limit: u32,
        cursor: Option<&PaddleCursor>,
    ) -> Result<Self, PaddleSubscriptionResultError> {
        subscription_id.validate()?;
        if !(1..=MAX_TRANSACTION_PAGE_LIMIT).contains(&limit) {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "transaction limit",
            ));
        }
        if cursor
            .as_ref()
            .is_some_and(|value| value.kind() != CursorKind::Transactions)
        {
            return Err(PaddleSubscriptionResultError::CursorMismatch);
        }
        let mut target = format!(
            "/transactions?subscription_id={}&per_page={}",
            subscription_id.as_str(),
            limit
        );
        if let Some(cursor) = cursor {
            target.push_str("&after=");
            target.push_str(cursor.as_str());
        }
        Ok(Self {
            path: String::from("/transactions"),
            target,
            kind: CursorKind::Transactions,
            subscription_id: Some(subscription_id),
            transaction_id: None,
            cursor_digest: cursor.map(PaddleCursor::digest),
            limit: Some(limit),
        })
    }

    pub(crate) fn events(
        limit: u32,
        cursor: Option<&PaddleCursor>,
    ) -> Result<Self, PaddleSubscriptionResultError> {
        if !(1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
            return Err(PaddleSubscriptionResultError::InvalidRequest("event limit"));
        }
        if cursor
            .as_ref()
            .is_some_and(|value| value.kind() != CursorKind::Events)
        {
            return Err(PaddleSubscriptionResultError::CursorMismatch);
        }
        let event_types = "subscription.activated,subscription.canceled,subscription.created,subscription.imported,subscription.past_due,subscription.paused,subscription.resumed,subscription.trialing,subscription.updated,transaction.billed,transaction.canceled,transaction.completed,transaction.created,transaction.paid,transaction.past_due,transaction.payment_failed,transaction.ready,transaction.revised,transaction.updated";
        let mut target = format!("/events?event_type={event_types}&per_page={limit}");
        if let Some(cursor) = cursor {
            target.push_str("&after=");
            target.push_str(cursor.as_str());
        }
        Ok(Self {
            path: String::from("/events"),
            target,
            kind: CursorKind::Events,
            subscription_id: None,
            transaction_id: None,
            cursor_digest: cursor.map(PaddleCursor::digest),
            limit: Some(limit),
        })
    }

    #[must_use]
    pub const fn method(&self) -> PaddleHttpMethod {
        PaddleHttpMethod::Get
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub const fn kind(&self) -> CursorKind {
        self.kind
    }

    #[must_use]
    pub fn subscription_id(&self) -> Option<&SubscriptionId> {
        self.subscription_id.as_ref()
    }

    #[must_use]
    pub fn transaction_id(&self) -> Option<&TransactionId> {
        self.transaction_id.as_ref()
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<&crate::Digest> {
        self.cursor_digest.as_ref()
    }

    #[must_use]
    pub const fn limit(&self) -> Option<u32> {
        self.limit
    }
}

/// A transport response retains raw bytes only until the provider projects
/// them to typed metadata. Its Debug output is digest/size-only.
#[derive(Clone)]
pub struct PaddleHttpResponse {
    status: u16,
    body: Vec<u8>,
    observed_at: u64,
    snapshot_revision: Revision,
}

impl fmt::Debug for PaddleHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaddleHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("body_digest", &crate::Digest::from_bytes(&self.body))
            .field("observed_at", &self.observed_at)
            .field("snapshot_revision", &self.snapshot_revision)
            .finish()
    }
}

impl PaddleHttpResponse {
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            observed_at: 0,
            snapshot_revision: Revision::new(1).expect("literal revision"),
        }
    }

    #[must_use]
    pub fn with_observed_at(mut self, observed_at: u64) -> Self {
        self.observed_at = observed_at;
        self
    }

    #[must_use]
    pub fn with_snapshot_revision(mut self, revision: Revision) -> Self {
        self.snapshot_revision = revision;
        self
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    #[must_use]
    pub const fn snapshot_revision(&self) -> Revision {
        self.snapshot_revision
    }
}

/// Transport errors are intentionally narrower than an HTTP client error and
/// contain no provider body or credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaddleTransportError {
    BlockedEnv,
    Timeout,
    TransportUnavailable,
    AccessLoss,
    Unauthorized,
    Forbidden,
    Conflict,
    RateLimited,
}

/// Host-owned transport seam. It receives only an opaque SecretReference and
/// can issue only typed Paddle GET request shapes.
pub trait PaddleTransport: fmt::Debug + Send + Sync {
    fn get(
        &self,
        request: &PaddleGetRequest,
        secret_reference: &SecretReference,
    ) -> std::result::Result<PaddleHttpResponse, PaddleTransportError>;
}

#[derive(Default)]
struct RecordingState {
    responses: VecDeque<std::result::Result<PaddleHttpResponse, PaddleTransportError>>,
    requests: Vec<PaddleGetRequest>,
}

/// Deterministic recording/fake/fixture/loopback transport used by Layer-1
/// evidence. It never resolves a credential and never opens a socket.
#[derive(Clone, Default)]
pub struct RecordingPaddleBillingTransport {
    state: Arc<Mutex<RecordingState>>,
}

impl fmt::Debug for RecordingPaddleBillingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().map_err(|_| fmt::Error)?;
        formatter
            .debug_struct("RecordingPaddleBillingTransport")
            .field("queued_responses", &state.responses.len())
            .field("request_count", &state.requests.len())
            .finish()
    }
}

impl RecordingPaddleBillingTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&self, response: PaddleHttpResponse) {
        if let Ok(mut state) = self.state.lock() {
            state.responses.push_back(Ok(response));
        }
    }

    pub fn push_error(&self, error: PaddleTransportError) {
        if let Ok(mut state) = self.state.lock() {
            state.responses.push_back(Err(error));
        }
    }

    #[must_use]
    pub fn requests(&self) -> Vec<PaddleGetRequest> {
        self.state
            .lock()
            .map(|state| state.requests.clone())
            .unwrap_or_default()
    }

    pub fn clear_requests(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.requests.clear();
        }
    }
}

impl PaddleTransport for RecordingPaddleBillingTransport {
    fn get(
        &self,
        request: &PaddleGetRequest,
        _secret_reference: &SecretReference,
    ) -> std::result::Result<PaddleHttpResponse, PaddleTransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PaddleTransportError::TransportUnavailable)?;
        state.requests.push(request.clone());
        state
            .responses
            .pop_front()
            .unwrap_or(Err(PaddleTransportError::TransportUnavailable))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvPaddleBillingTransport;

impl PaddleTransport for BlockedEnvPaddleBillingTransport {
    fn get(
        &self,
        _request: &PaddleGetRequest,
        _secret_reference: &SecretReference,
    ) -> std::result::Result<PaddleHttpResponse, PaddleTransportError> {
        Err(PaddleTransportError::BlockedEnv)
    }
}

pub type FakePaddleBillingTransport = RecordingPaddleBillingTransport;
pub type FixturePaddleBillingTransport = RecordingPaddleBillingTransport;
pub type LoopbackPaddleBillingTransport = RecordingPaddleBillingTransport;
