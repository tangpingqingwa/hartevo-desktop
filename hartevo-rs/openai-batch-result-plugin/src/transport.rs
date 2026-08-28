use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    error::OpenAiBatchResultError,
    model::{BatchCursor, BatchId, MAX_PAGE_LIMIT, Revision, SecretReference},
};

/// The only HTTP method representable by this transport seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
}

/// A bounded request target.  There is deliberately no constructor for POST,
/// upload, cancel, file-content, or arbitrary URL requests.
#[derive(Clone, Eq, PartialEq)]
pub struct GetRequest {
    path: String,
    limit: Option<u32>,
    after: Option<String>,
    batch_id: Option<BatchId>,
    cursor_digest: Option<crate::Digest>,
}

impl fmt::Debug for GetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetRequest")
            .field("method", &HttpMethod::Get)
            .field("path", &self.path)
            .field("limit", &self.limit)
            .field("after_digest", &self.cursor_digest)
            .field("batch_id", &self.batch_id)
            .finish_non_exhaustive()
    }
}

impl GetRequest {
    pub(crate) fn list(
        limit: u32,
        cursor: Option<&BatchCursor>,
    ) -> Result<Self, OpenAiBatchResultError> {
        if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
            return Err(OpenAiBatchResultError::InvalidRequest("limit"));
        }
        Ok(Self {
            path: String::from("/v1/batches"),
            limit: Some(limit),
            after: cursor.map(|value| value.as_str().to_owned()),
            batch_id: None,
            cursor_digest: cursor.map(BatchCursor::digest),
        })
    }

    pub(crate) fn batch(batch_id: BatchId) -> Result<Self, OpenAiBatchResultError> {
        batch_id.validate()?;
        Ok(Self {
            path: format!("/v1/batches/{}", batch_id.as_str()),
            limit: None,
            after: None,
            batch_id: Some(batch_id),
            cursor_digest: None,
        })
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        HttpMethod::Get
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn limit(&self) -> Option<u32> {
        self.limit
    }

    #[must_use]
    pub fn after(&self) -> Option<&str> {
        self.after.as_deref()
    }

    #[must_use]
    pub fn batch_id(&self) -> Option<&BatchId> {
        self.batch_id.as_ref()
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<&crate::Digest> {
        self.cursor_digest.as_ref()
    }

    /// A query-bearing target suitable for a narrow host HTTP adapter.
    #[must_use]
    pub fn target(&self) -> String {
        let mut target = self.path.clone();
        let mut first = true;
        if let Some(limit) = self.limit {
            target.push_str("?limit=");
            target.push_str(&limit.to_string());
            first = false;
        }
        if let Some(after) = &self.after {
            target.push(if first { '?' } else { '&' });
            target.push_str("after=");
            target.push_str(after);
        }
        target
    }
}

/// A transport response retains raw bytes only until the provider projects
/// them to typed metadata.  Its Debug output is digest/size-only.
#[derive(Clone)]
pub struct OpenAiBatchHttpResponse {
    status: u16,
    body: Vec<u8>,
    observed_at: u64,
    snapshot_revision: Revision,
}

impl fmt::Debug for OpenAiBatchHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiBatchHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("body_digest", &crate::Digest::from_bytes(&self.body))
            .field("observed_at", &self.observed_at)
            .field("snapshot_revision", &self.snapshot_revision)
            .finish()
    }
}

impl OpenAiBatchHttpResponse {
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
    pub fn body(&self) -> &[u8] {
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
pub enum OpenAiBatchTransportError {
    BlockedEnv,
    Timeout,
    TransportUnavailable,
    AccessLoss,
    Unauthorized,
    Forbidden,
}

/// Host-owned transport seam.  It receives only an opaque SecretReference and
/// can issue only the two Batch GET request shapes represented by GetRequest.
pub trait OpenAiBatchTransport: fmt::Debug + Send + Sync {
    fn get(
        &self,
        request: &GetRequest,
        secret_reference: &SecretReference,
    ) -> std::result::Result<OpenAiBatchHttpResponse, OpenAiBatchTransportError>;
}

#[derive(Default)]
struct RecordingState {
    responses: VecDeque<std::result::Result<OpenAiBatchHttpResponse, OpenAiBatchTransportError>>,
    requests: Vec<GetRequest>,
}

/// Deterministic recording/fake/fixture/loopback transport used by Layer-1
/// evidence.  It never resolves a credential and never opens a socket.
#[derive(Clone, Default)]
pub struct RecordingOpenAiBatchTransport {
    state: Arc<Mutex<RecordingState>>,
}

impl fmt::Debug for RecordingOpenAiBatchTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().map_err(|_| fmt::Error)?;
        formatter
            .debug_struct("RecordingOpenAiBatchTransport")
            .field("queued_responses", &state.responses.len())
            .field("request_count", &state.requests.len())
            .finish()
    }
}

impl RecordingOpenAiBatchTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&self, response: OpenAiBatchHttpResponse) {
        if let Ok(mut state) = self.state.lock() {
            state.responses.push_back(Ok(response));
        }
    }

    pub fn push_error(&self, error: OpenAiBatchTransportError) {
        if let Ok(mut state) = self.state.lock() {
            state.responses.push_back(Err(error));
        }
    }

    #[must_use]
    pub fn requests(&self) -> Vec<GetRequest> {
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

impl OpenAiBatchTransport for RecordingOpenAiBatchTransport {
    fn get(
        &self,
        request: &GetRequest,
        _secret_reference: &SecretReference,
    ) -> std::result::Result<OpenAiBatchHttpResponse, OpenAiBatchTransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OpenAiBatchTransportError::TransportUnavailable)?;
        state.requests.push(request.clone());
        state
            .responses
            .pop_front()
            .unwrap_or(Err(OpenAiBatchTransportError::TransportUnavailable))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvOpenAiBatchTransport;

impl OpenAiBatchTransport for BlockedEnvOpenAiBatchTransport {
    fn get(
        &self,
        _request: &GetRequest,
        _secret_reference: &SecretReference,
    ) -> std::result::Result<OpenAiBatchHttpResponse, OpenAiBatchTransportError> {
        Err(OpenAiBatchTransportError::BlockedEnv)
    }
}

pub type FakeOpenAiBatchTransport = RecordingOpenAiBatchTransport;
pub type FixtureOpenAiBatchTransport = RecordingOpenAiBatchTransport;
pub type LoopbackOpenAiBatchTransport = RecordingOpenAiBatchTransport;
