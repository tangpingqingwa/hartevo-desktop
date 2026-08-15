use std::{cell::RefCell, collections::VecDeque, fmt, rc::Rc};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{RenderDeploymentError, RenderTransportError, Result};
use crate::model::{
    Digest, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_RESPONSE_BYTES, ProviderProvenance,
    RenderDeploymentScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderOperation {
    GetService,
    ListDeploys,
    GetDeploy,
}

impl RenderOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetService => "get_service",
            Self::ListDeploys => "list_deploys",
            Self::GetDeploy => "get_deploy",
        }
    }
}

/// Redacted GET request. The raw path and cursor are retained only inside the
/// deterministic transport seam and never serialize or debug-print.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderRequest {
    pub operation: RenderOperation,
    method: &'static str,
    path: String,
    path_digest: Digest,
    service_id_digest: Digest,
    deploy_id_digest: Option<Digest>,
    cursor_digest: Option<Digest>,
    page_number: u16,
    attempt: u8,
}

impl fmt::Debug for RenderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("path_digest", &self.path_digest)
            .field("service_id_digest", &self.service_id_digest)
            .field("deploy_id_digest", &self.deploy_id_digest)
            .field("cursor_digest", &self.cursor_digest)
            .field("page_number", &self.page_number)
            .field("attempt", &self.attempt)
            .finish()
    }
}

impl Serialize for RenderRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RenderRequest", 8)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("pathDigest", &self.path_digest)?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("deployIdDigest", &self.deploy_id_digest)?;
        state.serialize_field("cursorDigest", &self.cursor_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("attempt", &self.attempt)?;
        state.end()
    }
}

impl RenderRequest {
    pub(crate) fn get_service(scope: &RenderDeploymentScope) -> Result<Self> {
        let path = format!("/v1/services/{}", scope.service_id().as_str());
        Self::new(RenderOperation::GetService, path, scope, None, None, 1)
    }

    pub(crate) fn list_deploys(
        scope: &RenderDeploymentScope,
        cursor: Option<(&str, u16)>,
    ) -> Result<Self> {
        let (cursor_value, page_number) =
            cursor.map_or((None, 1), |(value, page)| (Some(value.to_owned()), page));
        let mut path = format!(
            "/v1/services/{}/deploys?limit={}",
            scope.service_id().as_str(),
            crate::model::MAX_DEPLOYS_PER_PAGE
        );
        if let Some(cursor_value) = &cursor_value {
            path.push_str("&cursor=");
            path.push_str(cursor_value);
        }
        Self::new(
            RenderOperation::ListDeploys,
            path,
            scope,
            None,
            cursor_value,
            page_number,
        )
    }

    pub(crate) fn get_deploy(scope: &RenderDeploymentScope) -> Result<Self> {
        let path = format!("/v1/deploys/{}", scope.deploy_id().as_str());
        Self::new(
            RenderOperation::GetDeploy,
            path,
            scope,
            Some(scope.deploy_id().as_str().to_owned()),
            None,
            1,
        )
    }

    fn new(
        operation: RenderOperation,
        path: String,
        scope: &RenderDeploymentScope,
        deploy_id: Option<String>,
        cursor: Option<String>,
        page_number: u16,
    ) -> Result<Self> {
        if path.len() > MAX_IDENTIFIER_BYTES * 8 {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        if cursor
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_CURSOR_BYTES)
        {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        let request = Self {
            operation,
            method: "GET",
            path_digest: Digest::from_text(path.as_bytes()),
            path,
            service_id_digest: scope.service_id().digest(),
            deploy_id_digest: deploy_id.map(|value| Digest::from_text(value.as_bytes())),
            cursor_digest: cursor
                .as_ref()
                .map(|value| Digest::from_text(value.as_bytes())),
            page_number,
            attempt: 1,
        };
        if request.method != "GET" || request.path.is_empty() {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        Ok(request)
    }

    #[must_use]
    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }

    #[must_use]
    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor_digest.as_ref()
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    #[must_use]
    pub fn is_get(&self) -> bool {
        self.method == "GET"
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.is_get()
            && match self.operation {
                RenderOperation::GetService => {
                    self.path.starts_with("/v1/services/") && !self.path.contains("/deploys")
                }
                RenderOperation::ListDeploys => {
                    self.path.starts_with("/v1/services/") && self.path.contains("/deploys")
                }
                RenderOperation::GetDeploy => self.path.starts_with("/v1/deploys/"),
            }
    }
}

/// Bounded response envelope. Its body is available only to the provider
/// parser and is never exposed through Debug or Serialize.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderResponse {
    status: u16,
    body: Vec<u8>,
    declared_response_digest: Option<Digest>,
}

impl fmt::Debug for RenderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.body.len())
            .field("response_digest", &self.response_digest())
            .field("declared_response_digest", &self.declared_response_digest)
            .finish()
    }
}

impl Serialize for RenderResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RenderResponse", 4)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("responseBytes", &self.body.len())?;
        state.serialize_field("responseDigest", &self.response_digest())?;
        state.serialize_field("declaredResponseDigest", &self.declared_response_digest)?;
        state.end()
    }
}

impl RenderResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            declared_response_digest: None,
        }
    }

    pub fn json<T: Serialize>(status: u16, value: &T) -> Result<Self> {
        serde_json::to_vec(value)
            .map(|body| Self::new(status, body))
            .map_err(|_| RenderDeploymentError::InvalidResponse)
    }

    #[must_use]
    pub fn with_declared_response_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = Some(digest);
        self
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        Digest::from_bytes(&self.body)
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn validate_size_and_digest(&self) -> Result<()> {
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(RenderDeploymentError::InvalidResponse);
        }
        if self
            .declared_response_digest
            .as_ref()
            .is_some_and(|expected| expected != &self.response_digest())
        {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

pub trait RenderTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(
        &mut self,
        request: &RenderRequest,
    ) -> std::result::Result<RenderResponse, RenderTransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_backoff_seconds: u32,
    pub max_backoff_seconds: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: crate::model::MAX_RETRY_ATTEMPTS,
            base_backoff_seconds: 1,
            max_backoff_seconds: crate::model::MAX_BACKOFF_SECONDS,
        }
    }
}

impl RetryPolicy {
    #[must_use]
    pub fn backoff_seconds(self, attempt: u8) -> u32 {
        let shift = std::cmp::min(attempt.saturating_sub(1), 5);
        let multiplier = 1u32 << shift;
        self.base_backoff_seconds
            .saturating_mul(multiplier)
            .min(self.max_backoff_seconds)
            .min(crate::model::MAX_BACKOFF_SECONDS)
    }
}

#[derive(Clone, Debug)]
struct RecordingState {
    responses: VecDeque<RenderResponse>,
    requests: Vec<RenderRequest>,
}

#[derive(Clone)]
pub struct RecordingTransport {
    inner: Rc<RefCell<RecordingState>>,
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.borrow();
        formatter
            .debug_struct("RecordingTransport")
            .field("queued_responses", &inner.responses.len())
            .field("request_count", &inner.requests.len())
            .finish()
    }
}

impl RecordingTransport {
    #[must_use]
    pub fn new(responses: impl IntoIterator<Item = RenderResponse>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(RecordingState {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            })),
        }
    }

    #[must_use]
    pub fn requests(&self) -> Vec<RenderRequest> {
        self.inner.borrow().requests.clone()
    }

    pub fn push_response(&self, response: RenderResponse) {
        self.inner.borrow_mut().responses.push_back(response);
    }

    pub fn clear_requests(&self) {
        self.inner.borrow_mut().requests.clear();
    }
}

impl RenderTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &RenderRequest,
    ) -> std::result::Result<RenderResponse, RenderTransportError> {
        if !request.is_allowlisted() {
            return Err(RenderTransportError::ProviderUnknown);
        }
        let mut inner = self.inner.borrow_mut();
        inner.requests.push(request.clone());
        inner
            .responses
            .pop_front()
            .ok_or(RenderTransportError::Timeout)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    response: RenderResponse,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(response: RenderResponse) -> Self {
        Self { response }
    }
}

impl RenderTransport for FixtureTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &RenderRequest,
    ) -> std::result::Result<RenderResponse, RenderTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    response: RenderResponse,
}

impl FakeTransport {
    #[must_use]
    pub fn new(response: RenderResponse) -> Self {
        Self { response }
    }
}

impl RenderTransport for FakeTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }

    fn execute(
        &mut self,
        _request: &RenderRequest,
    ) -> std::result::Result<RenderResponse, RenderTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    response: RenderResponse,
}

impl LoopbackTransport {
    #[must_use]
    pub fn new(response: RenderResponse) -> Self {
        Self { response }
    }
}

impl RenderTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &RenderRequest,
    ) -> std::result::Result<RenderResponse, RenderTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl RenderTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &RenderRequest,
    ) -> std::result::Result<RenderResponse, RenderTransportError> {
        Err(RenderTransportError::BlockedEnv)
    }
}

/// An opaque page cursor retained by the service only as a digest.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn from_token(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() || token.len() > MAX_CURSOR_BYTES {
            return Err(RenderDeploymentError::InvalidRequest);
        }
        Ok(Self {
            digest: Digest::from_parts("render-pagination-cursor/v1", &[("token", token)]),
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}
