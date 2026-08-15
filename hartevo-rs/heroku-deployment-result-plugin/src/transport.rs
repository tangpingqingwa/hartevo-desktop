use std::{cell::RefCell, collections::VecDeque, fmt, rc::Rc};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{HerokuDeploymentError, HerokuTransportError, Result};
use crate::model::{
    Digest, HerokuDeploymentScope, MAX_BACKOFF_SECONDS, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_PAGES, MAX_RESPONSE_BYTES, ProviderProvenance,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HerokuOperation {
    GetApp,
    GetBuild,
    ListReleases,
    GetSlug,
    GetDyno,
}

impl HerokuOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetApp => "get_app",
            Self::GetBuild => "get_build",
            Self::ListReleases => "list_releases",
            Self::GetSlug => "get_slug",
            Self::GetDyno => "get_dyno",
        }
    }
}

/// Redacted GET request. The raw path and cursor remain inside the
/// deterministic transport seam and never serialize or debug-print.
#[derive(Clone, Eq, PartialEq)]
pub struct HerokuRequest {
    pub operation: HerokuOperation,
    method: &'static str,
    path: String,
    path_digest: Digest,
    app_id_digest: Digest,
    resource_id_digest: Option<Digest>,
    cursor_digest: Option<Digest>,
    page_number: u16,
    attempt: u8,
}

impl fmt::Debug for HerokuRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerokuRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("path_digest", &self.path_digest)
            .field("app_id_digest", &self.app_id_digest)
            .field("resource_id_digest", &self.resource_id_digest)
            .field("cursor_digest", &self.cursor_digest)
            .field("page_number", &self.page_number)
            .field("attempt", &self.attempt)
            .finish()
    }
}

impl Serialize for HerokuRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HerokuRequest", 8)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("pathDigest", &self.path_digest)?;
        state.serialize_field("appIdDigest", &self.app_id_digest)?;
        state.serialize_field("resourceIdDigest", &self.resource_id_digest)?;
        state.serialize_field("cursorDigest", &self.cursor_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("attempt", &self.attempt)?;
        state.end()
    }
}

impl HerokuRequest {
    pub(crate) fn get_app(scope: &HerokuDeploymentScope) -> Result<Self> {
        Self::new(
            HerokuOperation::GetApp,
            format!("/apps/{}", scope.app_id().as_str()),
            scope,
            None,
            None,
            1,
        )
    }

    pub(crate) fn get_build(scope: &HerokuDeploymentScope) -> Result<Self> {
        Self::new(
            HerokuOperation::GetBuild,
            format!(
                "/apps/{}/builds/{}",
                scope.app_id().as_str(),
                scope.build_id().as_str()
            ),
            scope,
            Some(scope.build_id().as_str().to_owned()),
            None,
            1,
        )
    }

    pub(crate) fn list_releases(
        scope: &HerokuDeploymentScope,
        cursor: Option<(&str, u16)>,
    ) -> Result<Self> {
        let (cursor_value, page_number) =
            cursor.map_or((None, 1), |(value, page)| (Some(value.to_owned()), page));
        let mut path = format!("/apps/{}/releases?limit=50", scope.app_id().as_str());
        if let Some(cursor_value) = &cursor_value {
            path.push_str("&cursor=");
            path.push_str(cursor_value);
        }
        Self::new(
            HerokuOperation::ListReleases,
            path,
            scope,
            None,
            cursor_value,
            page_number,
        )
    }

    pub(crate) fn get_slug(scope: &HerokuDeploymentScope) -> Result<Self> {
        Self::new(
            HerokuOperation::GetSlug,
            format!(
                "/apps/{}/slugs/{}",
                scope.app_id().as_str(),
                scope.slug_id().as_str()
            ),
            scope,
            Some(scope.slug_id().as_str().to_owned()),
            None,
            1,
        )
    }

    pub(crate) fn get_dyno(scope: &HerokuDeploymentScope) -> Result<Self> {
        Self::new(
            HerokuOperation::GetDyno,
            format!(
                "/apps/{}/dynos/{}",
                scope.app_id().as_str(),
                scope.dyno_id().as_str()
            ),
            scope,
            Some(scope.dyno_id().as_str().to_owned()),
            None,
            1,
        )
    }

    fn new(
        operation: HerokuOperation,
        path: String,
        scope: &HerokuDeploymentScope,
        resource_id: Option<String>,
        cursor: Option<String>,
        page_number: u16,
    ) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_IDENTIFIER_BYTES * 8 || page_number == 0 {
            return Err(HerokuDeploymentError::InvalidRequest);
        }
        if cursor
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_CURSOR_BYTES)
        {
            return Err(HerokuDeploymentError::InvalidRequest);
        }
        let request = Self {
            operation,
            method: "GET",
            path_digest: Digest::from_text(path.as_bytes()),
            path,
            app_id_digest: scope.app_id().digest(),
            resource_id_digest: resource_id.map(|value| Digest::from_text(value.as_bytes())),
            cursor_digest: cursor
                .as_ref()
                .map(|value| Digest::from_text(value.as_bytes())),
            page_number,
            attempt: 1,
        };
        if !request.is_get() || !request.is_allowlisted() {
            return Err(HerokuDeploymentError::InvalidRequest);
        }
        Ok(request)
    }

    pub(crate) fn with_attempt(&self, attempt: u8) -> Self {
        let mut request = self.clone();
        request.attempt = attempt;
        request
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
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    #[must_use]
    pub fn is_get(&self) -> bool {
        self.method == "GET"
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        if !self.is_get() {
            return false;
        }
        match self.operation {
            HerokuOperation::GetApp => {
                self.path.starts_with("/apps/") && self.path.matches('/').count() == 2
            }
            HerokuOperation::GetBuild => {
                self.path.matches('/').count() == 4
                    && self.path.starts_with("/apps/")
                    && self.path.contains("/builds/")
            }
            HerokuOperation::ListReleases => {
                self.path.starts_with("/apps/")
                    && self.path.contains("/releases?limit=50")
                    && !self.path.contains("/config-vars")
            }
            HerokuOperation::GetSlug => {
                self.path.matches('/').count() == 4
                    && self.path.starts_with("/apps/")
                    && self.path.contains("/slugs/")
            }
            HerokuOperation::GetDyno => {
                self.path.matches('/').count() == 4
                    && self.path.starts_with("/apps/")
                    && self.path.contains("/dynos/")
            }
        }
    }
}

/// Bounded response envelope. Its body is available only to the provider
/// parser and is never exposed through Debug or Serialize.
#[derive(Clone, Eq, PartialEq)]
pub struct HerokuResponse {
    status: u16,
    body: Vec<u8>,
    declared_response_digest: Option<Digest>,
    retry_after_seconds: Option<u32>,
}

impl fmt::Debug for HerokuResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerokuResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.body.len())
            .field("response_digest", &self.response_digest())
            .field("declared_response_digest", &self.declared_response_digest)
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

impl Serialize for HerokuResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HerokuResponse", 5)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("responseBytes", &self.body.len())?;
        state.serialize_field("responseDigest", &self.response_digest())?;
        state.serialize_field("declaredResponseDigest", &self.declared_response_digest)?;
        state.serialize_field("retryAfterSeconds", &self.retry_after_seconds)?;
        state.end()
    }
}

impl HerokuResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            declared_response_digest: None,
            retry_after_seconds: None,
        }
    }

    pub fn json<T: Serialize>(status: u16, value: &T) -> Result<Self> {
        serde_json::to_vec(value)
            .map(|body| Self::new(status, body))
            .map_err(|_| HerokuDeploymentError::InvalidResponse)
    }

    #[must_use]
    pub fn with_declared_response_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = Some(digest);
        self
    }

    #[must_use]
    pub const fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
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

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn validate_size_and_digest(&self) -> Result<()> {
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(HerokuDeploymentError::InvalidResponse);
        }
        if self
            .declared_response_digest
            .as_ref()
            .is_some_and(|expected| expected != &self.response_digest())
        {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

pub trait HerokuTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(
        &mut self,
        request: &HerokuRequest,
    ) -> std::result::Result<HerokuResponse, HerokuTransportError>;
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
            max_backoff_seconds: MAX_BACKOFF_SECONDS,
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
            .min(MAX_BACKOFF_SECONDS)
    }
}

#[derive(Clone, Debug)]
struct RecordingState {
    responses: VecDeque<HerokuResponse>,
    requests: Vec<HerokuRequest>,
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
    pub fn new(responses: impl IntoIterator<Item = HerokuResponse>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(RecordingState {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            })),
        }
    }

    #[must_use]
    pub fn requests(&self) -> Vec<HerokuRequest> {
        self.inner.borrow().requests.clone()
    }

    pub fn push_response(&self, response: HerokuResponse) {
        self.inner.borrow_mut().responses.push_back(response);
    }

    pub fn clear_requests(&self) {
        self.inner.borrow_mut().requests.clear();
    }
}

impl HerokuTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &HerokuRequest,
    ) -> std::result::Result<HerokuResponse, HerokuTransportError> {
        if !request.is_allowlisted() {
            return Err(HerokuTransportError::ProviderUnknown);
        }
        let mut inner = self.inner.borrow_mut();
        inner.requests.push(request.clone());
        inner
            .responses
            .pop_front()
            .ok_or(HerokuTransportError::Timeout)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    response: HerokuResponse,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(response: HerokuResponse) -> Self {
        Self { response }
    }
}

impl HerokuTransport for FixtureTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &HerokuRequest,
    ) -> std::result::Result<HerokuResponse, HerokuTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    response: HerokuResponse,
}

impl FakeTransport {
    #[must_use]
    pub fn new(response: HerokuResponse) -> Self {
        Self { response }
    }
}

impl HerokuTransport for FakeTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }

    fn execute(
        &mut self,
        _request: &HerokuRequest,
    ) -> std::result::Result<HerokuResponse, HerokuTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    response: HerokuResponse,
}

impl LoopbackTransport {
    #[must_use]
    pub fn new(response: HerokuResponse) -> Self {
        Self { response }
    }
}

impl HerokuTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &HerokuRequest,
    ) -> std::result::Result<HerokuResponse, HerokuTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl HerokuTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &HerokuRequest,
    ) -> std::result::Result<HerokuResponse, HerokuTransportError> {
        Err(HerokuTransportError::BlockedEnv)
    }
}

/// An opaque page cursor retained by the provider only as a digest in public
/// evidence. The raw token never appears in a request debug or receipt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn from_token(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() || token.len() > MAX_CURSOR_BYTES {
            return Err(HerokuDeploymentError::InvalidRequest);
        }
        Ok(Self {
            digest: Digest::from_parts("heroku-pagination-cursor/v1", &[("token", token)]),
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[allow(dead_code)]
const _: u16 = MAX_PAGES;
