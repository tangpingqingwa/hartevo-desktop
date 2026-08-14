//! Safe GET-shaped transport seams.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize, Serializer};

use crate::model::{
    AssetId, Digest, FrameIoApiEndpoint, FrameIoApprovalSummary, FrameIoAssetSummary,
    FrameIoBounds, FrameIoCommentSummary, FrameIoHttpMethod, FrameIoPayload, FrameIoReadOperation,
    FrameIoReviewLinkSummary, FrameIoRevisionFence, FrameIoScope, FrameIoVersionSummary,
    ModelError, ObservationWindow, Revision, SecretReference, digest_serializable,
};

pub(crate) const MAX_CURSOR_BYTES: usize = 4 * 1024;

/// Cursor values are retained only inside a transport and are represented at
/// every public boundary by their digest.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let raw = value.into();
        if raw.is_empty() || raw.len() > MAX_CURSOR_BYTES {
            return Err(ModelError::InvalidCursor);
        }
        let digest = Digest::from_text(&raw);
        Ok(Self { digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoGetRequest {
    pub operation: FrameIoReadOperation,
    pub endpoint: FrameIoApiEndpoint,
    pub method: FrameIoHttpMethod,
    pub account_id: crate::AccountId,
    pub frameio_project_id: crate::FrameIoProjectId,
    pub asset_id: AssetId,
    pub asset_version_id: crate::AssetVersionId,
    pub review_link_id: crate::ReviewLinkId,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revision_fence: FrameIoRevisionFence,
    pub credential_revision: Revision,
    pub page_number: u16,
    pub page_size: u16,
    pub cursor: Option<OpaqueCursor>,
    pub window: ObservationWindow,
    pub secret_reference_digest: Digest,
}

impl FrameIoGetRequest {
    pub fn new(
        scope: &FrameIoScope,
        secret_reference: &SecretReference,
        operation: FrameIoReadOperation,
        bounds: FrameIoBounds,
        window: ObservationWindow,
        page_number: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        if page_number == 0 || page_number > bounds.max_pages() {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            operation,
            endpoint: FrameIoApiEndpoint::for_operation(operation),
            method: FrameIoHttpMethod::Get,
            account_id: scope.account_id.clone(),
            frameio_project_id: scope.frameio_project_id.clone(),
            asset_id: scope.asset_id.clone(),
            asset_version_id: scope.asset_version_id.clone(),
            review_link_id: scope.review_link_id.clone(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            consent_digest: scope.consent_digest(),
            revision_fence: scope.fence(),
            credential_revision: secret_reference.credential_revision(),
            page_number,
            page_size: bounds.page_size(),
            cursor,
            window,
            secret_reference_digest: secret_reference.reference_digest().clone(),
        })
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoGetResponse {
    pub operation: FrameIoReadOperation,
    pub payload: FrameIoPayload,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revision_fence: FrameIoRevisionFence,
    pub credential_revision: Revision,
    pub status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub next_cursor: Option<OpaqueCursor>,
}

impl FrameIoGetResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: FrameIoReadOperation,
        payload: FrameIoPayload,
        scope_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
        revision_fence: FrameIoRevisionFence,
        credential_revision: Revision,
        status: u16,
        response_size: usize,
        provider_revision: impl Into<String>,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, FrameIoTransportError> {
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(FrameIoTransportError::invalid_response(
                "empty provider revision",
            ));
        }
        let mut response = Self {
            operation,
            payload,
            scope_digest,
            permission_digest,
            consent_digest,
            revision_fence,
            credential_revision,
            status,
            response_size,
            response_digest: Digest::from_text("uninitialized-frameio-response-digest"),
            provider_revision,
            next_cursor,
        };
        response.response_digest = response.recompute_digest()?;
        Ok(response)
    }

    pub fn recompute_digest(&self) -> Result<Digest, FrameIoTransportError> {
        let material = FrameIoGetResponseMaterial {
            operation: self.operation,
            payload: self.payload.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            revision_fence: self.revision_fence,
            credential_revision: self.credential_revision,
            status: self.status,
            response_size: self.response_size,
            provider_revision: self.provider_revision.clone(),
            next_cursor_digest: self
                .next_cursor
                .as_ref()
                .map(|cursor| cursor.digest().clone()),
        };
        digest_serializable(&material).map_err(FrameIoTransportError::from_model)
    }

    pub fn validate_integrity(&self) -> Result<(), FrameIoTransportError> {
        if self.response_digest != self.recompute_digest()? {
            return Err(FrameIoTransportError::invalid_response(
                "response digest mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrameIoGetResponseMaterial {
    pub operation: FrameIoReadOperation,
    pub payload: FrameIoPayload,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revision_fence: FrameIoRevisionFence,
    pub credential_revision: Revision,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: String,
    pub next_cursor_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameIoSnapshot {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revision_fence: FrameIoRevisionFence,
    pub credential_revision: Revision,
    pub provider_revision: String,
    pub asset: Option<FrameIoAssetSummary>,
    pub version: Option<FrameIoVersionSummary>,
    pub review_link: Option<FrameIoReviewLinkSummary>,
    pub approval: Option<FrameIoApprovalSummary>,
    pub comments: Option<FrameIoCommentSummary>,
    pub next_comment_cursor: Option<OpaqueCursor>,
}

impl FrameIoSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &FrameIoScope,
        credential_revision: Revision,
        provider_revision: impl Into<String>,
        asset: Option<FrameIoAssetSummary>,
        version: Option<FrameIoVersionSummary>,
        review_link: Option<FrameIoReviewLinkSummary>,
        approval: Option<FrameIoApprovalSummary>,
        comments: Option<FrameIoCommentSummary>,
        next_comment_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, FrameIoTransportError> {
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(FrameIoTransportError::invalid_response(
                "empty provider revision",
            ));
        }
        Ok(Self {
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            consent_digest: scope.consent_digest(),
            revision_fence: scope.fence(),
            credential_revision,
            provider_revision,
            asset,
            version,
            review_link,
            approval,
            comments,
            next_comment_cursor,
        })
    }

    pub fn response_for(
        &self,
        request: &FrameIoGetRequest,
    ) -> Result<FrameIoGetResponse, FrameIoTransportError> {
        if request.scope_digest != self.scope_digest
            || request.permission_digest != self.permission_digest
            || request.consent_digest != self.consent_digest
            || request.credential_revision != self.credential_revision
        {
            return Err(FrameIoTransportError::scope_mismatch(
                "fixture response scope fence differs",
            ));
        }
        let payload = match request.operation {
            FrameIoReadOperation::AssetMetadata => self
                .asset
                .clone()
                .map(FrameIoPayload::Asset)
                .ok_or_else(|| FrameIoTransportError::not_found("asset"))?,
            FrameIoReadOperation::AssetVersion => self
                .version
                .clone()
                .map(FrameIoPayload::Version)
                .ok_or_else(|| FrameIoTransportError::not_found("asset version"))?,
            FrameIoReadOperation::ReviewLink => self
                .review_link
                .clone()
                .map(FrameIoPayload::ReviewLink)
                .ok_or_else(|| FrameIoTransportError::not_found("review link"))?,
            FrameIoReadOperation::ApprovalStatus => self
                .approval
                .clone()
                .map(FrameIoPayload::Approval)
                .ok_or_else(|| FrameIoTransportError::not_found("approval"))?,
            FrameIoReadOperation::CommentSummary => self
                .comments
                .clone()
                .map(FrameIoPayload::Comments)
                .ok_or_else(|| FrameIoTransportError::not_found("comments"))?,
        };
        let response_size = serde_json::to_vec(&payload)
            .map_err(|error| FrameIoTransportError::invalid_response(error.to_string()))?
            .len();
        FrameIoGetResponse::new(
            request.operation,
            payload,
            self.scope_digest.clone(),
            self.permission_digest.clone(),
            self.consent_digest.clone(),
            self.revision_fence,
            self.credential_revision,
            200,
            response_size,
            self.provider_revision.clone(),
            if request.operation.is_comment_summary() {
                self.next_comment_cursor.clone()
            } else {
                None
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoTransportErrorKind {
    BlockedEnv,
    RateLimited,
    Timeout,
    ServerFailure,
    PermissionDenied,
    NotFound,
    InvalidResponse,
    ScopeMismatch,
}

impl FrameIoTransportErrorKind {
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::Timeout | Self::ServerFailure
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FrameIoTransportError {
    pub kind: FrameIoTransportErrorKind,
    pub status_code: Option<u16>,
    diagnostic_digest: Digest,
}

impl fmt::Debug for FrameIoTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameIoTransportError")
            .field("kind", &self.kind)
            .field("status_code", &self.status_code)
            .field("diagnostic_digest", &self.diagnostic_digest)
            .finish()
    }
}

impl std::error::Error for FrameIoTransportError {}

impl fmt::Display for FrameIoTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Frame.io transport returned {:?}", self.kind)
    }
}

impl FrameIoTransportError {
    pub fn new(
        kind: FrameIoTransportErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(FrameIoTransportErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn rate_limited() -> Self {
        Self::new(
            FrameIoTransportErrorKind::RateLimited,
            Some(429),
            "rate-limited",
        )
    }

    pub fn timeout() -> Self {
        Self::new(FrameIoTransportErrorKind::Timeout, None, "timeout")
    }

    pub fn server_failure() -> Self {
        Self::new(
            FrameIoTransportErrorKind::ServerFailure,
            Some(503),
            "server-failure",
        )
    }

    pub fn permission_denied() -> Self {
        Self::new(
            FrameIoTransportErrorKind::PermissionDenied,
            Some(403),
            "permission-denied",
        )
    }

    pub fn not_found(resource: &str) -> Self {
        Self::new(FrameIoTransportErrorKind::NotFound, Some(404), resource)
    }

    pub fn invalid_response(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(FrameIoTransportErrorKind::InvalidResponse, None, diagnostic)
    }

    pub fn scope_mismatch(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(FrameIoTransportErrorKind::ScopeMismatch, None, diagnostic)
    }

    pub(crate) fn from_model(error: ModelError) -> Self {
        Self::invalid_response(error.to_string())
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }

    pub const fn is_retryable(&self) -> bool {
        self.kind.retryable()
    }

    pub const fn is_blocked_env(&self) -> bool {
        matches!(self.kind, FrameIoTransportErrorKind::BlockedEnv)
    }
}

pub trait FrameIoTransport: fmt::Debug {
    fn get(
        &mut self,
        request: &FrameIoGetRequest,
    ) -> Result<FrameIoGetResponse, FrameIoTransportError>;
}

#[derive(Debug, Default)]
pub struct RecordingFrameIoTransport {
    requests: Vec<FrameIoGetRequest>,
    responses: VecDeque<Result<FrameIoGetResponse, FrameIoTransportError>>,
}

impl RecordingFrameIoTransport {
    pub fn push_response(&mut self, response: FrameIoGetResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: FrameIoTransportError) {
        self.responses.push_back(Err(error));
    }

    pub fn requests(&self) -> &[FrameIoGetRequest] {
        &self.requests
    }
}

impl FrameIoTransport for RecordingFrameIoTransport {
    fn get(
        &mut self,
        request: &FrameIoGetRequest,
    ) -> Result<FrameIoGetResponse, FrameIoTransportError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(FrameIoTransportError::invalid_response(
                "recording transport has no queued response",
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct FixtureFrameIoTransport {
    snapshot: FrameIoSnapshot,
    requests: Vec<FrameIoGetRequest>,
}

impl FixtureFrameIoTransport {
    pub fn new(snapshot: FrameIoSnapshot) -> Self {
        Self {
            snapshot,
            requests: Vec::new(),
        }
    }

    pub fn snapshot(&self) -> &FrameIoSnapshot {
        &self.snapshot
    }

    pub fn requests(&self) -> &[FrameIoGetRequest] {
        &self.requests
    }
}

impl FrameIoTransport for FixtureFrameIoTransport {
    fn get(
        &mut self,
        request: &FrameIoGetRequest,
    ) -> Result<FrameIoGetResponse, FrameIoTransportError> {
        self.requests.push(request.clone());
        self.snapshot.response_for(request)
    }
}

pub type FrameIoFixtureTransport = FixtureFrameIoTransport;

#[derive(Clone, Debug)]
pub struct LoopbackFrameIoTransport {
    inner: FixtureFrameIoTransport,
}

impl LoopbackFrameIoTransport {
    pub fn new(snapshot: FrameIoSnapshot) -> Self {
        Self {
            inner: FixtureFrameIoTransport::new(snapshot),
        }
    }

    pub fn requests(&self) -> &[FrameIoGetRequest] {
        self.inner.requests()
    }
}

impl FrameIoTransport for LoopbackFrameIoTransport {
    fn get(
        &mut self,
        request: &FrameIoGetRequest,
    ) -> Result<FrameIoGetResponse, FrameIoTransportError> {
        self.inner.get(request)
    }
}

pub type FrameIoLoopbackTransport = LoopbackFrameIoTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvFrameIoTransport;

impl FrameIoTransport for BlockedEnvFrameIoTransport {
    fn get(
        &mut self,
        _request: &FrameIoGetRequest,
    ) -> Result<FrameIoGetResponse, FrameIoTransportError> {
        Err(FrameIoTransportError::blocked_env())
    }
}
