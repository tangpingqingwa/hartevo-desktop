use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    BoardEvidence, CannyFeedbackProviderEvidence, CannyFeedbackResultStatus, CannyFeedbackScope,
    CategoryEvidence, CommentEvidence, Digest, FeedbackPostStatus, ModelError, PostEvidence,
    ProviderErrorKind, ProviderProvenance, RedactionSummary, Revision, RoadmapEvidence,
    SecretReference, StatusEvidence, VoteAggregate,
};
use crate::query::CannyFeedbackResultRequest;
use crate::{
    CANNY_API_METHOD, CANNY_API_ORIGIN, CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT,
    CANNY_FEEDBACK_RESULT_PROVIDER_ID, CANNY_MAX_CATEGORIES, CANNY_MAX_COMMENTS, CANNY_MAX_POSTS,
    CANNY_MAX_REQUESTS_PER_SCOPE_PER_UTC_HOUR, CANNY_MAX_RESPONSE_BYTES, CANNY_MAX_ROADMAPS,
    CANNY_MAX_STATUSES, CANNY_MAX_VOTE_AGGREGATES,
};

const ALLOWLISTED_PATHS: &[&str] = &[
    "/api/v1/boards/list",
    "/api/v1/boards/retrieve",
    "/api/v1/categories/list",
    "/api/v1/categories/retrieve",
    "/api/v1/posts/list",
    "/api/v1/posts/retrieve",
    "/api/v2/comments/list",
    "/api/v2/votes/list",
    "/api/v2/status_changes/list",
];

const ALLOWLISTED_OPERATIONS: &[&str] = &[
    "board.read",
    "post.read",
    "comment.read",
    "vote.aggregate.read",
    "status.read",
    "category.read",
    "roadmap.read_from_post",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyProviderDefinition {
    pub id: String,
    pub version: String,
    pub origin: String,
    pub method: String,
    pub paths: Vec<String>,
    pub allowlisted_operations: Vec<String>,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub https_transport: bool,
    pub first_party: bool,
    pub readback: bool,
    pub writes: bool,
    pub max_response_bytes: usize,
    pub max_posts: usize,
    pub max_comments: usize,
    pub max_vote_aggregates: usize,
    pub max_statuses: usize,
    pub max_categories: usize,
    pub max_roadmaps: usize,
    pub single_page: bool,
}

impl CannyProviderDefinition {
    pub fn new() -> Self {
        Self {
            id: CANNY_FEEDBACK_RESULT_PROVIDER_ID.to_owned(),
            version: CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            origin: CANNY_API_ORIGIN.to_owned(),
            method: CANNY_API_METHOD.to_owned(),
            paths: ALLOWLISTED_PATHS
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
            allowlisted_operations: ALLOWLISTED_OPERATIONS
                .iter()
                .map(|operation| (*operation).to_owned())
                .collect(),
            read_only: true,
            native: false,
            connected: false,
            https_transport: false,
            first_party: false,
            readback: false,
            writes: false,
            max_response_bytes: CANNY_MAX_RESPONSE_BYTES,
            max_posts: CANNY_MAX_POSTS,
            max_comments: CANNY_MAX_COMMENTS,
            max_vote_aggregates: CANNY_MAX_VOTE_AGGREGATES,
            max_statuses: CANNY_MAX_STATUSES,
            max_categories: CANNY_MAX_CATEGORIES,
            max_roadmaps: CANNY_MAX_ROADMAPS,
            single_page: true,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self != &Self::new() {
            Err(ProviderDefinitionError::DefinitionDrift)
        } else {
            Ok(())
        }
    }

    pub fn provider_digest(&self) -> Digest {
        crate::model::canonical_digest(self)
    }

    pub fn digest(&self) -> Digest {
        self.provider_digest()
    }
}

impl Default for CannyProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Canny provider definition drifted from the Layer-1 contract")]
    DefinitionDrift,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CannyTransportError {
    #[error("Canny returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("Canny rate limit exhausted")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Canny access was lost")]
    AccessLost,
    #[error("Canny response is partial and cannot be paginated in Layer 1")]
    Partial,
    #[error("Canny native transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Canny response exceeds the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("Canny response body is malformed")]
    MalformedResponse,
    #[error("Canny response is outside the registered scope")]
    ScopeDrift,
    #[error("Canny response exceeds a bounded evidence limit")]
    BoundExceeded,
    #[error("Canny response has an unexpected shape")]
    UnexpectedShape,
    #[error("Canny transport failed")]
    Transport,
}

impl CannyTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(status) => Some(*status),
            Self::RateLimited { .. } => Some(429),
            Self::AccessLost => Some(404),
            Self::Partial
            | Self::BlockedEnv
            | Self::ResponseTooLarge
            | Self::MalformedResponse
            | Self::ScopeDrift
            | Self::BoundExceeded
            | Self::UnexpectedShape
            | Self::Transport => None,
        }
    }

    pub const fn rate_limited() -> Self {
        Self::RateLimited {
            retry_after_seconds: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CannyHttpResponse {
    status: u16,
    body: String,
    partial: bool,
}

impl CannyHttpResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            partial: false,
        }
    }

    pub fn ok(body: impl Into<String>) -> Self {
        Self::new(200, body)
    }

    pub fn partial(body: impl Into<String>) -> Self {
        Self {
            status: 206,
            body: body.into(),
            partial: true,
        }
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn body_bytes(&self) -> usize {
        self.body.len()
    }

    pub const fn is_partial(&self) -> bool {
        self.partial
    }
}

impl fmt::Debug for CannyHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CannyHttpResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("partial", &self.partial)
            .finish()
    }
}

pub trait CannyFeedbackTransport: fmt::Debug {
    const PROVENANCE: ProviderProvenance;

    fn post(
        &mut self,
        request: &CannyFeedbackResultRequest,
    ) -> Result<CannyHttpResponse, CannyTransportError>;
}

pub use self::CannyFeedbackTransport as CannyTransport;

#[derive(Clone, Debug)]
pub struct FixtureCannyTransport {
    body: String,
}

impl FixtureCannyTransport {
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into() }
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

impl CannyFeedbackTransport for FixtureCannyTransport {
    const PROVENANCE: ProviderProvenance = ProviderProvenance::Fixture;

    fn post(
        &mut self,
        _request: &CannyFeedbackResultRequest,
    ) -> Result<CannyHttpResponse, CannyTransportError> {
        Ok(CannyHttpResponse::ok(self.body.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct RecordingCannyTransport {
    response: CannyHttpResponse,
    request_count: usize,
}

impl RecordingCannyTransport {
    pub fn new(body: impl Into<String>) -> Self {
        Self::from_response(CannyHttpResponse::ok(body))
    }

    pub fn from_response(response: CannyHttpResponse) -> Self {
        Self {
            response,
            request_count: 0,
        }
    }

    pub const fn request_count(&self) -> usize {
        self.request_count
    }
}

impl CannyFeedbackTransport for RecordingCannyTransport {
    const PROVENANCE: ProviderProvenance = ProviderProvenance::Recording;

    fn post(
        &mut self,
        _request: &CannyFeedbackResultRequest,
    ) -> Result<CannyHttpResponse, CannyTransportError> {
        self.request_count = self.request_count.saturating_add(1);
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeCannyTransport {
    body: String,
}

impl FakeCannyTransport {
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into() }
    }
}

impl CannyFeedbackTransport for FakeCannyTransport {
    const PROVENANCE: ProviderProvenance = ProviderProvenance::Fake;

    fn post(
        &mut self,
        _request: &CannyFeedbackResultRequest,
    ) -> Result<CannyHttpResponse, CannyTransportError> {
        Ok(CannyHttpResponse::ok(self.body.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackCannyTransport {
    body: String,
}

impl LoopbackCannyTransport {
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into() }
    }
}

impl CannyFeedbackTransport for LoopbackCannyTransport {
    const PROVENANCE: ProviderProvenance = ProviderProvenance::Loopback;

    fn post(
        &mut self,
        _request: &CannyFeedbackResultRequest,
    ) -> Result<CannyHttpResponse, CannyTransportError> {
        Ok(CannyHttpResponse::ok(self.body.clone()))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCannyTransport;

impl CannyFeedbackTransport for BlockedEnvCannyTransport {
    const PROVENANCE: ProviderProvenance = ProviderProvenance::BlockedEnv;

    fn post(
        &mut self,
        _request: &CannyFeedbackResultRequest,
    ) -> Result<CannyHttpResponse, CannyTransportError> {
        Err(CannyTransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvCannyTransport;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CannyProviderError {
    #[error("Canny provider definition drifted")]
    DefinitionDrift,
    #[error("Canny request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Canny request scope does not match the secret reference")]
    ScopeMismatch,
    #[error("Canny secret reference is revoked")]
    SecretRevoked,
}

pub type CannyFeedbackProviderError = CannyProviderError;

pub struct CannyProvider<T> {
    transport: T,
    definition: CannyProviderDefinition,
    quota: BTreeMap<(Digest, i64), u8>,
}

pub type CannyFeedbackProvider<T> = CannyProvider<T>;

impl<T> fmt::Debug for CannyProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CannyProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("quota_entries", &self.quota.len())
            .finish()
    }
}

impl<T> CannyProvider<T>
where
    T: CannyFeedbackTransport,
{
    pub fn new(transport: T) -> Result<Self, CannyProviderError> {
        let definition = CannyProviderDefinition::new();
        definition
            .validate()
            .map_err(|_| CannyProviderError::DefinitionDrift)?;
        Ok(Self {
            transport,
            definition,
            quota: BTreeMap::new(),
        })
    }

    pub fn with_definition(
        transport: T,
        definition: CannyProviderDefinition,
    ) -> Result<Self, CannyProviderError> {
        definition
            .validate()
            .map_err(|_| CannyProviderError::DefinitionDrift)?;
        Ok(Self {
            transport,
            definition,
            quota: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &CannyProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> ProviderProvenance {
        T::PROVENANCE
    }

    pub fn read(
        &mut self,
        request: &CannyFeedbackResultRequest,
        secret: &SecretReference,
    ) -> Result<CannyFeedbackProviderEvidence, CannyProviderError> {
        self.definition
            .validate()
            .map_err(|_| CannyProviderError::DefinitionDrift)?;
        request
            .validate()
            .map_err(|error| CannyProviderError::InvalidRequest(error.to_string()))?;
        if secret.is_revoked() {
            return Err(CannyProviderError::SecretRevoked);
        }
        if secret.scope_digest() != &request.scope().digest() {
            return Err(CannyProviderError::ScopeMismatch);
        }
        let quota_key = (
            request.scope_digest.clone(),
            request.requested_at().utc_hour(),
        );
        let used = self.quota.entry(quota_key).or_default();
        if *used >= CANNY_MAX_REQUESTS_PER_SCOPE_PER_UTC_HOUR {
            return Ok(self.error_evidence(
                request,
                secret,
                None,
                CannyTransportError::RateLimited {
                    retry_after_seconds: Some(60),
                },
            ));
        }
        *used = used.saturating_add(1);
        match self.transport.post(request) {
            Ok(response) => Ok(self.parse_response(request, secret, response)),
            Err(error) => Ok(self.error_evidence(request, secret, None, error)),
        }
    }

    fn parse_response(
        &self,
        request: &CannyFeedbackResultRequest,
        secret: &SecretReference,
        response: CannyHttpResponse,
    ) -> CannyFeedbackProviderEvidence {
        let response_digest = Digest::from_text(response.body());
        if response.body_bytes() > self.definition.max_response_bytes {
            return self.error_evidence(
                request,
                secret,
                Some(response_digest),
                CannyTransportError::ResponseTooLarge,
            );
        }
        if response.status() == 401 || response.status() == 403 {
            return self.error_evidence(
                request,
                secret,
                Some(response_digest),
                CannyTransportError::HttpStatus(response.status()),
            );
        }
        if response.status() == 404 {
            return self.error_evidence(
                request,
                secret,
                Some(response_digest),
                CannyTransportError::AccessLost,
            );
        }
        if response.status() == 429 {
            return self.error_evidence(
                request,
                secret,
                Some(response_digest),
                CannyTransportError::rate_limited(),
            );
        }
        if response.status() >= 400 {
            return self.error_evidence(
                request,
                secret,
                Some(response_digest),
                CannyTransportError::HttpStatus(response.status()),
            );
        }
        let value = match serde_json::from_str::<Value>(response.body()) {
            Ok(value) => value,
            Err(_) => {
                return self.error_evidence(
                    request,
                    secret,
                    Some(response_digest),
                    CannyTransportError::MalformedResponse,
                );
            }
        };
        let mut parsed = match parse_payload(&value, request.scope()) {
            Ok(parsed) => parsed,
            Err(failure) => {
                return self.error_evidence(
                    request,
                    secret,
                    Some(response_digest),
                    failure.transport_error(),
                );
            }
        };
        apply_redaction_counts(&value, &mut parsed.redactions);
        let mut evidence = CannyFeedbackProviderEvidence {
            request_digest: request.request_digest().clone(),
            project_digest: request.scope().project.digest(),
            scope_digest: request.scope().digest(),
            provider_digest: self.definition.provider_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            provenance: TProvenance::value::<T>(),
            status: parsed.status(response.is_partial()),
            error: parsed.error(response.is_partial()),
            board: parsed.board,
            posts: parsed.posts,
            comments: parsed.comments,
            vote_aggregates: parsed.vote_aggregates,
            statuses: parsed.statuses,
            categories: parsed.categories,
            roadmaps: parsed.roadmaps,
            redactions: parsed.redactions,
            response_digest,
            retry_after_seconds: None,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence);
        evidence
    }

    fn error_evidence(
        &self,
        request: &CannyFeedbackResultRequest,
        secret: &SecretReference,
        response_digest: Option<Digest>,
        error: CannyTransportError,
    ) -> CannyFeedbackProviderEvidence {
        let (status, error_kind) = status_for_transport(&error);
        let response_digest = response_digest.unwrap_or_else(|| {
            Digest::from_fields("canny-transport-error/v1", &[format!("{error:?}")])
        });
        let mut evidence = CannyFeedbackProviderEvidence {
            request_digest: request.request_digest().clone(),
            project_digest: request.scope().project.digest(),
            scope_digest: request.scope().digest(),
            provider_digest: self.definition.provider_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            provenance: TProvenance::value::<T>(),
            status,
            error: Some(error_kind),
            board: None,
            posts: Vec::new(),
            comments: Vec::new(),
            vote_aggregates: Vec::new(),
            statuses: Vec::new(),
            categories: Vec::new(),
            roadmaps: Vec::new(),
            redactions: RedactionSummary::strict(),
            response_digest,
            retry_after_seconds: retry_after_for_transport(&error),
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence);
        evidence
    }
}

impl CannyProvider<FixtureCannyTransport> {
    pub fn fixture(body: impl Into<String>) -> Self {
        Self::new(FixtureCannyTransport::new(body)).expect("fixed Canny provider definition")
    }
}

impl CannyProvider<RecordingCannyTransport> {
    pub fn recording(body: impl Into<String>) -> Self {
        Self::new(RecordingCannyTransport::new(body)).expect("fixed Canny provider definition")
    }
}

impl CannyProvider<FakeCannyTransport> {
    pub fn fake(body: impl Into<String>) -> Self {
        Self::new(FakeCannyTransport::new(body)).expect("fixed Canny provider definition")
    }
}

impl CannyProvider<LoopbackCannyTransport> {
    pub fn loopback(body: impl Into<String>) -> Self {
        Self::new(LoopbackCannyTransport::new(body)).expect("fixed Canny provider definition")
    }
}

impl CannyProvider<BlockedEnvCannyTransport> {
    pub fn blocked_env() -> Self {
        Self::new(BlockedEnvCannyTransport).expect("fixed Canny provider definition")
    }
}

const fn retry_after_for_transport(error: &CannyTransportError) -> Option<u64> {
    match error {
        CannyTransportError::RateLimited {
            retry_after_seconds,
        } => *retry_after_seconds,
        _ => None,
    }
}

struct TProvenance;

impl TProvenance {
    fn value<T: CannyFeedbackTransport>() -> ProviderProvenance {
        T::PROVENANCE
    }
}

fn status_for_transport(
    error: &CannyTransportError,
) -> (CannyFeedbackResultStatus, ProviderErrorKind) {
    match error {
        CannyTransportError::HttpStatus(401 | 403) => {
            (CannyFeedbackResultStatus::Denied, ProviderErrorKind::Denied)
        }
        CannyTransportError::HttpStatus(404) | CannyTransportError::AccessLost => (
            CannyFeedbackResultStatus::AccessLost,
            ProviderErrorKind::AccessLost,
        ),
        CannyTransportError::RateLimited { .. } | CannyTransportError::HttpStatus(429) => (
            CannyFeedbackResultStatus::RateLimited,
            ProviderErrorKind::RateLimited,
        ),
        CannyTransportError::Partial => (
            CannyFeedbackResultStatus::Partial,
            ProviderErrorKind::Partial,
        ),
        CannyTransportError::BlockedEnv => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::BlockedEnv,
        ),
        CannyTransportError::ResponseTooLarge => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::ResponseTooLarge,
        ),
        CannyTransportError::MalformedResponse => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::MalformedResponse,
        ),
        CannyTransportError::ScopeDrift => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::ScopeDrift,
        ),
        CannyTransportError::BoundExceeded => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::ResponseTooLarge,
        ),
        CannyTransportError::UnexpectedShape => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::UnexpectedShape,
        ),
        CannyTransportError::Transport | CannyTransportError::HttpStatus(_) => (
            CannyFeedbackResultStatus::ProviderUnknown,
            ProviderErrorKind::Transport,
        ),
    }
}

#[derive(Clone, Copy, Debug)]
enum ParseFailure {
    ScopeDrift,
    BoundExceeded,
    MalformedResponse,
    UnexpectedShape,
}

impl ParseFailure {
    const fn transport_error(self) -> CannyTransportError {
        match self {
            Self::ScopeDrift => CannyTransportError::ScopeDrift,
            Self::BoundExceeded => CannyTransportError::BoundExceeded,
            Self::UnexpectedShape => CannyTransportError::UnexpectedShape,
            Self::MalformedResponse => CannyTransportError::MalformedResponse,
        }
    }
}

struct ParsedFeedback {
    board: Option<BoardEvidence>,
    posts: Vec<PostEvidence>,
    comments: Vec<CommentEvidence>,
    vote_aggregates: Vec<VoteAggregate>,
    statuses: Vec<StatusEvidence>,
    categories: Vec<CategoryEvidence>,
    roadmaps: Vec<RoadmapEvidence>,
    redactions: RedactionSummary,
    status_hint: Option<FeedbackPostStatus>,
    partial: bool,
}

impl ParsedFeedback {
    fn status(&self, response_partial: bool) -> CannyFeedbackResultStatus {
        if response_partial || self.partial {
            return CannyFeedbackResultStatus::Partial;
        }
        match self.status_hint {
            Some(FeedbackPostStatus::Open) => CannyFeedbackResultStatus::Open,
            Some(FeedbackPostStatus::Planned) => CannyFeedbackResultStatus::Planned,
            Some(FeedbackPostStatus::Complete) => CannyFeedbackResultStatus::Complete,
            Some(FeedbackPostStatus::Duplicate) => CannyFeedbackResultStatus::Duplicate,
            Some(
                FeedbackPostStatus::UnderReview
                | FeedbackPostStatus::InProgress
                | FeedbackPostStatus::Unknown,
            )
            | None => CannyFeedbackResultStatus::Unknown,
        }
    }

    fn error(&self, response_partial: bool) -> Option<ProviderErrorKind> {
        if response_partial || self.partial {
            Some(ProviderErrorKind::Partial)
        } else {
            None
        }
    }
}

fn parse_payload(
    value: &Value,
    scope: &CannyFeedbackScope,
) -> Result<ParsedFeedback, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::UnexpectedShape)?;
    let mut parsed = ParsedFeedback {
        board: None,
        posts: Vec::new(),
        comments: Vec::new(),
        vote_aggregates: Vec::new(),
        statuses: Vec::new(),
        categories: Vec::new(),
        roadmaps: Vec::new(),
        redactions: RedactionSummary::strict(),
        status_hint: object
            .get("status")
            .and_then(Value::as_str)
            .map(FeedbackPostStatus::parse),
        partial: bool_field(object, "partial")
            || bool_field(object, "hasMore")
            || bool_field(object, "hasNextPage"),
    };

    let recognized = [
        "board",
        "boards",
        "posts",
        "ideas",
        "comments",
        "portalComments",
        "votes",
        "items",
        "statuses",
        "statusChanges",
        "status_changes",
        "categories",
        "roadmaps",
        "status",
    ]
    .iter()
    .any(|key| object.contains_key(*key));
    if !recognized {
        return Err(ParseFailure::UnexpectedShape);
    }

    let board_value = object
        .get("board")
        .or_else(|| object.get("boards").and_then(first_array_value))
        .or_else(|| {
            object
                .get("id")
                .filter(|_| object.contains_key("postCount") || object.contains_key("post_count"))
        });
    if let Some(board_value) = board_value.filter(|value| !value.is_null()) {
        parsed.board = Some(parse_board(board_value, scope)?);
    }

    if let Some(values) = array_field(object, &["posts", "ideas"]) {
        for value in values {
            parsed
                .posts
                .push(parse_post(value, scope, &mut parsed.redactions)?);
        }
    }
    if parsed.posts.len() > CANNY_MAX_POSTS {
        return Err(ParseFailure::BoundExceeded);
    }

    if let Some(values) = array_field(object, &["comments", "portalComments"]) {
        for value in values {
            parsed
                .comments
                .push(parse_comment(value, scope, &mut parsed.redactions)?);
        }
    }
    if parsed.comments.len() > CANNY_MAX_COMMENTS {
        return Err(ParseFailure::BoundExceeded);
    }

    if let Some(values) = array_field(object, &["votes"]) {
        parse_votes(values, scope, &mut parsed)?;
    }
    if parsed.vote_aggregates.len() > CANNY_MAX_VOTE_AGGREGATES {
        return Err(ParseFailure::BoundExceeded);
    }

    if let Some(values) = array_field(object, &["statuses", "statusChanges", "status_changes"]) {
        for value in values {
            parsed.statuses.push(parse_status(value, scope)?);
        }
    }
    if parsed.statuses.len() > CANNY_MAX_STATUSES {
        return Err(ParseFailure::BoundExceeded);
    }

    if let Some(values) = array_field(object, &["items"]) {
        match classify_items(values) {
            ItemsKind::Comments => {
                for value in values {
                    parsed
                        .comments
                        .push(parse_comment(value, scope, &mut parsed.redactions)?);
                }
            }
            ItemsKind::Votes => parse_votes(values, scope, &mut parsed)?,
            ItemsKind::Statuses => {
                for value in values {
                    parsed.statuses.push(parse_status(value, scope)?);
                }
            }
            ItemsKind::Unknown => {}
        }
    }
    if parsed.comments.len() > CANNY_MAX_COMMENTS
        || parsed.vote_aggregates.len() > CANNY_MAX_VOTE_AGGREGATES
        || parsed.statuses.len() > CANNY_MAX_STATUSES
    {
        return Err(ParseFailure::BoundExceeded);
    }

    if let Some(values) = array_field(object, &["categories"]) {
        for value in values {
            parsed.categories.push(parse_category(value, scope)?);
        }
    }
    if parsed.categories.len() > CANNY_MAX_CATEGORIES {
        return Err(ParseFailure::BoundExceeded);
    }

    if let Some(values) = array_field(object, &["roadmaps"]) {
        for value in values {
            parsed.roadmaps.push(parse_roadmap(value, scope)?);
        }
    }
    let post_roadmaps = parsed
        .posts
        .iter()
        .flat_map(|post| post.roadmap_digests.iter().cloned())
        .collect::<Vec<_>>();
    for roadmap_digest in post_roadmaps {
        if !parsed
            .roadmaps
            .iter()
            .any(|roadmap| roadmap.roadmap_digest == roadmap_digest)
        {
            parsed.roadmaps.push(RoadmapEvidence {
                roadmap_digest,
                post_count: 0,
                archived: false,
            });
        }
    }
    if parsed.roadmaps.len() > CANNY_MAX_ROADMAPS {
        return Err(ParseFailure::BoundExceeded);
    }

    let mut statuses = parsed
        .posts
        .iter()
        .map(|post| post.status)
        .collect::<Vec<_>>();
    statuses.sort_unstable();
    statuses.dedup();
    if parsed.status_hint.is_none() && statuses.len() == 1 {
        parsed.status_hint = statuses.first().copied();
    } else if statuses.len() > 1 {
        parsed.status_hint = Some(FeedbackPostStatus::Unknown);
    }
    Ok(parsed)
}

fn parse_board(value: &Value, scope: &CannyFeedbackScope) -> Result<BoardEvidence, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
    let id = required_id(object, "id")?;
    if id != scope.board.id.as_str() {
        return Err(ParseFailure::ScopeDrift);
    }
    Ok(BoardEvidence {
        board_digest: scope.board.id.digest(),
        post_count: bounded_count(object, &["postCount", "post_count"])?.unwrap_or_default(),
        private: bool_field(object, "isPrivate") || bool_field(object, "private"),
    })
}

fn parse_post(
    value: &Value,
    scope: &CannyFeedbackScope,
    redactions: &mut RedactionSummary,
) -> Result<PostEvidence, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
    let id = required_id(object, "id")?;
    if !scope.post.allows(&id) {
        return Err(ParseFailure::ScopeDrift);
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .map_or(FeedbackPostStatus::Unknown, FeedbackPostStatus::parse);
    if !scope.status.allows(status) {
        return Err(ParseFailure::ScopeDrift);
    }
    let category_digest = nested_id(object, &["category", "categoryID", "categoryId"])
        .map(|category_id| {
            if !scope.category.allows(&category_id) {
                Err(ParseFailure::ScopeDrift)
            } else {
                Ok(external_digest("CategoryId", &category_id))
            }
        })
        .transpose()?;
    let mut roadmap_digests = Vec::new();
    if let Some(values) = object.get("roadmaps").and_then(Value::as_array) {
        for roadmap in values {
            let roadmap_id = required_id(
                roadmap.as_object().ok_or(ParseFailure::MalformedResponse)?,
                "id",
            )?;
            if !scope.roadmap.allows(&roadmap_id) {
                return Err(ParseFailure::ScopeDrift);
            }
            roadmap_digests.push(external_digest("RoadmapId", &roadmap_id));
        }
    }
    if let Some(body) = object.get("title").or_else(|| object.get("body"))
        && !body.is_null()
    {
        redactions.feedback_text_dropped = redactions.feedback_text_dropped.saturating_add(1);
    }
    Ok(PostEvidence {
        post_digest: scope_digest_for_id("PostId", &id),
        status,
        category_digest,
        roadmap_digests,
        comment_count: bounded_count(object, &["commentCount", "comment_count"])?
            .unwrap_or_default(),
        vote_count: bounded_count_u64(object, &["score", "voteCount", "vote_count"])?
            .unwrap_or_default(),
        feedback_text_redacted: true,
    })
}

fn parse_comment(
    value: &Value,
    scope: &CannyFeedbackScope,
    redactions: &mut RedactionSummary,
) -> Result<CommentEvidence, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
    let id = required_id(object, "id")?;
    if !scope.comment.allows(&id) {
        return Err(ParseFailure::ScopeDrift);
    }
    let post_id =
        nested_id(object, &["post", "postID", "postId"]).ok_or(ParseFailure::MalformedResponse)?;
    if !scope.post.allows(&post_id) {
        return Err(ParseFailure::ScopeDrift);
    }
    if object.get("body").is_some() || object.get("value").is_some() {
        redactions.comment_body_dropped = redactions.comment_body_dropped.saturating_add(1);
        redactions.feedback_text_dropped = redactions.feedback_text_dropped.saturating_add(1);
    }
    if object.get("author").is_some() || object.get("user").is_some() {
        redactions.author_identity_dropped = redactions.author_identity_dropped.saturating_add(1);
    }
    Ok(CommentEvidence {
        comment_digest: external_digest("CommentId", &id),
        post_digest: external_digest("PostId", &post_id),
        body_redacted: true,
        author_redacted: true,
    })
}

fn parse_votes(
    values: &[Value],
    scope: &CannyFeedbackScope,
    parsed: &mut ParsedFeedback,
) -> Result<(), ParseFailure> {
    let mut counts = std::collections::BTreeMap::<Digest, u64>::new();
    for value in values {
        let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
        let post_id = nested_id(object, &["post", "postID", "postId"])
            .ok_or(ParseFailure::MalformedResponse)?;
        if !scope.post.allows(&post_id) {
            return Err(ParseFailure::ScopeDrift);
        }
        if object.get("user").is_some() || object.get("voter").is_some() {
            parsed.redactions.voter_identity_dropped =
                parsed.redactions.voter_identity_dropped.saturating_add(1);
        }
        let post_digest = external_digest("PostId", &post_id);
        let count = bounded_count_u64(object, &["count", "score"])?.unwrap_or(1);
        let entry = counts.entry(post_digest).or_default();
        *entry = entry.saturating_add(count);
    }
    for (post_digest, count) in counts {
        parsed.vote_aggregates.push(VoteAggregate {
            post_digest,
            vote_window_digest: scope.vote_window.digest(),
            count,
        });
    }
    Ok(())
}

fn parse_status(value: &Value, scope: &CannyFeedbackScope) -> Result<StatusEvidence, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
    let id = required_id(object, "id")?;
    let post_id =
        nested_id(object, &["post", "postID", "postId"]).ok_or(ParseFailure::MalformedResponse)?;
    if !scope.post.allows(&post_id) {
        return Err(ParseFailure::ScopeDrift);
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .map_or(FeedbackPostStatus::Unknown, FeedbackPostStatus::parse);
    if !scope.status.allows(status) {
        return Err(ParseFailure::ScopeDrift);
    }
    Ok(StatusEvidence {
        status_change_digest: external_digest("StatusId", &id),
        post_digest: external_digest("PostId", &post_id),
        status,
    })
}

fn parse_category(
    value: &Value,
    scope: &CannyFeedbackScope,
) -> Result<CategoryEvidence, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
    let id = required_id(object, "id")?;
    if !scope.category.allows(&id) {
        return Err(ParseFailure::ScopeDrift);
    }
    let board_id = nested_id(object, &["board", "boardID", "boardId"])
        .unwrap_or_else(|| scope.board.id.as_str().to_owned());
    if board_id != scope.board.id.as_str() {
        return Err(ParseFailure::ScopeDrift);
    }
    Ok(CategoryEvidence {
        category_digest: external_digest("CategoryId", &id),
        board_digest: scope.board.id.digest(),
        post_count: bounded_count(object, &["postCount", "post_count"])?.unwrap_or_default(),
    })
}

fn parse_roadmap(
    value: &Value,
    scope: &CannyFeedbackScope,
) -> Result<RoadmapEvidence, ParseFailure> {
    let object = value.as_object().ok_or(ParseFailure::MalformedResponse)?;
    let id = required_id(object, "id")?;
    if !scope.roadmap.allows(&id) {
        return Err(ParseFailure::ScopeDrift);
    }
    Ok(RoadmapEvidence {
        roadmap_digest: external_digest("RoadmapId", &id),
        post_count: bounded_count(object, &["postCount", "post_count"])?.unwrap_or_default(),
        archived: bool_field(object, "archived"),
    })
}

fn array_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a [Value]> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ItemsKind {
    Comments,
    Votes,
    Statuses,
    Unknown,
}

fn classify_items(values: &[Value]) -> ItemsKind {
    let Some(object) = values.first().and_then(Value::as_object) else {
        return ItemsKind::Unknown;
    };
    if object.contains_key("changeComment")
        || object.contains_key("changer")
        || (object.contains_key("status") && object.contains_key("post"))
    {
        ItemsKind::Statuses
    } else if object.contains_key("user") || object.contains_key("voter") {
        ItemsKind::Votes
    } else if object.contains_key("author")
        || object.contains_key("body")
        || object.contains_key("value")
    {
        ItemsKind::Comments
    } else {
        ItemsKind::Unknown
    }
}

fn first_array_value(value: &Value) -> Option<&Value> {
    value.as_array().and_then(|values| values.first())
}

fn bool_field(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn required_id(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, ParseFailure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= crate::model::MAX_IDENTIFIER_BYTES)
        .map(ToOwned::to_owned)
        .ok_or(ParseFailure::MalformedResponse)
}

fn nested_id(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| match value {
            Value::String(value) if !value.is_empty() => Some(value.clone()),
            Value::Object(object) => object
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        })
    })
}

fn bounded_count(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<u32>, ParseFailure> {
    bounded_count_u64(object, keys)?.map_or(Ok(None), |value| {
        u32::try_from(value)
            .map(Some)
            .map_err(|_| ParseFailure::BoundExceeded)
    })
}

fn bounded_count_u64(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<u64>, ParseFailure> {
    let Some(value) = keys.iter().find_map(|key| object.get(*key)) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(ParseFailure::MalformedResponse);
    };
    Ok(Some(value))
}

fn external_digest(kind: &str, value: &str) -> Digest {
    Digest::from_fields(&format!("canny-{kind}/v1"), &[value.to_owned()])
}

fn scope_digest_for_id(kind: &str, value: &str) -> Digest {
    external_digest(kind, value)
}

fn apply_redaction_counts(value: &Value, redactions: &mut RedactionSummary) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let lowered = key.to_ascii_lowercase();
                let identity = matches!(
                    lowered.as_str(),
                    "author" | "user" | "voter" | "owner" | "changer"
                );
                if identity && !value.is_null() {
                    if lowered == "voter" || lowered == "user" {
                        redactions.voter_identity_dropped =
                            redactions.voter_identity_dropped.saturating_add(1);
                    } else {
                        redactions.author_identity_dropped =
                            redactions.author_identity_dropped.saturating_add(1);
                    }
                }
                if matches!(
                    lowered.as_str(),
                    "email" | "userid" | "user_id" | "authorid" | "author_id" | "companyid"
                ) && !value.is_null()
                {
                    redactions.user_pii_dropped = redactions.user_pii_dropped.saturating_add(1);
                }
                if matches!(lowered.as_str(), "url" | "imageurls" | "image_urls")
                    && !value.is_null()
                {
                    redactions.urls_dropped = redactions.urls_dropped.saturating_add(1);
                }
                if lowered.contains("token") || lowered == "apikey" || lowered == "api_key" {
                    redactions.tokens_dropped = redactions.tokens_dropped.saturating_add(1);
                }
                if lowered == "jira" || lowered == "linear" || lowered == "project" {
                    redactions.jira_or_project_links_dropped =
                        redactions.jira_or_project_links_dropped.saturating_add(1);
                }
                if matches!(
                    lowered.as_str(),
                    "body" | "value" | "markdown" | "markdownbody" | "plaintextdetails"
                ) && !value.is_null()
                {
                    redactions.feedback_text_dropped =
                        redactions.feedback_text_dropped.saturating_add(1);
                }
                apply_redaction_counts(value, redactions);
            }
        }
        Value::Array(values) => {
            for value in values {
                apply_redaction_counts(value, redactions);
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

pub(crate) fn compute_evidence_digest(evidence: &CannyFeedbackProviderEvidence) -> Digest {
    let mut fingerprint = evidence.clone();
    fingerprint.evidence_digest = Digest::zero();
    crate::model::canonical_digest(&fingerprint)
}

#[allow(dead_code)]
fn _keep_model_error_visible(_: ModelError, _: Revision) {}
