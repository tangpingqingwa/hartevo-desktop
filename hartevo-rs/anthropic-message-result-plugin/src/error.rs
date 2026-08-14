use thiserror::Error;

/// Result alias for the bounded Anthropic Messages Layer-1 seam.
pub type Result<T> = std::result::Result<T, AnthropicMessageResultError>;

/// Errors never carry raw prompts, output, thinking, tool input, credentials,
/// or provider error bodies. They are deliberately projected at the boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AnthropicMessageResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid provider registration")]
    InvalidRegistration,
    #[error("registration has been revoked")]
    RegistrationRevoked,
    #[error("registration digest mismatch")]
    RegistrationDigestMismatch,
    #[error("secret reference does not belong to the exact scope")]
    SecretReferenceMismatch,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("provider identity or revision drifted")]
    ProviderRevisionDrift,
    #[error("API identity or version drifted")]
    ApiVersionDrift,
    #[error("model identity or immutable version drifted")]
    ModelVersionDrift,
    #[error("permission snapshot drifted")]
    PermissionDrift,
    #[error("project revision is stale")]
    StaleProjectRevision,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("Work Product revision is stale")]
    StaleWorkProductRevision,
    #[error("request id is missing or invalid")]
    RequestIdInvalid,
    #[error("request replay was detected")]
    ReplayDetected,
    #[error("proposal digest mismatch")]
    ProposalDigestMismatch,
    #[error("evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("response digest mismatch")]
    ResponseDigestMismatch,
    #[error("request body exceeds the configured content bound")]
    RequestContentTooLarge,
    #[error("message count exceeds the configured bound")]
    MessageCountExceeded,
    #[error("message content exceeds the configured bound")]
    MessageContentTooLarge,
    #[error("max_tokens exceeds the configured bound")]
    MaxTokensExceeded,
    #[error("streaming is forbidden by the Layer-1 contract")]
    StreamingForbidden,
    #[error("tools and tool execution are forbidden by the Layer-1 contract")]
    ToolExecutionForbidden,
    #[error("file upload is forbidden by the Layer-1 contract")]
    FileUploadForbidden,
    #[error("batch administration is forbidden by the Layer-1 contract")]
    BatchAdministrationForbidden,
    #[error("model registry or model creation is forbidden by the Layer-1 contract")]
    ModelRegistryForbidden,
    #[error("HTTP method is not allowlisted")]
    MethodNotAllowlisted,
    #[error("HTTP path is not allowlisted")]
    PathNotAllowlisted,
    #[error("response exceeded the configured bound")]
    ResponseTooLarge,
    #[error("response was malformed: {0}")]
    MalformedResponse(&'static str),
    #[error("response was partial: {0}")]
    PartialResponse(&'static str),
    #[error("provider returned an unsupported status: {0}")]
    UnsupportedStatus(u16),
    #[error("provider returned HTTP 400")]
    BadRequest,
    #[error("provider rejected credentials with HTTP 401")]
    Unauthorized,
    #[error("provider denied permission with HTTP 403")]
    Forbidden,
    #[error("provider returned HTTP 404")]
    NotFound,
    #[error("provider returned HTTP 409")]
    Conflict,
    #[error("provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned server error HTTP {status}")]
    ServerError { status: u16 },
    #[error("provider transport is unavailable")]
    TransportUnavailable,
    #[error("provider is blocked by the environment gate: {0}")]
    BlockedEnv(&'static str),
    #[error("provider returned an unknown projection")]
    ProviderUnknown,
    #[error("token usage is internally inconsistent")]
    UsageInconsistent,
    #[error("latency is outside the configured bound")]
    LatencyInvalid,
    #[error("native execution remains a Layer-2 gap")]
    NativeExecutionUnavailable,
    #[error("operation is forbidden in Layer 1: {0}")]
    MutationForbidden(&'static str),
}
