use thiserror::Error;

/// Result alias for the bounded SageMaker endpoint-result seam.
pub type Result<T> = std::result::Result<T, SageMakerEndpointResultError>;

/// Errors are deliberately typed at the provider boundary. No raw AWS
/// response body, credential material, log line, or inference payload is
/// carried by this error type.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SageMakerEndpointResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid traffic snapshot")]
    InvalidTraffic,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("registration has been revoked")]
    RegistrationRevoked,
    #[error("registration digest mismatch")]
    RegistrationDigestMismatch,
    #[error("secret reference does not belong to the exact SageMaker scope")]
    SecretReferenceMismatch,
    #[error("long-lived AWS credentials are not accepted")]
    LongLivedCredentialsRejected,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("Work Product revision is stale")]
    StaleWorkProductRevision,
    #[error("endpoint identity changed for the same endpoint name")]
    SameNameReplacement,
    #[error("endpoint configuration identity or digest drifted")]
    EndpointConfigDrift,
    #[error("production variant mismatch")]
    VariantMismatch,
    #[error("model revision drifted")]
    ModelRevisionDrift,
    #[error("model digest mismatch")]
    ModelDigestMismatch,
    #[error("image reference digest mismatch")]
    ImageDigestMismatch,
    #[error("model code digest mismatch")]
    CodeDigestMismatch,
    #[error("endpoint configuration digest mismatch")]
    ConfigDigestMismatch,
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("partial provider response")]
    PartialResponse,
    #[error("provider returned an unknown state")]
    ProviderUnknown,
    #[error("endpoint access was lost")]
    AccessLost,
    #[error("duplicate evidence fingerprint")]
    DuplicateFingerprint,
    #[error("invalid evidence")]
    InvalidEvidence,
    #[error("evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("proposal digest mismatch")]
    ProposalDigestMismatch,
    #[error("receipt mismatch")]
    ReceiptMismatch,
    #[error("provider is blocked by the Layer-2 environment gate")]
    BlockedEnv,
    #[error("AWS request was rejected as malformed (400)")]
    BadRequest,
    #[error("AWS credentials were rejected (401)")]
    Unauthorized,
    #[error("AWS permission was denied (403)")]
    Forbidden,
    #[error("SageMaker resource was not found (404)")]
    NotFound,
    #[error("SageMaker request conflicted (409)")]
    Conflict,
    #[error("SageMaker request was rate limited (429)")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("SageMaker request timed out")]
    Timeout,
    #[error("SageMaker server error ({status})")]
    ServerError { status: u16 },
    #[error("provider response exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("retry budget exhausted")]
    RetryExhausted,
    #[error("mutation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
}
