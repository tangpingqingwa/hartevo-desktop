use thiserror::Error;

/// Errors at the typed Layer-1 Cloud Run boundary.  Error variants never
/// carry raw response bodies, URLs with credentials, IAM principals, or logs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CloudRunDeploymentResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid Cloud Run traffic plan")]
    InvalidTraffic,
    #[error("invalid Cloud Run registration")]
    InvalidRegistration,
    #[error("Cloud Run registration is revoked")]
    RegistrationRevoked,
    #[error("Cloud Run registration digest does not match")]
    RegistrationDigestMismatch,
    #[error("Cloud Run provider version does not match")]
    ProviderVersionMismatch,
    #[error("Cloud Run scope does not match the registration")]
    ScopeMismatch,
    #[error("Cloud Run permission snapshot does not match the registration")]
    PermissionDrift,
    #[error("Cloud Run Mission revision is stale")]
    StaleMissionRevision,
    #[error("Cloud Run Work Product revision is stale")]
    StaleWorkProductRevision,
    #[error("Cloud Run service generation is stale")]
    StaleGeneration,
    #[error("Cloud Run revision is stale or replaced")]
    StaleRevision,
    #[error("Cloud Run service with the same name was replaced")]
    SameNameReplacement,
    #[error("Cloud Run source image or digest does not match the exact scope")]
    SourceDigestMismatch,
    #[error("Cloud Run traffic allocation does not match the exact scope")]
    TrafficMismatch,
    #[error("Cloud Run readiness evidence is partial")]
    PartialEvidence,
    #[error("Cloud Run provider returned an unknown state")]
    ProviderUnknown,
    #[error("provider returned an authorization-obscured 404")]
    NotFoundOrUnauthorized,
    #[error("provider rejected authentication")]
    Unauthorized,
    #[error("provider denied access")]
    Forbidden,
    #[error("Cloud Run resource was not found")]
    NotFound,
    #[error("BLOCKED_ENV: Google Cloud credentials are unavailable")]
    BlockedEnv,
    #[error("provider reported a conflicting Cloud Run state")]
    Conflict,
    #[error("provider rejected the typed request")]
    UnprocessableEntity,
    #[error("provider rate limit exceeded")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider transport failed")]
    Transport,
    #[error("provider response could not be decoded")]
    Decode,
    #[error("provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("bounded retry budget was exhausted")]
    RetryExhausted,
    #[error("bounded revision pagination exceeded its hard fence")]
    PaginationBoundExceeded,
    #[error("the provider evidence is invalid or tampered")]
    InvalidEvidence,
    #[error("the provider evidence was truncated")]
    TruncatedEvidence,
    #[error("an equivalent Cloud Run receipt already exists with a different fingerprint")]
    DuplicateFingerprint,
    #[error("the Cloud Run receipt was not recorded by this provider")]
    ReceiptNotRecorded,
    #[error("the Cloud Run receipt does not match the exact provider evidence")]
    ReceiptMismatch,
    #[error("Layer 1 is read-only; {operation} is reserved for Layer 2")]
    MutationForbidden { operation: &'static str },
    #[error("native Connected or first-party evidence is not available in Layer 1")]
    NativeConnectedForbidden,
}

/// Transport failures preserve HTTP authorization and bounded-response
/// semantics without retaining provider error bodies.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CloudRunTransportError {
    #[error("authorization-obscured not found")]
    NotFoundOrUnauthorized,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("unprocessable entity")]
    UnprocessableEntity,
    #[error("rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("request timed out")]
    Timeout,
    #[error("server unavailable")]
    ServerUnavailable,
    #[error("network failure")]
    Network,
    #[error("response could not be decoded")]
    Decode,
    #[error("response exceeded the bounded size")]
    ResponseTooLarge,
    #[error("transport configuration is invalid")]
    InvalidConfiguration,
}

impl From<CloudRunTransportError> for CloudRunDeploymentResultError {
    fn from(error: CloudRunTransportError) -> Self {
        match error {
            CloudRunTransportError::NotFoundOrUnauthorized => Self::NotFoundOrUnauthorized,
            CloudRunTransportError::Unauthorized => Self::Unauthorized,
            CloudRunTransportError::Forbidden => Self::Forbidden,
            CloudRunTransportError::NotFound => Self::NotFound,
            CloudRunTransportError::Conflict => Self::Conflict,
            CloudRunTransportError::UnprocessableEntity => Self::UnprocessableEntity,
            CloudRunTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            CloudRunTransportError::Timeout => Self::Timeout,
            CloudRunTransportError::ServerUnavailable => Self::RetryExhausted,
            CloudRunTransportError::Network => Self::Transport,
            CloudRunTransportError::Decode => Self::Decode,
            CloudRunTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            CloudRunTransportError::InvalidConfiguration => Self::InvalidInput {
                field: "Cloud Run transport",
                reason: "configuration is not an exact HTTPS or loopback endpoint",
            },
        }
    }
}
