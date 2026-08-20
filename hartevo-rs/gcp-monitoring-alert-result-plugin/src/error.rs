use thiserror::Error;

pub type Result<T> = std::result::Result<T, GcpMonitoringAlertError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpMonitoringAlertError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("page token is empty, oversized, or contains whitespace")]
    InvalidPageToken,
    #[error("scope is empty or internally inconsistent")]
    InvalidScope,
    #[error("allowlist or bound is empty or exceeds the Layer-1 ceiling")]
    InvalidBound,
    #[error("timestamp is not a valid RFC-3339 value")]
    InvalidTimestamp,
    #[error("policy condition is unsupported or exceeds the safe shape")]
    InvalidPolicyCondition,
    #[error("label set is empty, duplicated, or exceeds the safe shape")]
    InvalidLabels,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration is already reversed")]
    AlreadyReversed,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("provider definition is invalid")]
    InvalidProviderDefinition,
    #[error("provider evidence is tampered or has a stale digest")]
    TamperedEvidence,
    #[error("provider response exceeds the bounded evidence shape")]
    InvalidResponseShape,
    #[error("provider response fence does not match the request")]
    FenceMismatch,
    #[error("provider returned a different metrics scope or project")]
    ScopeMismatch,
    #[error("provider returned a policy or alert outside the registered allowlist")]
    PolicyOrAlertOutOfScope,
    #[error("provider returned a different policy or alert identity")]
    IdentityMismatch,
    #[error("provider returned an alert whose policy snapshot does not match")]
    PolicyAlertMismatch,
    #[error("provider returned a repeated opaque page token")]
    PaginationLoop,
    #[error("provider returned a page without the required next token")]
    MissingPageToken,
    #[error("provider returned a changed policy or alert projection")]
    ProjectionDrift,
    #[error("record idempotency key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("recorded evidence failed deterministic read-back")]
    ReadBackMismatch,
    #[error("contract document drifted from the typed boundary")]
    ContractDrift,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GCP Monitoring transport returned {kind:?}")]
pub struct GcpMonitoringTransportError {
    pub kind: TransportErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: crate::Digest,
}

impl GcpMonitoringTransportError {
    pub fn new(
        kind: TransportErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            TransportErrorKind::RateLimited
                | TransportErrorKind::ServerFailure
                | TransportErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: matches!(kind, TransportErrorKind::BlockedEnv),
            diagnostic_digest: crate::Digest::from_text(diagnostic),
        }
    }

    pub fn unauthorized() -> Self {
        Self::new(
            TransportErrorKind::Unauthenticated,
            Some(401),
            "unauthorized",
        )
    }

    pub fn forbidden() -> Self {
        Self::new(TransportErrorKind::PermissionDenied, Some(403), "forbidden")
    }

    pub fn not_found() -> Self {
        Self::new(TransportErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn conflict() -> Self {
        Self::new(TransportErrorKind::Conflict, Some(409), "conflict")
    }

    pub fn rate_limited() -> Self {
        Self::new(TransportErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn bad_request() -> Self {
        Self::new(TransportErrorKind::BadRequest, Some(400), "bad-request")
    }

    pub fn server_failure() -> Self {
        Self::new(
            TransportErrorKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }

    pub fn timeout() -> Self {
        Self::new(TransportErrorKind::Timeout, None, "timeout")
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    Unknown,
}
