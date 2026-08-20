use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum OpenFgaAuthorizationResultError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("OpenFGA SecretReference is invalid or revoked")]
    InvalidSecretReference,
    #[error("consent scope is invalid or expired")]
    InvalidConsent,
    #[error("consent has expired")]
    ConsentExpired,
    #[error("scope or digest fence does not match")]
    ScopeMismatch,
    #[error("revision fence does not match")]
    RevisionMismatch,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("request is invalid or exceeds the Layer-1 bound")]
    InvalidRequest,
    #[error("cursor is invalid or bound to a different query")]
    CursorMismatch,
    #[error("provider response is malformed or outside the Layer-1 bound")]
    InvalidProviderResponse,
    #[error("provider response is stale")]
    StaleEvidence,
    #[error("provider response is partial")]
    PartialEvidence,
    #[error("evidence was tampered with")]
    TamperedEvidence,
    #[error("recording idempotency key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("contract JSON or digest closure drifted")]
    ContractDrift,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum OpenFgaTransportError {
    #[error("{0} environment is blocked for Layer-1 OpenFGA transport")]
    BlockedEnvironment(&'static str),
    #[error("recording transport has no response for the requested operation")]
    NoRecording,
    #[error("OpenFGA provider rate limit exceeded")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("OpenFGA provider denied authentication")]
    Unauthorized,
    #[error("OpenFGA provider denied the requested operation")]
    Forbidden,
    #[error("OpenFGA provider could not find the requested resource")]
    NotFound,
    #[error("OpenFGA provider reported a revision conflict")]
    Conflict,
    #[error("OpenFGA provider request timed out")]
    TimedOut,
    #[error("OpenFGA provider returned partial evidence")]
    Partial,
    #[error("OpenFGA provider returned stale evidence")]
    Stale,
    #[error("OpenFGA provider returned malformed evidence")]
    Malformed,
    #[error("OpenFGA provider returned an unknown failure: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, OpenFgaAuthorizationResultError>;

impl OpenFgaTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::RateLimited { .. } => Some(429),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict | Self::Stale => Some(409),
            Self::TimedOut => Some(408),
            Self::BlockedEnvironment(_)
            | Self::NoRecording
            | Self::Partial
            | Self::Malformed
            | Self::Unknown(_) => None,
        }
    }

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u32> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnvironment(_) => "blocked_env",
            Self::NoRecording => "recording_unavailable",
            Self::RateLimited { .. } => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TimedOut => "timed_out",
            Self::Partial => "partial",
            Self::Stale => "stale",
            Self::Malformed => "malformed",
            Self::Unknown(_) => "provider_unknown",
        }
    }
}
