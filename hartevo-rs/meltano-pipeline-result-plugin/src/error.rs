use thiserror::Error;

pub type Result<T> = std::result::Result<T, MeltanoPipelineResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MeltanoTransportError {
    #[error("BLOCKED_ENV: Meltano native transport is disabled")]
    BlockedEnv,
    #[error("Meltano request was invalid")]
    BadRequest,
    #[error("Meltano credentials were not authorized")]
    Unauthorized,
    #[error("Meltano access was forbidden")]
    Forbidden,
    #[error("Meltano resource was not found")]
    NotFound,
    #[error("Meltano request conflicted with provider state")]
    Conflict,
    #[error("Meltano request was rate limited")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Meltano provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Meltano transport timed out")]
    Timeout,
    #[error("Meltano access was lost while reading evidence")]
    AccessLost,
    #[error("Meltano returned a partial response")]
    Partial,
    #[error("Meltano evidence has expired")]
    Expired,
    #[error("Meltano cursor or provider snapshot is stale")]
    Stale,
    #[error("Meltano provider returned an invalid response")]
    InvalidResponse,
}

impl MeltanoTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict | Self::Stale => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::Expired => Some(410),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MeltanoPipelineResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Meltano identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Meltano scope is invalid")]
    InvalidScope,
    #[error("Meltano permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("opaque Meltano API-token SecretReference is invalid")]
    InvalidSecretReference,
    #[error("opaque Meltano cursor is invalid")]
    InvalidCursor,
    #[error("Meltano registration is invalid")]
    InvalidRegistration,
    #[error("Meltano read request is invalid")]
    InvalidRequest,
    #[error("Meltano provider response is invalid")]
    InvalidResponse,
    #[error("Meltano request does not match its bound scope")]
    ScopeMismatch,
    #[error("Meltano request revision or idempotency fence does not match")]
    RevisionMismatch,
    #[error("Meltano provider definition drifted")]
    ProviderDrift,
    #[error("Meltano contract definition drifted")]
    ContractDrift,
    #[error("Meltano registration is revoked")]
    RegistrationRevoked,
    #[error("Meltano registration is reversed")]
    RegistrationReversed,
    #[error("Meltano registration is not active")]
    RegistrationInactive,
    #[error("Meltano evidence was tampered with")]
    TamperedEvidence,
    #[error("Meltano evidence is partial or truncated")]
    PartialEvidence,
    #[error("Meltano idempotency key conflicts with an existing recording")]
    IdempotencyConflict,
    #[error("Meltano recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Meltano registration revision overflowed")]
    RevisionOverflow,
    #[error("Meltano metadata is outside the Layer-1 bound")]
    BoundsExceeded,
    #[error("Meltano transport failed: {0}")]
    Transport(#[from] MeltanoTransportError),
}
