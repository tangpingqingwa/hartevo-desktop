use thiserror::Error;

pub type Result<T> = std::result::Result<T, DaggerPipelineResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaggerTransportError {
    #[error("BLOCKED_ENV: Dagger native transport is disabled")]
    BlockedEnv,
    #[error("Dagger request was invalid")]
    BadRequest,
    #[error("Dagger credentials were not authorized")]
    Unauthorized,
    #[error("Dagger access was forbidden")]
    Forbidden,
    #[error("Dagger module, pipeline, execution, or artifact was not found")]
    NotFound,
    #[error("Dagger request conflicted with provider state")]
    Conflict,
    #[error("Dagger request was rate limited")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Dagger provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Dagger transport timed out")]
    Timeout,
    #[error("Dagger access was lost while reading evidence")]
    AccessLost,
    #[error("Dagger returned a partial response")]
    Partial,
    #[error("Dagger response was invalid")]
    InvalidResponse,
}

impl DaggerTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
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
pub enum DaggerPipelineResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Dagger identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Dagger pipeline scope is invalid")]
    InvalidScope,
    #[error("Dagger permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Dagger consent scope is invalid")]
    InvalidConsent,
    #[error("opaque token/OCI SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Dagger registration is invalid")]
    InvalidRegistration,
    #[error("Dagger read request is invalid")]
    InvalidRequest,
    #[error("Dagger request does not match its bound scope")]
    ScopeMismatch,
    #[error("Dagger request revision or idempotency fence does not match")]
    RevisionMismatch,
    #[error("Dagger provider definition drifted")]
    ProviderDrift,
    #[error("Dagger contract definition drifted")]
    ContractDrift,
    #[error("Dagger registration is revoked")]
    RegistrationRevoked,
    #[error("Dagger registration is reversed")]
    RegistrationReversed,
    #[error("Dagger registration is not active")]
    RegistrationInactive,
    #[error("Dagger consent is expired")]
    ConsentExpired,
    #[error("Dagger consent is revoked")]
    ConsentRevoked,
    #[error("Dagger evidence was tampered with")]
    TamperedEvidence,
    #[error("Dagger evidence is partial or truncated")]
    PartialEvidence,
    #[error("Dagger idempotency key conflicts with an existing recording")]
    IdempotencyConflict,
    #[error("Dagger recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Dagger registration revision overflowed")]
    RevisionOverflow,
    #[error("Dagger metadata is outside the Layer-1 bound")]
    BoundsExceeded,
    #[error("Dagger transport failed: {0}")]
    Transport(#[from] DaggerTransportError),
}
