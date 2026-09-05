use thiserror::Error;

pub type Result<T> = std::result::Result<T, WorkfrontReviewResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkfrontTransportError {
    #[error("BLOCKED_ENV: Workfront native transport is disabled")]
    BlockedEnv,
    #[error("Workfront request was invalid")]
    BadRequest,
    #[error("Workfront credentials were not authorized")]
    Unauthorized,
    #[error("Workfront access was forbidden")]
    Forbidden,
    #[error("Workfront object was not found")]
    NotFound,
    #[error("Workfront request conflicted with provider state")]
    Conflict,
    #[error("Workfront request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Workfront provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Workfront transport timed out")]
    Timeout,
    #[error("Workfront access was lost while reading evidence")]
    AccessLost,
    #[error("Workfront provider returned a partial response")]
    Partial,
    #[error("Workfront provider returned unknown state")]
    Unknown,
    #[error("Workfront provider response was invalid")]
    InvalidResponse,
    #[error("Workfront response was tampered")]
    Tampered,
    #[error("Workfront state revision was stale")]
    StaleState,
    #[error("Workfront pagination loop was detected")]
    PaginationLoop,
}

impl WorkfrontTransportError {
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
            | Self::Unknown
            | Self::InvalidResponse
            | Self::Tampered
            | Self::StaleState
            | Self::PaginationLoop => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkfrontReviewResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Workfront revision must be positive")]
    InvalidRevision,
    #[error("Workfront time window is invalid")]
    InvalidTimeWindow,
    #[error("Workfront scope is invalid")]
    InvalidScope,
    #[error("Workfront permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Workfront consent scope is invalid")]
    InvalidConsent,
    #[error("opaque OAuth/API SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Workfront registration is invalid")]
    InvalidRegistration,
    #[error("Workfront request is invalid")]
    InvalidRequest,
    #[error("Workfront provider response is invalid")]
    InvalidResponse,
    #[error("Workfront scope does not match the request or response")]
    ScopeMismatch,
    #[error("Workfront provider object is outside the explicit scope")]
    ObjectNotAllowed,
    #[error("Workfront cursor does not match the bound request")]
    CursorMismatch,
    #[error("Workfront pagination loop was detected")]
    PaginationLoop,
    #[error("Workfront provider definition drifted")]
    ProviderDrift,
    #[error("Workfront contract definition drifted")]
    ContractDrift,
    #[error("Workfront registration is revoked")]
    RegistrationRevoked,
    #[error("Workfront registration is reversed")]
    RegistrationReversed,
    #[error("Workfront registration is not active")]
    RegistrationInactive,
    #[error("Workfront consent is expired")]
    ConsentExpired,
    #[error("Workfront SecretReference is revoked")]
    SecretRevoked,
    #[error("Workfront evidence was tampered with")]
    TamperedEvidence,
    #[error("Workfront evidence is partial or truncated")]
    PartialEvidence,
    #[error("Workfront provider state is unknown")]
    ProviderUnknown,
    #[error("Workfront evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("Workfront recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Workfront provider is rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Workfront access was lost")]
    AccessLost,
    #[error("Workfront state revision is stale")]
    StaleState,
    #[error("Workfront transport failed: {0}")]
    Transport(#[from] WorkfrontTransportError),
}
