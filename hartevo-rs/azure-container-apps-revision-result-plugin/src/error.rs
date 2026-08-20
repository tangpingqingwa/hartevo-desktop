use thiserror::Error;

pub type Result<T> = std::result::Result<T, AzureContainerAppsRevisionResultError>;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureContainerAppsRevisionResultError {
    #[error("invalid identifier: {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid text: {field}")]
    InvalidText { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("contract metadata drifted")]
    ContractDrift,
    #[error("service descriptor drifted")]
    ServiceDrift,
    #[error("provider definition drifted")]
    ProviderDrift,
    #[error("provider API revision drifted")]
    ApiDrift,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration has been revoked")]
    RegistrationRevoked,
    #[error("registration has been reversed")]
    RegistrationReversed,
    #[error("registration cannot be restored")]
    RegistrationNotRestorable,
    #[error("scope does not match the bound registration")]
    ScopeMismatch,
    #[error("permission digest does not match the bound registration")]
    PermissionMismatch,
    #[error("stale request or evidence")]
    StaleEvidence,
    #[error("tampered evidence")]
    TamperedEvidence,
    #[error("replay conflicts with the existing local recording")]
    ReplayConflict,
    #[error("pagination cursor does not match the bound scope")]
    CursorMismatch,
    #[error("pagination cursor loop detected")]
    PaginationLoop,
    #[error("bounded page or response was truncated")]
    TruncatedEvidence,
    #[error("partial evidence")]
    PartialEvidence,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("provider returned a revision replacement or conflict")]
    RevisionConflict,
    #[error("provider returned contradictory readiness metadata")]
    ReadinessConflict,
    #[error("invalid response")]
    InvalidResponse,
    #[error("request bound to an unsupported permission")]
    ForbiddenPermission,
    #[error("response exceeded the bounded byte limit")]
    ResponseTooLarge,
    #[error("invalid registration transition")]
    InvalidTransition,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureContainerAppsTransportError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("access lost")]
    AccessLost,
    #[error("not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("request timed out")]
    Timeout,
    #[error("bad request")]
    BadRequest,
    #[error("conflict")]
    Conflict,
    #[error("server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("invalid provider response")]
    InvalidResponse,
    #[error("provider response was truncated")]
    Truncated,
    #[error("BLOCKED_ENV")]
    BlockedEnv,
}

impl AzureContainerAppsTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::BadRequest => Some(400),
            Self::Conflict => Some(409),
            Self::ServerFailure { status_code } => *status_code,
            Self::AccessLost
            | Self::Timeout
            | Self::InvalidResponse
            | Self::Truncated
            | Self::BlockedEnv => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}
