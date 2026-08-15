use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsLicenseManagerError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsLicenseManagerTransportError {
    #[error("BLOCKED_ENV: AWS License Manager native transport is disabled")]
    BlockedEnv,
    #[error("AWS License Manager request was invalid")]
    BadRequest,
    #[error("AWS License Manager credentials were not authorized")]
    Unauthorized,
    #[error("AWS License Manager access was forbidden")]
    Forbidden,
    #[error("AWS License Manager configuration or usage was not found")]
    NotFound,
    #[error("AWS License Manager request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS License Manager provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS License Manager transport timed out")]
    Timeout,
    #[error("AWS License Manager access was lost while reading evidence")]
    AccessLost,
    #[error("AWS License Manager returned a partial response")]
    Partial,
    #[error("AWS License Manager response was malformed")]
    InvalidResponse,
    #[error("AWS License Manager recording queue was exhausted")]
    QueueExhausted,
}

impl AwsLicenseManagerTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse
            | Self::QueueExhausted => None,
        }
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "throttled",
            Self::ServerError { .. } => "server_error",
            Self::Timeout => "timeout",
            Self::AccessLost => "access_loss",
            Self::Partial => "partial",
            Self::InvalidResponse => "invalid_response",
            Self::QueueExhausted => "queue_exhausted",
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost | Self::BlockedEnv
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsLicenseManagerError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not an allowed AWS License Manager identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS License Manager scope is invalid")]
    InvalidScope,
    #[error("AWS License Manager permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS License Manager registration is invalid")]
    InvalidRegistration,
    #[error("AWS License Manager request is invalid")]
    InvalidRequest,
    #[error("AWS License Manager request does not match its scope")]
    ScopeMismatch,
    #[error("AWS License Manager filter does not match the bound scope")]
    FilterMismatch,
    #[error("AWS License Manager cursor does not match the bound request")]
    CursorMismatch,
    #[error("AWS License Manager provider definition drifted")]
    ProviderDrift,
    #[error("AWS License Manager contract definition drifted")]
    ContractDrift,
    #[error("AWS License Manager permission snapshot drifted")]
    PermissionDrift,
    #[error("AWS License Manager license configuration drifted")]
    ConfigurationDrift,
    #[error("AWS License Manager managed resource drifted")]
    ResourceDrift,
    #[error("AWS License Manager consumption window drifted")]
    UsageWindowDrift,
    #[error("AWS License Manager pagination repeated a cursor")]
    PageLoop,
    #[error("AWS License Manager pagination or response was partial")]
    PartialEvidence,
    #[error("AWS License Manager quota was exceeded")]
    QuotaExceeded,
    #[error("AWS License Manager evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS License Manager recording key conflicts with an existing digest")]
    ReplayConflict,
    #[error("AWS License Manager registration is revoked")]
    RegistrationRevoked,
    #[error("AWS License Manager registration is reversed")]
    RegistrationReversed,
    #[error("AWS License Manager registration is not active")]
    RegistrationInactive,
    #[error("AWS License Manager evidence is stale")]
    StaleEvidence,
    #[error("AWS License Manager provider transport failed: {0}")]
    Transport(#[from] AwsLicenseManagerTransportError),
}
