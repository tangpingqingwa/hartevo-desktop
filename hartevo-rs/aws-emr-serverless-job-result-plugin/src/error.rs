use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsEmrServerlessJobResultError>;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AwsEmrServerlessTransportError {
    #[error("BLOCKED_ENV: native EMR Serverless transport is disabled")]
    BlockedEnv,
    #[error("EMR Serverless request was invalid")]
    BadRequest,
    #[error("EMR Serverless credentials were not authorized")]
    Unauthorized,
    #[error("EMR Serverless access was forbidden")]
    Forbidden,
    #[error("EMR Serverless application or job run was not found")]
    NotFound,
    #[error("EMR Serverless provider rate limited the read")]
    RateLimited,
    #[error("EMR Serverless provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("EMR Serverless transport timed out")]
    Timeout,
    #[error("EMR Serverless returned a partial transport response")]
    Partial,
    #[error("EMR Serverless response was invalid")]
    InvalidResponse,
}

impl AwsEmrServerlessTransportError {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited => Some(429),
            Self::ServerError { status } => Some(status),
            Self::BlockedEnv | Self::Timeout | Self::Partial | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden)
    }

    pub const fn kind(self) -> TransportErrorKind {
        match self {
            Self::BlockedEnv => TransportErrorKind::BlockedEnv,
            Self::BadRequest => TransportErrorKind::BadRequest,
            Self::Unauthorized => TransportErrorKind::Unauthorized,
            Self::Forbidden => TransportErrorKind::Forbidden,
            Self::NotFound => TransportErrorKind::NotFound,
            Self::RateLimited => TransportErrorKind::RateLimited,
            Self::ServerError { .. } => TransportErrorKind::ServerError,
            Self::Timeout => TransportErrorKind::Timeout,
            Self::Partial => TransportErrorKind::Partial,
            Self::InvalidResponse => TransportErrorKind::InvalidResponse,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransportErrorKind {
    BlockedEnv,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerError,
    Timeout,
    Partial,
    InvalidResponse,
}

impl TransportErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
            Self::Timeout => "timeout",
            Self::Partial => "partial",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEmrServerlessJobResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid EMR Serverless identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("EMR Serverless scope is invalid")]
    InvalidScope,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("EMR Serverless request is invalid")]
    InvalidRequest,
    #[error("EMR Serverless request does not match its scope")]
    ScopeMismatch,
    #[error("EMR Serverless response does not match its scope")]
    ResponseScopeMismatch,
    #[error("EMR Serverless response credential revision does not match its registration")]
    CredentialMismatch,
    #[error("EMR Serverless response exceeded the Layer-1 safety ceiling")]
    ResponseTooLarge,
    #[error("EMR Serverless response shape was invalid")]
    InvalidResponseShape,
    #[error("EMR Serverless response contained too many summaries")]
    SummaryCap,
    #[error("EMR Serverless pagination repeated an opaque next token")]
    PageLoop,
    #[error("EMR Serverless pagination exceeded the Layer-1 page cap")]
    PageCap,
    #[error("exact EMR Serverless job run was absent from the bounded listing")]
    ExactJobRunMissing,
    #[error("EMR Serverless lifecycle regressed")]
    LifecycleRegression,
    #[error("EMR Serverless evidence was tampered with")]
    TamperedEvidence,
    #[error("EMR Serverless provider definition drifted")]
    ProviderDrift,
    #[error("EMR Serverless contract definition drifted")]
    ContractDrift,
    #[error("EMR Serverless registration is invalid")]
    InvalidRegistration,
    #[error("EMR Serverless registration is revoked")]
    RegistrationRevoked,
    #[error("EMR Serverless registration is reversed")]
    RegistrationReversed,
    #[error("EMR Serverless registration is not active")]
    RegistrationInactive,
    #[error("Mission scope is stale")]
    StaleMission,
    #[error("Mission scope is expired")]
    ExpiredMission,
    #[error("EMR Serverless transport failed: {0}")]
    Transport(#[from] AwsEmrServerlessTransportError),
}
