use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsCloudFrontDistributionError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCloudFrontTransportError {
    #[error("BLOCKED_ENV: CloudFront native transport is disabled")]
    BlockedEnv,
    #[error("CloudFront request was invalid")]
    BadRequest,
    #[error("CloudFront credentials were not authorized")]
    Unauthorized,
    #[error("CloudFront access was forbidden")]
    Forbidden,
    #[error("CloudFront distribution was not found")]
    NotFound,
    #[error("CloudFront request conflicted with provider state")]
    Conflict,
    #[error("CloudFront request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("CloudFront provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("CloudFront transport timed out")]
    Timeout,
    #[error("CloudFront access was lost while reading evidence")]
    AccessLost,
    #[error("CloudFront returned a partial response")]
    Partial,
    #[error("CloudFront provider returned unknown state")]
    Unknown,
    #[error("CloudFront response was invalid")]
    InvalidResponse,
    #[error("CloudFront evidence was tampered with")]
    Tampered,
    #[error("CloudFront ETag or configuration revision drifted")]
    ConfigDrift,
    #[error("CloudFront pagination loop detected")]
    PaginationLoop,
}

impl AwsCloudFrontTransportError {
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
            | Self::ConfigDrift
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
pub enum AwsCloudFrontDistributionError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid CloudFront identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("CloudFront scope is invalid")]
    InvalidScope,
    #[error("CloudFront permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("CloudFront consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("CloudFront registration is invalid")]
    InvalidRegistration,
    #[error("CloudFront request is invalid")]
    InvalidRequest,
    #[error("CloudFront provider response is invalid")]
    InvalidResponse,
    #[error("CloudFront scope does not match the request or response")]
    ScopeMismatch,
    #[error("CloudFront distribution is outside the explicit allowlist")]
    DistributionNotAllowed,
    #[error("CloudFront distribution identity drifted")]
    DistributionDrift,
    #[error("CloudFront cursor does not match the bound request")]
    CursorMismatch,
    #[error("CloudFront pagination loop detected")]
    PaginationLoop,
    #[error("CloudFront ETag or configuration revision drifted")]
    ConfigDrift,
    #[error("CloudFront provider definition drifted")]
    ProviderDrift,
    #[error("CloudFront contract definition drifted")]
    ContractDrift,
    #[error("CloudFront registration is revoked")]
    RegistrationRevoked,
    #[error("CloudFront registration is reversed")]
    RegistrationReversed,
    #[error("CloudFront registration is not active")]
    RegistrationInactive,
    #[error("CloudFront consent is expired")]
    ConsentExpired,
    #[error("CloudFront consent is revoked")]
    ConsentRevoked,
    #[error("CloudFront SecretReference is revoked")]
    SecretRevoked,
    #[error("CloudFront evidence was tampered with")]
    TamperedEvidence,
    #[error("CloudFront evidence is partial or truncated")]
    PartialEvidence,
    #[error("CloudFront provider state is unknown")]
    ProviderUnknown,
    #[error("CloudFront evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("CloudFront recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("CloudFront transport failed: {0}")]
    Transport(#[from] AwsCloudFrontTransportError),
}
