use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsAthenaQueryResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAthenaTransportError {
    #[error("BLOCKED_ENV: AWS Athena native transport is disabled")]
    BlockedEnv,
    #[error("AWS Athena request was invalid")]
    BadRequest,
    #[error("AWS Athena credentials were not authorized")]
    Unauthorized,
    #[error("AWS Athena access was forbidden")]
    Forbidden,
    #[error("AWS Athena query execution was not found")]
    NotFound,
    #[error("AWS Athena provider state conflicted with the request")]
    Conflict,
    #[error("AWS Athena request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Athena provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Athena transport timed out")]
    Timeout,
    #[error("AWS Athena access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Athena evidence was partial or truncated")]
    Partial,
    #[error("AWS Athena query execution or result output expired")]
    Expired,
    #[error("AWS Athena provider returned an unknown state")]
    Unknown,
    #[error("AWS Athena response was invalid")]
    InvalidResponse,
    #[error("AWS Athena evidence was tampered with")]
    Tampered,
    #[error("AWS Athena opaque pagination loop detected")]
    PaginationLoop,
}

impl AwsAthenaTransportError {
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
            | Self::Expired
            | Self::Unknown
            | Self::InvalidResponse
            | Self::Tampered
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
pub enum AwsAthenaQueryResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Athena identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Athena query-result scope is invalid")]
    InvalidScope,
    #[error("AWS Athena permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Athena consent scope is invalid")]
    InvalidConsent,
    #[error("opaque AWS Athena SigV4 SecretReference is invalid")]
    InvalidSecretReference,
    #[error("AWS Athena registration is invalid")]
    InvalidRegistration,
    #[error("AWS Athena request is invalid")]
    InvalidRequest,
    #[error("AWS Athena provider response is invalid")]
    InvalidResponse,
    #[error("AWS Athena scope does not match the request or response")]
    ScopeMismatch,
    #[error("AWS Athena query digest drifted")]
    QueryDrift,
    #[error("AWS Athena query execution identity or status drifted")]
    ExecutionDrift,
    #[error("AWS Athena opaque page token does not match its bound request")]
    PageTokenMismatch,
    #[error("AWS Athena opaque pagination loop detected")]
    PaginationLoop,
    #[error("AWS Athena provider definition drifted")]
    ProviderDrift,
    #[error("AWS Athena contract definition drifted")]
    ContractDrift,
    #[error("AWS Athena registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Athena registration is reversed")]
    RegistrationReversed,
    #[error("AWS Athena registration is not active")]
    RegistrationInactive,
    #[error("AWS Athena consent is expired")]
    ConsentExpired,
    #[error("AWS Athena consent is revoked")]
    ConsentRevoked,
    #[error("AWS Athena SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Athena Mission revision is stale")]
    MissionStale,
    #[error("AWS Athena evidence was tampered with")]
    EvidenceTampered,
    #[error("AWS Athena evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Athena provider state is unknown")]
    ProviderUnknown,
    #[error("AWS Athena evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("AWS Athena recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Athena transport failed: {0}")]
    Transport(#[from] AwsAthenaTransportError),
}
