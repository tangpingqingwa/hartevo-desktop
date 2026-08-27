use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsKinesisStreamResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsKinesisTransportError {
    #[error("BLOCKED_ENV: AWS Kinesis native transport is disabled")]
    BlockedEnv,
    #[error("AWS Kinesis request was invalid")]
    BadRequest,
    #[error("AWS Kinesis credentials were not authorized")]
    Unauthorized,
    #[error("AWS Kinesis access was forbidden")]
    Forbidden,
    #[error("AWS Kinesis stream or consumer was not found")]
    NotFound,
    #[error("AWS Kinesis request conflicted with provider state")]
    Conflict,
    #[error("AWS Kinesis request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Kinesis provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Kinesis transport timed out")]
    Timeout,
    #[error("AWS Kinesis access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Kinesis returned a partial response")]
    Partial,
    #[error("AWS Kinesis pagination token expired")]
    TokenExpired,
    #[error("AWS Kinesis pagination loop detected")]
    PaginationLoop,
    #[error("AWS Kinesis response was invalid")]
    InvalidResponse,
    #[error("AWS Kinesis evidence was tampered with")]
    Tampered,
}

impl AwsKinesisTransportError {
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
            | Self::TokenExpired
            | Self::PaginationLoop
            | Self::InvalidResponse
            | Self::Tampered => None,
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
pub enum AwsKinesisStreamResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Kinesis identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Kinesis stream scope is invalid")]
    InvalidScope,
    #[error("AWS Kinesis shard filter is invalid")]
    InvalidFilter,
    #[error("AWS Kinesis permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Kinesis consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 SecretReference is invalid")]
    InvalidSecretReference,
    #[error("AWS Kinesis registration is invalid")]
    InvalidRegistration,
    #[error("AWS Kinesis request is invalid")]
    InvalidRequest,
    #[error("AWS Kinesis request or response does not match its exact scope")]
    ScopeMismatch,
    #[error("AWS Kinesis stream identity or version drifted")]
    StreamDrift,
    #[error("AWS Kinesis shard filter drifted")]
    ShardFilterMismatch,
    #[error("AWS Kinesis exact consumer scope drifted")]
    ConsumerDrift,
    #[error("AWS Kinesis cursor does not match the bound scope or filter")]
    CursorMismatch,
    #[error("AWS Kinesis opaque pagination token expired")]
    CursorExpired,
    #[error("AWS Kinesis pagination loop detected")]
    PaginationLoop,
    #[error("AWS Kinesis pagination exceeded its bound")]
    PaginationLimit,
    #[error("AWS Kinesis response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("AWS Kinesis provider definition drifted")]
    ProviderDrift,
    #[error("AWS Kinesis contract definition drifted")]
    ContractDrift,
    #[error("AWS Kinesis registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Kinesis registration is reversed")]
    RegistrationReversed,
    #[error("AWS Kinesis registration is not active")]
    RegistrationInactive,
    #[error("AWS Kinesis consent is expired")]
    ConsentExpired,
    #[error("AWS Kinesis consent is revoked")]
    ConsentRevoked,
    #[error("AWS Kinesis SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Kinesis evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Kinesis evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Kinesis provider state is unknown")]
    ProviderUnknown,
    #[error("AWS Kinesis recording key conflicts with an existing digest")]
    ReplayConflict,
    #[error("AWS Kinesis Mission revision is stale")]
    StaleMissionRevision,
    #[error("AWS Kinesis transport failed: {0}")]
    Transport(#[from] AwsKinesisTransportError),
}

pub type AwsKinesisProviderError = AwsKinesisTransportError;
