use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsSqsQueueError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSqsQueueTransportError {
    #[error("BLOCKED_ENV: native AWS SQS transport is disabled")]
    BlockedEnv,
    #[error("AWS SQS request was invalid")]
    BadRequest,
    #[error("AWS SQS credentials were not authorized")]
    Unauthorized,
    #[error("AWS SQS access was forbidden")]
    Forbidden,
    #[error("AWS SQS queue was not found")]
    NotFound,
    #[error("AWS SQS request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS SQS provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS SQS transport timed out")]
    Timeout,
    #[error("AWS SQS access was lost while reading posture")]
    AccessLost,
    #[error("AWS SQS returned a partial transport response")]
    Partial,
    #[error("AWS SQS response was invalid")]
    InvalidResponse,
}

impl AwsSqsQueueTransportError {
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
            | Self::InvalidResponse => None,
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            Self::BlockedEnv
            | Self::BadRequest
            | Self::Unauthorized
            | Self::Forbidden
            | Self::NotFound
            | Self::ServerError { .. }
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse => None,
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
pub enum AwsSqsQueueError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS SQS identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS SQS scope is invalid")]
    InvalidScope,
    #[error("AWS SQS permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS SQS registration is invalid")]
    InvalidRegistration,
    #[error("AWS SQS request is invalid")]
    InvalidRequest,
    #[error("AWS SQS queue identity does not match the bound scope")]
    QueueMismatch,
    #[error("AWS SQS scope or permission fence does not match")]
    ScopeMismatch,
    #[error("AWS SQS cursor does not match the bound filter")]
    CursorMismatch,
    #[error("AWS SQS provider definition drifted")]
    ProviderDrift,
    #[error("AWS SQS contract definition drifted")]
    ContractDrift,
    #[error("AWS SQS registration is revoked")]
    RegistrationRevoked,
    #[error("AWS SQS registration is reversed")]
    RegistrationReversed,
    #[error("AWS SQS registration is not active")]
    RegistrationInactive,
    #[error("AWS SQS evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS SQS evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS SQS evidence is stale")]
    StaleObservation,
    #[error("AWS SQS pagination cursor looped")]
    PaginationLoop,
    #[error("AWS SQS queue was replaced")]
    QueueReplaced,
    #[error("AWS SQS queue attributes drifted")]
    AttributeDrift,
    #[error("AWS SQS recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS SQS transport failed: {0}")]
    Transport(#[from] AwsSqsQueueTransportError),
}
