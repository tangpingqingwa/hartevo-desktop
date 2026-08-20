use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsEventBridgePipeError>;

/// Classification retained in Layer-1 evidence. Provider messages are never
/// retained because they may contain arbitrary account or configuration data.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClassification {
    None,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    BlockedEnv,
    AccessLoss,
    InvalidResponse,
    PaginationLoop,
    Truncated,
    StateDrift,
    SourceTargetMismatch,
    ProviderReported,
    RegistrationRevoked,
}

impl ErrorClassification {
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::None)
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLoss
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEventBridgePipeTransportError {
    #[error("BLOCKED_ENV: EventBridge Pipes native transport is disabled")]
    BlockedEnv,
    #[error("EventBridge Pipes request was invalid")]
    BadRequest,
    #[error("EventBridge Pipes credentials were not authorized")]
    Unauthorized,
    #[error("EventBridge Pipes access was forbidden")]
    Forbidden,
    #[error("EventBridge Pipe was not found")]
    NotFound,
    #[error("EventBridge Pipes request conflicted with provider state")]
    Conflict,
    #[error("EventBridge Pipes request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("EventBridge Pipes provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("EventBridge Pipes transport timed out")]
    Timeout,
    #[error("EventBridge Pipes access was lost while reading evidence")]
    AccessLost,
    #[error("EventBridge Pipes returned a partial transport response")]
    Partial,
    #[error("EventBridge Pipes response was invalid")]
    InvalidResponse,
}

impl AwsEventBridgePipeTransportError {
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

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn classification(&self) -> ErrorClassification {
        match self {
            Self::BlockedEnv => ErrorClassification::BlockedEnv,
            Self::BadRequest => ErrorClassification::BadRequest,
            Self::Unauthorized => ErrorClassification::Unauthorized,
            Self::Forbidden => ErrorClassification::Forbidden,
            Self::NotFound => ErrorClassification::NotFound,
            Self::Conflict => ErrorClassification::Conflict,
            Self::RateLimited { .. } => ErrorClassification::RateLimited,
            Self::ServerError { .. } => ErrorClassification::ServerError,
            Self::Timeout => ErrorClassification::Timeout,
            Self::AccessLost => ErrorClassification::AccessLoss,
            Self::Partial | Self::InvalidResponse => ErrorClassification::InvalidResponse,
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
pub enum AwsEventBridgePipeError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid EventBridge Pipes identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("EventBridge Pipes scope is invalid")]
    InvalidScope,
    #[error("EventBridge Pipes permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("EventBridge Pipes registration is invalid")]
    InvalidRegistration,
    #[error("EventBridge Pipes request is invalid")]
    InvalidRequest,
    #[error("EventBridge Pipes request does not match its scope")]
    ScopeMismatch,
    #[error("EventBridge Pipes filter does not match its scope")]
    FilterMismatch,
    #[error("EventBridge Pipes cursor does not match its request")]
    CursorMismatch,
    #[error("EventBridge Pipes provider definition drifted")]
    ProviderDrift,
    #[error("EventBridge Pipes contract definition drifted")]
    ContractDrift,
    #[error("EventBridge Pipes registration is revoked")]
    RegistrationRevoked,
    #[error("EventBridge Pipes registration is reversed")]
    RegistrationReversed,
    #[error("EventBridge Pipes registration is not active")]
    RegistrationInactive,
    #[error("EventBridge Pipe state drifted between ListPipes and DescribePipe")]
    StateDrift,
    #[error("EventBridge Pipe source or target does not match the bound scope")]
    SourceTargetMismatch,
    #[error("EventBridge Pipe was not found in a complete bounded listing")]
    PipeNotFound,
    #[error("EventBridge Pipes evidence was tampered with")]
    TamperedEvidence,
    #[error("EventBridge Pipes evidence is partial or truncated")]
    PartialEvidence,
    #[error("EventBridge Pipes recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("EventBridge Pipes transport failed: {0}")]
    Transport(#[from] AwsEventBridgePipeTransportError),
}
