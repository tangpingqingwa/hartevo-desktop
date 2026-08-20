use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsSnsTopicError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSnsTransportError {
    #[error("BLOCKED_ENV: AWS SNS native transport is disabled")]
    BlockedEnv,
    #[error("AWS SNS request was invalid")]
    BadRequest,
    #[error("AWS SNS credentials were not authorized")]
    Unauthorized,
    #[error("AWS SNS access was forbidden")]
    Forbidden,
    #[error("AWS SNS topic or subscription was not found")]
    NotFound,
    #[error("AWS SNS request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS SNS provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS SNS transport timed out")]
    Timeout,
    #[error("AWS SNS access was lost while reading evidence")]
    AccessLost,
    #[error("AWS SNS returned a partial transport response")]
    Partial,
    #[error("AWS SNS response was invalid")]
    InvalidResponse,
}

impl AwsSnsTransportError {
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

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "throttled",
            Self::ServerError { .. } => "provider_unknown",
            Self::Timeout => "timeout",
            Self::AccessLost => "access_loss",
            Self::Partial => "partial",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSnsTopicError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS SNS identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS SNS topic scope is invalid")]
    InvalidScope,
    #[error("AWS SNS permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS SNS consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS SNS registration is invalid")]
    InvalidRegistration,
    #[error("AWS SNS read request is invalid")]
    InvalidRequest,
    #[error("AWS SNS read request does not match its scope")]
    ScopeMismatch,
    #[error("AWS SNS topic is outside the explicit topic allowlist")]
    TopicAllowlistViolation,
    #[error("AWS SNS subscription is outside the explicit subscription allowlist")]
    SubscriptionAllowlistViolation,
    #[error("AWS SNS topic was replaced or drifted")]
    TopicReplaced,
    #[error("AWS SNS subscription was replaced or drifted")]
    SubscriptionReplaced,
    #[error("AWS SNS pagination cursor loop detected")]
    PaginationLoop,
    #[error("AWS SNS evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS SNS evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS SNS recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS SNS provider definition drifted")]
    ProviderDrift,
    #[error("AWS SNS contract definition drifted")]
    ContractDrift,
    #[error("AWS SNS registration is revoked")]
    RegistrationRevoked,
    #[error("AWS SNS registration is reversed")]
    RegistrationReversed,
    #[error("AWS SNS registration is not active")]
    RegistrationInactive,
    #[error("AWS SNS consent is expired")]
    ConsentExpired,
    #[error("AWS SNS consent is revoked")]
    ConsentRevoked,
    #[error("AWS SNS transport failed: {0}")]
    Transport(#[from] AwsSnsTransportError),
}
