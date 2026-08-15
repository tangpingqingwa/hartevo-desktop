use thiserror::Error;

pub type Result<T> = std::result::Result<T, HarnessDeliveryResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HarnessTransportError {
    #[error("BLOCKED_ENV: Harness native transport is disabled")]
    BlockedEnv,
    #[error("Harness request was invalid")]
    BadRequest,
    #[error("Harness API key was not authorized")]
    Unauthorized,
    #[error("Harness access was forbidden")]
    Forbidden,
    #[error("Harness resource was not found")]
    NotFound,
    #[error("Harness request conflicted with provider state")]
    Conflict,
    #[error("Harness request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Harness provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Harness transport timed out")]
    Timeout,
    #[error("Harness access was lost while reading evidence")]
    AccessLost,
    #[error("Harness returned a partial transport response")]
    Partial,
    #[error("Harness response was invalid")]
    InvalidResponse,
    #[error("Harness fixture did not contain a response for the request")]
    FixtureMissing,
    #[error("Harness transport does not implement this bounded read")]
    Unsupported,
}

impl HarnessTransportError {
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
            | Self::InvalidResponse
            | Self::FixtureMissing
            | Self::Unsupported => None,
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
pub enum HarnessDeliveryResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Harness identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Harness delivery scope is invalid")]
    InvalidScope,
    #[error("Harness permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Harness consent scope is invalid")]
    InvalidConsent,
    #[error("opaque API-key SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Harness registration is invalid")]
    InvalidRegistration,
    #[error("Harness request is invalid")]
    InvalidRequest,
    #[error("Harness request does not match its scope")]
    ScopeMismatch,
    #[error("Harness cursor does not match its bound request")]
    CursorMismatch,
    #[error("Harness execution binding does not match the scope")]
    ExecutionBindingMismatch,
    #[error("Harness provider definition drifted")]
    ProviderDrift,
    #[error("Harness contract definition drifted")]
    ContractDrift,
    #[error("Harness registration is revoked")]
    RegistrationRevoked,
    #[error("Harness registration is reversed")]
    RegistrationReversed,
    #[error("Harness registration is not active")]
    RegistrationInactive,
    #[error("Harness consent is expired")]
    ConsentExpired,
    #[error("Harness consent is revoked")]
    ConsentRevoked,
    #[error("Harness evidence was tampered with")]
    TamperedEvidence,
    #[error("Harness evidence is partial or truncated")]
    PartialEvidence,
    #[error("Harness evidence has a conflicting execution binding")]
    ExecutionReplaced,
    #[error("Harness recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Harness transport failed: {0}")]
    Transport(#[from] HarnessTransportError),
}
