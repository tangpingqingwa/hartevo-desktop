use thiserror::Error;

pub type ModelResult<T> = std::result::Result<T, AwsSsmAutomationError>;

/// Errors surfaced by the bounded, non-native transport seam.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSsmAutomationTransportError {
    #[error("BLOCKED_ENV: AWS SSM Automation native transport is disabled")]
    BlockedEnv,
    #[error("AWS SSM Automation rejected the filter")]
    InvalidFilter,
    #[error("AWS SSM Automation rejected the next token")]
    InvalidNextToken,
    #[error("AWS SSM Automation returned a bad request")]
    BadRequest,
    #[error("AWS SSM credentials were not authorized")]
    Unauthorized,
    #[error("AWS SSM access was forbidden")]
    Forbidden,
    #[error("AWS SSM Automation execution or document was not found")]
    NotFound,
    #[error("AWS SSM Automation request conflicted with provider state")]
    Conflict,
    #[error("AWS SSM Automation request was throttled")]
    Throttled { retry_after_seconds: Option<u64> },
    #[error("AWS SSM provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS SSM Automation transport timed out")]
    Timeout,
    #[error("AWS SSM Automation access was lost while reading evidence")]
    AccessLoss,
    #[error("AWS SSM Automation returned a partial response")]
    Partial,
    #[error("AWS SSM Automation response was truncated")]
    Truncated,
    #[error("AWS SSM Automation provider returned an unknown response")]
    Unknown,
    #[error("AWS SSM Automation response was invalid")]
    InvalidResponse,
}

impl AwsSsmAutomationTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidFilter | Self::InvalidNextToken | Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLoss
            | Self::Partial
            | Self::Truncated
            | Self::Unknown
            | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLoss
        )
    }

    pub const fn stable_code(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::InvalidFilter => "InvalidFilter",
            Self::InvalidNextToken => "InvalidNextToken",
            Self::BadRequest => "BadRequest",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "NotFound",
            Self::Conflict => "Conflict",
            Self::Throttled { .. } => "ThrottlingException",
            Self::ServerError { .. } => "ServerError",
            Self::Timeout => "Timeout",
            Self::AccessLoss => "AccessLoss",
            Self::Partial => "Partial",
            Self::Truncated => "Truncated",
            Self::Unknown => "Unknown",
            Self::InvalidResponse => "InvalidResponse",
        }
    }
}

/// Model and lifecycle errors. No variant carries raw provider output or an
/// error message supplied by the provider.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSsmAutomationError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS SSM Automation identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("AWS SSM Automation scope is invalid")]
    InvalidScope,
    #[error("AWS SSM Automation permission fence is invalid")]
    InvalidPermissionFence,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS SSM Automation filter is invalid")]
    InvalidFilter,
    #[error("AWS SSM Automation next token is invalid")]
    InvalidNextToken,
    #[error("AWS SSM Automation scope mismatch for {field}")]
    ScopeMismatch { field: &'static str },
    #[error("AWS SSM Automation filter is not bound to its scope")]
    FilterMismatch,
    #[error("AWS SSM Automation cursor is not bound to its filter")]
    CursorMismatch,
    #[error("AWS SSM Automation provider definition drifted")]
    ProviderDrift,
    #[error("AWS SSM Automation registration is tampered")]
    RegistrationTampered,
    #[error("AWS SSM Automation registration is revoked")]
    RegistrationRevoked,
    #[error("AWS SSM Automation registration is reversed")]
    RegistrationReversed,
    #[error("AWS SSM Automation registration is not active")]
    RegistrationInactive,
    #[error("AWS SSM Automation execution was replaced")]
    ExecutionReplaced,
    #[error("AWS SSM Automation execution status regressed")]
    StatusRegression,
    #[error("AWS SSM Automation evidence is partial")]
    PartialEvidence,
    #[error("AWS SSM Automation evidence was truncated")]
    TruncatedEvidence,
    #[error("AWS SSM Automation evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS SSM Automation response was invalid")]
    InvalidResponse,
    #[error("AWS SSM Automation proposal was tampered with")]
    TamperedProposal,
    #[error("AWS SSM Automation recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("AWS SSM Automation transport failed: {0}")]
    Transport(#[from] AwsSsmAutomationTransportError),
}

pub type Result<T> = std::result::Result<T, AwsSsmAutomationError>;
