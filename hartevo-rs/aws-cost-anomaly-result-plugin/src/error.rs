use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsCostAnomalyError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCostAnomalyTransportError {
    #[error("BLOCKED_ENV: AWS Cost Anomaly native transport is disabled")]
    BlockedEnv,
    #[error("AWS Cost Anomaly request was invalid")]
    BadRequest,
    #[error("AWS Cost Anomaly credentials were not authorized")]
    Unauthorized,
    #[error("AWS Cost Anomaly access was forbidden")]
    Forbidden,
    #[error("AWS Cost Anomaly target was not found")]
    NotFound,
    #[error("AWS Cost Anomaly request conflicted with provider state")]
    Conflict,
    #[error("AWS Cost Anomaly request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Cost Anomaly provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Cost Anomaly transport timed out")]
    Timeout,
    #[error("AWS Cost Anomaly access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Cost Anomaly provider returned a partial response")]
    Partial,
    #[error("AWS Cost Anomaly provider response was invalid")]
    InvalidResponse,
}

impl AwsCostAnomalyTransportError {
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

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCostAnomalyError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Cost Anomaly identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Cost Anomaly scope is invalid")]
    InvalidScope,
    #[error("AWS Cost Anomaly permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Cost Anomaly consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS Cost Anomaly registration is invalid")]
    InvalidRegistration,
    #[error("AWS Cost Anomaly request is invalid")]
    InvalidRequest,
    #[error("AWS Cost Anomaly request does not match its scope")]
    ScopeMismatch,
    #[error("AWS Cost Anomaly monitor allowlist does not match the bound monitor")]
    MonitorMismatch,
    #[error("AWS Cost Anomaly date window is not allowlisted")]
    WindowMismatch,
    #[error("AWS Cost Anomaly filter does not match its scope")]
    FilterMismatch,
    #[error("AWS Cost Anomaly cursor does not match its request")]
    CursorMismatch,
    #[error("AWS Cost Anomaly pagination cursor repeated")]
    PaginationLoop,
    #[error("AWS Cost Anomaly retention fence expired")]
    RetentionExpired,
    #[error("AWS Cost Anomaly provider definition drifted")]
    ProviderDrift,
    #[error("AWS Cost Anomaly contract definition drifted")]
    ContractDrift,
    #[error("AWS Cost Anomaly registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Cost Anomaly registration is reversed")]
    RegistrationReversed,
    #[error("AWS Cost Anomaly registration is not active")]
    RegistrationInactive,
    #[error("AWS Cost Anomaly consent is expired")]
    ConsentExpired,
    #[error("AWS Cost Anomaly consent is revoked")]
    ConsentRevoked,
    #[error("AWS Cost Anomaly evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Cost Anomaly evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Cost Anomaly target was replaced while being read")]
    TargetReplaced,
    #[error("AWS Cost Anomaly recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Cost Anomaly transport failed: {0}")]
    Transport(#[from] AwsCostAnomalyTransportError),
}
