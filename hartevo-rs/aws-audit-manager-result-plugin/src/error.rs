//! Errors for the bounded AWS Audit Manager Layer-1 boundary.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsAuditManagerError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAuditManagerTransportError {
    #[error("BLOCKED_ENV: AWS Audit Manager native transport is disabled")]
    BlockedEnv,
    #[error("AWS Audit Manager request was invalid")]
    BadRequest,
    #[error("AWS Audit Manager credentials were not authorized")]
    Unauthorized,
    #[error("AWS Audit Manager access was forbidden")]
    Forbidden,
    #[error("AWS Audit Manager assessment or report was not found")]
    NotFound,
    #[error("AWS Audit Manager request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Audit Manager provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Audit Manager transport timed out")]
    Timeout,
    #[error("AWS Audit Manager access was lost while reading evidence")]
    AccessLoss,
    #[error("AWS Audit Manager returned a partial transport response")]
    Partial,
    #[error("AWS Audit Manager response was invalid")]
    InvalidResponse,
}

impl AwsAuditManagerTransportError {
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
            | Self::AccessLoss
            | Self::Partial
            | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLoss
        )
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerError { .. } => "server_error",
            Self::Timeout => "timeout",
            Self::AccessLoss => "access_loss",
            Self::Partial => "partial",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAuditManagerError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Audit Manager identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Audit Manager scope is invalid")]
    InvalidScope,
    #[error("AWS Audit Manager permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Audit Manager consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS Audit Manager registration is invalid")]
    InvalidRegistration,
    #[error("AWS Audit Manager request is invalid")]
    InvalidRequest,
    #[error("AWS Audit Manager request does not match its scope")]
    ScopeMismatch,
    #[error("AWS Audit Manager status filter does not match its bound request")]
    FilterMismatch,
    #[error("AWS Audit Manager cursor does not match its bound request")]
    CursorMismatch,
    #[error("AWS Audit Manager provider definition drifted")]
    ProviderDrift,
    #[error("AWS Audit Manager contract definition drifted")]
    ContractDrift,
    #[error("AWS Audit Manager account is not registered as an existing tenant")]
    UnregisteredAccount,
    #[error("AWS Audit Manager is not available to new customers")]
    NewCustomerNotEligible,
    #[error("AWS Audit Manager registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Audit Manager registration is reversed")]
    RegistrationReversed,
    #[error("AWS Audit Manager registration is not active")]
    RegistrationInactive,
    #[error("AWS Audit Manager consent is expired")]
    ConsentExpired,
    #[error("AWS Audit Manager consent is revoked")]
    ConsentRevoked,
    #[error("AWS Audit Manager evidence is expired or stale")]
    EvidenceExpired,
    #[error("AWS Audit Manager evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Audit Manager assessment revision was replaced")]
    AssessmentReplaced,
    #[error("AWS Audit Manager framework revision was replaced")]
    FrameworkReplaced,
    #[error("AWS Audit Manager control-set revision was replaced")]
    ControlSetReplaced,
    #[error("AWS Audit Manager report revision was replaced")]
    ReportReplaced,
    #[error("AWS Audit Manager pagination loop was detected")]
    PaginationLoop,
    #[error("AWS Audit Manager proposal or recording was replayed with different evidence")]
    ReplayDetected,
    #[error("AWS Audit Manager evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Audit Manager recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Audit Manager transport failed: {0}")]
    Transport(#[from] AwsAuditManagerTransportError),
}

pub type AwsAuditManagerServiceError = AwsAuditManagerError;
