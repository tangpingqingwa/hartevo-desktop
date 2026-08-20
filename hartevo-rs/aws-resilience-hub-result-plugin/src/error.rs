use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsResilienceHubError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsResilienceHubTransportError {
    #[error("BLOCKED_ENV: AWS Resilience Hub native transport is disabled")]
    BlockedEnv,
    #[error("AWS Resilience Hub request was invalid")]
    BadRequest,
    #[error("AWS Resilience Hub credentials were not authorized")]
    Unauthorized,
    #[error("AWS Resilience Hub access was forbidden")]
    Forbidden,
    #[error("AWS Resilience Hub application or assessment was not found")]
    NotFound,
    #[error("AWS Resilience Hub request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Resilience Hub provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Resilience Hub transport timed out")]
    Timeout,
    #[error("AWS Resilience Hub access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Resilience Hub returned a partial response")]
    Partial,
    #[error("AWS Resilience Hub pagination loop was detected")]
    PaginationLoop,
    #[error("AWS Resilience Hub response was invalid")]
    InvalidResponse,
    #[error("AWS Resilience Hub evidence drifted from the requested scope")]
    Drift,
}

impl AwsResilienceHubTransportError {
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
            | Self::PaginationLoop
            | Self::InvalidResponse
            | Self::Drift => None,
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
pub enum AwsResilienceHubError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Resilience Hub identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Resilience Hub scope is invalid")]
    InvalidScope,
    #[error("AWS Resilience Hub application or assessment allowlist is invalid: {field}")]
    InvalidAllowlist { field: &'static str },
    #[error("AWS Resilience Hub permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Resilience Hub consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS Resilience Hub registration is invalid")]
    InvalidRegistration,
    #[error("AWS Resilience Hub request is invalid")]
    InvalidRequest,
    #[error("AWS Resilience Hub request does not match its scope")]
    ScopeMismatch,
    #[error("AWS Resilience Hub application is not in the explicit allowlist")]
    ApplicationNotAllowed,
    #[error("AWS Resilience Hub assessment is not in the explicit allowlist")]
    AssessmentNotAllowed,
    #[error("AWS Resilience Hub cursor is invalid or does not match the request")]
    CursorMismatch,
    #[error("AWS Resilience Hub opaque cursor is invalid")]
    InvalidCursor,
    #[error("AWS Resilience Hub provider definition drifted")]
    ProviderDrift,
    #[error("AWS Resilience Hub contract definition drifted")]
    ContractDrift,
    #[error("AWS Resilience Hub application identity drifted")]
    ApplicationDrift,
    #[error("AWS Resilience Hub application version drifted")]
    ApplicationVersionDrift,
    #[error("AWS Resilience Hub assessment identity drifted")]
    AssessmentDrift,
    #[error("AWS Resilience Hub resiliency policy drifted")]
    ResiliencyPolicyDrift,
    #[error("AWS Resilience Hub assessment metadata is invalid")]
    InvalidAssessmentMetadata,
    #[error("AWS Resilience Hub registration was revoked")]
    RegistrationRevoked,
    #[error("AWS Resilience Hub registration was reversed")]
    RegistrationReversed,
    #[error("AWS Resilience Hub registration is not active")]
    RegistrationInactive,
    #[error("AWS Resilience Hub consent is expired")]
    ConsentExpired,
    #[error("AWS Resilience Hub consent is revoked")]
    ConsentRevoked,
    #[error("AWS Resilience Hub evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Resilience Hub evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Resilience Hub assessment evidence is stale or expired")]
    ExpiredEvidence,
    #[error("AWS Resilience Hub pagination loop was detected")]
    PaginationLoop,
    #[error("AWS Resilience Hub recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Resilience Hub transport failed: {0}")]
    Transport(#[from] AwsResilienceHubTransportError),
}
