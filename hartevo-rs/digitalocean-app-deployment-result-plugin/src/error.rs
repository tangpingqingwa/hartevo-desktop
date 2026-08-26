use thiserror::Error;

pub type Result<T> = std::result::Result<T, DigitalOceanAppDeploymentResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DigitalOceanTransportError {
    #[error("BLOCKED_ENV: DigitalOcean native transport is disabled")]
    BlockedEnv,
    #[error("DigitalOcean request was invalid")]
    BadRequest,
    #[error("DigitalOcean credentials were not authorized")]
    Unauthorized,
    #[error("DigitalOcean access was forbidden")]
    Forbidden,
    #[error("DigitalOcean app or deployment was not found")]
    NotFound,
    #[error("DigitalOcean request conflicted with provider state")]
    Conflict,
    #[error("DigitalOcean request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("DigitalOcean provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("DigitalOcean request timed out")]
    Timeout,
    #[error("DigitalOcean access was lost while reading evidence")]
    AccessLost,
    #[error("DigitalOcean returned a partial response")]
    Partial,
    #[error("DigitalOcean provider returned unknown state")]
    Unknown,
    #[error("DigitalOcean response was invalid")]
    InvalidResponse,
    #[error("DigitalOcean evidence was tampered with")]
    Tampered,
    #[error("DigitalOcean deployment pagination loop detected")]
    PaginationLoop,
}

impl DigitalOceanTransportError {
    #[must_use]
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
            | Self::Unknown
            | Self::InvalidResponse
            | Self::Tampered
            | Self::PaginationLoop => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DigitalOceanAppDeploymentResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid DigitalOcean identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("DigitalOcean App Platform scope is invalid")]
    InvalidScope,
    #[error("DigitalOcean component selector is invalid")]
    InvalidComponent,
    #[error("DigitalOcean permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("DigitalOcean consent scope is invalid")]
    InvalidConsent,
    #[error("opaque OAuth/API-token SecretReference is invalid")]
    InvalidSecretReference,
    #[error("DigitalOcean registration is invalid")]
    InvalidRegistration,
    #[error("DigitalOcean request is invalid")]
    InvalidRequest,
    #[error("DigitalOcean provider response is invalid")]
    InvalidResponse,
    #[error("DigitalOcean scope does not match the request or response")]
    ScopeMismatch,
    #[error("DigitalOcean account identity drifted")]
    AccountDrift,
    #[error("DigitalOcean team identity drifted")]
    TeamDrift,
    #[error("DigitalOcean app identity drifted")]
    AppDrift,
    #[error("DigitalOcean deployment identity drifted")]
    DeploymentDrift,
    #[error("DigitalOcean region drifted")]
    RegionDrift,
    #[error("DigitalOcean component allowlist drifted")]
    ComponentDrift,
    #[error("DigitalOcean source revision drifted")]
    SourceRevisionDrift,
    #[error("DigitalOcean deployment lifecycle regressed")]
    LifecycleRegression,
    #[error("DigitalOcean deployment page cursor does not match the bound request")]
    CursorMismatch,
    #[error("DigitalOcean deployment pagination loop detected")]
    PaginationLoop,
    #[error("DigitalOcean provider definition drifted")]
    ProviderDrift,
    #[error("DigitalOcean contract definition drifted")]
    ContractDrift,
    #[error("DigitalOcean registration is revoked")]
    RegistrationRevoked,
    #[error("DigitalOcean registration is reversed")]
    RegistrationReversed,
    #[error("DigitalOcean registration is not active")]
    RegistrationInactive,
    #[error("DigitalOcean consent is expired")]
    ConsentExpired,
    #[error("DigitalOcean consent is revoked")]
    ConsentRevoked,
    #[error("DigitalOcean SecretReference is revoked")]
    SecretRevoked,
    #[error("DigitalOcean evidence was tampered with")]
    TamperedEvidence,
    #[error("DigitalOcean evidence is partial or truncated")]
    PartialEvidence,
    #[error("DigitalOcean provider state is unknown")]
    ProviderUnknown,
    #[error("DigitalOcean evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("DigitalOcean recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("DigitalOcean Mission revision is stale")]
    StaleMission,
    #[error("DigitalOcean transport failed: {0}")]
    Transport(#[from] DigitalOceanTransportError),
}
