use thiserror::Error;

pub type Result<T> = std::result::Result<T, FlyioDeploymentResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlyioTransportError {
    #[error("BLOCKED_ENV: native Fly.io token and HTTPS authority are unavailable")]
    BlockedEnv,
    #[error("Fly.io request was invalid")]
    BadRequest,
    #[error("Fly.io credentials were not authorized")]
    Unauthorized,
    #[error("Fly.io access was forbidden")]
    Forbidden,
    #[error("Fly.io app or Machine was not found")]
    NotFound,
    #[error("Fly.io request conflicted with provider state")]
    Conflict,
    #[error("Fly.io request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Fly.io provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Fly.io provider request timed out")]
    Timeout,
    #[error("Fly.io access was lost while reading evidence")]
    AccessLost,
    #[error("Fly.io provider returned partial evidence")]
    Partial,
    #[error("Fly.io provider returned an unknown state")]
    Unknown,
    #[error("Fly.io provider response was invalid")]
    InvalidResponse,
    #[error("Fly.io evidence was tampered with")]
    Tampered,
    #[error("Fly.io pagination loop detected")]
    PaginationLoop,
}

impl FlyioTransportError {
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

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlyioDeploymentResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Fly.io identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Fly.io image reference is not a sha256 digest")]
    InvalidImageDigest,
    #[error("Fly.io scope is invalid")]
    InvalidScope,
    #[error("Fly.io permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Fly.io consent scope is invalid")]
    InvalidConsent,
    #[error("opaque Fly API-token SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Fly.io registration is invalid")]
    InvalidRegistration,
    #[error("Fly.io request is invalid")]
    InvalidRequest,
    #[error("Fly.io provider response is invalid")]
    InvalidResponse,
    #[error("Fly.io scope does not match the request or response")]
    ScopeMismatch,
    #[error("Fly.io app, Machine, instance, image, release, region, or process scope drifted")]
    ScopeDrift,
    #[error("Fly.io provider definition drifted")]
    ProviderDrift,
    #[error("Fly.io contract definition drifted")]
    ContractDrift,
    #[error("Fly.io registration is revoked")]
    RegistrationRevoked,
    #[error("Fly.io registration is reversed")]
    RegistrationReversed,
    #[error("Fly.io registration is not active")]
    RegistrationInactive,
    #[error("Fly.io consent is expired or revoked")]
    ConsentInvalid,
    #[error("Fly.io SecretReference is revoked")]
    SecretRevoked,
    #[error("Fly.io evidence was tampered with")]
    TamperedEvidence,
    #[error("Fly.io evidence is partial or truncated")]
    PartialEvidence,
    #[error("Fly.io provider state is unknown")]
    ProviderUnknown,
    #[error("Fly.io evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("Fly.io recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Fly.io evidence sequence moved backwards")]
    EvidenceSequenceRegression,
    #[error("Fly.io transport failed: {0}")]
    Transport(#[from] FlyioTransportError),
}
