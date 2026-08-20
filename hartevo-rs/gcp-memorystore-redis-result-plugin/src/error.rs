use thiserror::Error;

pub type Result<T> = std::result::Result<T, GcpMemorystoreError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpMemorystoreTransportError {
    #[error("BLOCKED_ENV: native Google Cloud Memorystore transport is disabled")]
    BlockedEnv,
    #[error("Memorystore request was invalid")]
    BadRequest,
    #[error("Memorystore credentials were not authorized")]
    Unauthorized,
    #[error("Memorystore access was forbidden")]
    Forbidden,
    #[error("Memorystore instance was not found")]
    NotFound,
    #[error("Memorystore request conflicted with provider state")]
    Conflict,
    #[error("Memorystore request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Memorystore provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Memorystore transport timed out")]
    Timeout,
    #[error("Memorystore access was lost while reading evidence")]
    AccessLost,
    #[error("Memorystore provider returned a partial response")]
    Partial,
    #[error("Memorystore provider returned an unreachable location")]
    UnreachableLocation,
    #[error("Memorystore provider returned an unknown state")]
    Unknown,
    #[error("Memorystore response was invalid")]
    InvalidResponse,
    #[error("Memorystore evidence was tampered with")]
    Tampered,
    #[error("Memorystore API revision drifted")]
    ApiDrift,
    #[error("Memorystore response was truncated")]
    Truncated,
    #[error("Memorystore pagination loop detected")]
    PaginationLoop,
}

impl GcpMemorystoreTransportError {
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
            | Self::UnreachableLocation
            | Self::Unknown
            | Self::InvalidResponse
            | Self::Tampered
            | Self::ApiDrift
            | Self::Truncated
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
pub enum GcpMemorystoreError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Google Cloud Memorystore identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Google Cloud Memorystore scope is invalid")]
    InvalidScope,
    #[error("Google Cloud Memorystore permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Google Cloud Memorystore consent binding is invalid")]
    InvalidConsent,
    #[error("opaque OAuth/service-account SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Google Cloud Memorystore registration is invalid")]
    InvalidRegistration,
    #[error("Google Cloud Memorystore request is invalid")]
    InvalidRequest,
    #[error("Google Cloud Memorystore provider response is invalid")]
    InvalidResponse,
    #[error("Google Cloud Memorystore scope does not match the request or response")]
    ScopeMismatch,
    #[error("Google Cloud Memorystore project, location, or instance drifted")]
    ScopeDrift,
    #[error("Google Cloud Memorystore API revision drifted")]
    ApiDrift,
    #[error("Google Cloud Memorystore provider definition drifted")]
    ProviderDrift,
    #[error("Google Cloud Memorystore permission fence drifted")]
    PermissionDrift,
    #[error("Google Cloud Memorystore evidence was stale")]
    StaleState,
    #[error("Google Cloud Memorystore page token does not match its bound request")]
    CursorMismatch,
    #[error("Google Cloud Memorystore pagination loop detected")]
    PaginationLoop,
    #[error("Google Cloud Memorystore location was unreachable")]
    UnreachableLocation,
    #[error("Google Cloud Memorystore evidence was truncated or partial")]
    TruncatedEvidence,
    #[error("Google Cloud Memorystore evidence was tampered with")]
    TamperedEvidence,
    #[error("Google Cloud Memorystore provider state is unknown")]
    ProviderUnknown,
    #[error("Google Cloud Memorystore evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("Google Cloud Memorystore recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Google Cloud Memorystore registration is revoked")]
    RegistrationRevoked,
    #[error("Google Cloud Memorystore registration is reversed")]
    RegistrationReversed,
    #[error("Google Cloud Memorystore registration is not active")]
    RegistrationInactive,
    #[error("Google Cloud Memorystore consent is expired")]
    ConsentExpired,
    #[error("Google Cloud Memorystore consent is revoked")]
    ConsentRevoked,
    #[error("Google Cloud Memorystore SecretReference is revoked")]
    SecretRevoked,
    #[error("Google Cloud Memorystore proposal was replayed")]
    ReplayDetected,
    #[error("Google Cloud Memorystore contract definition drifted")]
    ContractDrift,
    #[error("Google Cloud Memorystore transport failed: {0}")]
    Transport(#[from] GcpMemorystoreTransportError),
}
