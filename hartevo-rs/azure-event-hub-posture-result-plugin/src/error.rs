use thiserror::Error;

pub type Result<T> = std::result::Result<T, AzureEventHubPostureResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureEventHubTransportError {
    #[error("BLOCKED_ENV: Azure Event Hub native transport is disabled")]
    BlockedEnv,
    #[error("Azure Event Hub management request was invalid")]
    BadRequest,
    #[error("Azure Event Hub credentials were not authorized")]
    Unauthorized,
    #[error("Azure Event Hub access was forbidden")]
    Forbidden,
    #[error("Azure Event Hub resource was not found")]
    NotFound,
    #[error("Azure Event Hub request conflicted with provider state")]
    Conflict,
    #[error("Azure Event Hub management request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Azure Event Hub provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Azure Event Hub management transport timed out")]
    Timeout,
    #[error("Azure Event Hub access was lost while reading posture")]
    AccessLost,
    #[error("Azure Event Hub provider returned a partial or truncated response")]
    Partial,
    #[error("Azure Event Hub provider returned unknown state")]
    Unknown,
    #[error("Azure Event Hub provider response was invalid")]
    InvalidResponse,
    #[error("Azure Event Hub evidence was tampered with")]
    Tampered,
    #[error("Azure Event Hub API revision drifted")]
    ApiDrift,
    #[error("Azure Event Hub scope drifted")]
    ScopeDrift,
    #[error("Azure Event Hub state is stale")]
    StaleState,
    #[error("Azure Event Hub consumer-group pagination loop detected")]
    PaginationLoop,
    #[error("Azure Event Hub registration was revoked")]
    Revoked,
}

impl AzureEventHubTransportError {
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
            | Self::ApiDrift
            | Self::ScopeDrift
            | Self::StaleState
            | Self::PaginationLoop
            | Self::Revoked => None,
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
pub enum AzureEventHubPostureResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Azure Event Hub identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Azure Event Hub posture scope is invalid")]
    InvalidScope,
    #[error("Azure Event Hub permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Azure Event Hub consent scope is invalid")]
    InvalidConsent,
    #[error("opaque non-serializing Entra SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Azure Event Hub registration is invalid")]
    InvalidRegistration,
    #[error("Azure Event Hub posture request is invalid")]
    InvalidRequest,
    #[error("Azure Event Hub provider response is invalid")]
    InvalidResponse,
    #[error("Azure Event Hub scope does not match the request or response")]
    ScopeMismatch,
    #[error("Azure Event Hub API revision drifted")]
    ApiDrift,
    #[error("Azure Event Hub provider definition drifted")]
    ProviderDrift,
    #[error("Azure Event Hub contract definition drifted")]
    ContractDrift,
    #[error("Azure Event Hub permission definition drifted")]
    PermissionDrift,
    #[error("Azure Event Hub metadata is stale")]
    StaleState,
    #[error("Azure Event Hub consumer-group pagination loop detected")]
    PaginationLoop,
    #[error("Azure Event Hub registration is revoked")]
    RegistrationRevoked,
    #[error("Azure Event Hub registration is reversed")]
    RegistrationReversed,
    #[error("Azure Event Hub registration is not active")]
    RegistrationInactive,
    #[error("Azure Event Hub consent is expired")]
    ConsentExpired,
    #[error("Azure Event Hub consent is revoked")]
    ConsentRevoked,
    #[error("Azure Event Hub SecretReference is revoked")]
    SecretRevoked,
    #[error("Azure Event Hub evidence was tampered with")]
    TamperedEvidence,
    #[error("Azure Event Hub evidence is partial or truncated")]
    PartialEvidence,
    #[error("Azure Event Hub provider state is unknown")]
    ProviderUnknown,
    #[error("Azure Event Hub evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("Azure Event Hub recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Azure Event Hub transport failed: {0}")]
    Transport(#[from] AzureEventHubTransportError),
}
