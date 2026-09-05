use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsDataZoneSubscriptionResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsDataZoneTransportError {
    #[error("BLOCKED_ENV: Amazon DataZone native transport is disabled")]
    BlockedEnv,
    #[error("Amazon DataZone request was invalid")]
    BadRequest,
    #[error("Amazon DataZone credentials were not authorized")]
    Unauthorized,
    #[error("Amazon DataZone access was forbidden")]
    Forbidden,
    #[error("Amazon DataZone asset, subscription request, or subscription was not found")]
    NotFound,
    #[error("Amazon DataZone request conflicted with provider state")]
    Conflict,
    #[error("Amazon DataZone request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Amazon DataZone provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Amazon DataZone transport timed out")]
    Timeout,
    #[error("Amazon DataZone access was lost while reading evidence")]
    AccessLost,
    #[error("Amazon DataZone returned a partial transport response")]
    Partial,
    #[error("Amazon DataZone response was invalid")]
    InvalidResponse,
}

impl AwsDataZoneTransportError {
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
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsDataZoneSubscriptionResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Amazon DataZone identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Amazon DataZone scope is invalid")]
    InvalidScope,
    #[error("Amazon DataZone permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Amazon DataZone consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("Amazon DataZone registration is invalid")]
    InvalidRegistration,
    #[error("Amazon DataZone evidence request is invalid")]
    InvalidRequest,
    #[error("Amazon DataZone request does not match its scope")]
    ScopeMismatch,
    #[error("Amazon DataZone filter does not match the bound scope")]
    FilterMismatch,
    #[error("Amazon DataZone cursor does not match its bound filter")]
    CursorMismatch,
    #[error("Amazon DataZone provider definition drifted")]
    ProviderDrift,
    #[error("Amazon DataZone contract definition drifted")]
    ContractDrift,
    #[error("Amazon DataZone registration is reversed")]
    RegistrationReversed,
    #[error("Amazon DataZone registration is not active")]
    RegistrationInactive,
    #[error("Amazon DataZone consent is expired")]
    ConsentExpired,
    #[error("Amazon DataZone consent is revoked")]
    ConsentRevoked,
    #[error("Amazon DataZone evidence was tampered with")]
    TamperedEvidence,
    #[error("Amazon DataZone evidence is partial or truncated")]
    PartialEvidence,
    #[error("Amazon DataZone status, revision, reviewer role, or resource drifted")]
    EvidenceDrift,
    #[error("Amazon DataZone recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Amazon DataZone transport failed: {0}")]
    Transport(#[from] AwsDataZoneTransportError),
}
