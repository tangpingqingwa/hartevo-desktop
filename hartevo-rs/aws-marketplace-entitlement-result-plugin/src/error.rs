use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsMarketplaceEntitlementError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsMarketplaceTransportError {
    #[error("BLOCKED_ENV: AWS Marketplace native transport is disabled")]
    BlockedEnv,
    #[error("AWS Marketplace GetEntitlements request was invalid")]
    BadRequest,
    #[error("AWS Marketplace credentials were not authorized")]
    Unauthorized,
    #[error("AWS Marketplace access was forbidden")]
    Forbidden,
    #[error("AWS Marketplace entitlement was not found")]
    NotFound,
    #[error("AWS Marketplace request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Marketplace provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Marketplace transport timed out")]
    Timeout,
    #[error("AWS Marketplace access was lost while reading entitlements")]
    AccessLost,
    #[error("AWS Marketplace returned a partial response")]
    Partial,
    #[error("AWS Marketplace response was invalid")]
    InvalidResponse,
    #[error("AWS Marketplace pagination loop detected")]
    PaginationLoop,
}

impl AwsMarketplaceTransportError {
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
            | Self::InvalidResponse
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
pub enum AwsMarketplaceEntitlementError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Marketplace identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Marketplace entitlement scope is invalid")]
    InvalidScope,
    #[error("AWS Marketplace permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Marketplace consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS Marketplace entitlement registration is invalid")]
    InvalidRegistration,
    #[error("AWS Marketplace GetEntitlements request is invalid")]
    InvalidRequest,
    #[error("AWS Marketplace provider response is invalid")]
    InvalidResponse,
    #[error("AWS Marketplace entitlement scope does not match the request or response")]
    ScopeMismatch,
    #[error("AWS Marketplace GetEntitlements customer filters are not mutually exclusive")]
    FilterMismatch,
    #[error("AWS Marketplace pagination cursor does not match the bound filter")]
    CursorMismatch,
    #[error("AWS Marketplace provider definition drifted")]
    ProviderDrift,
    #[error("AWS Marketplace contract definition drifted")]
    ContractDrift,
    #[error("AWS Marketplace registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Marketplace registration is reversed")]
    RegistrationReversed,
    #[error("AWS Marketplace registration is not active")]
    RegistrationInactive,
    #[error("AWS Marketplace consent is expired")]
    ConsentExpired,
    #[error("AWS Marketplace consent is revoked")]
    ConsentRevoked,
    #[error("AWS Marketplace SigV4 SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Marketplace entitlement is expired or outside the required expiry window")]
    ExpiredEntitlement,
    #[error("AWS Marketplace returned an empty page with a continuation token")]
    EmptyPage,
    #[error("AWS Marketplace pagination loop detected")]
    PaginationLoop,
    #[error("AWS Marketplace page limit exceeded")]
    PageLimitExceeded,
    #[error("AWS Marketplace evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Marketplace evidence was partial or truncated")]
    PartialEvidence,
    #[error("AWS Marketplace recording key conflicts with an existing proposal")]
    ReplayConflict,
    #[error("AWS Marketplace recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Marketplace transport failed: {0}")]
    Transport(#[from] AwsMarketplaceTransportError),
}
