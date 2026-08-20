use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsSecurityLakeError>;

/// Errors exposed by a Layer-1 transport seam. They are intentionally
/// protocol-level categories; provider payloads and response text are never
/// carried across the boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSecurityLakeTransportError {
    #[error("Security Lake access was denied")]
    AccessDenied,
    #[error("Security Lake authentication was rejected")]
    Unauthorized,
    #[error("Security Lake resource was not found")]
    NotFound,
    #[error("Security Lake pagination token was invalid or expired")]
    InvalidToken,
    #[error("Security Lake request was throttled")]
    Throttled,
    #[error("Security Lake service was unavailable")]
    ServiceUnavailable,
    #[error("Security Lake request timed out")]
    Timeout,
    #[error("Security Lake request was malformed")]
    BadRequest,
    #[error("Security Lake response exceeded the Layer-1 bound")]
    ResponseTooLarge,
    #[error("Security Lake response retention fence was not satisfied")]
    RetentionExpired,
    #[error("the Layer-1 environment is blocked from native execution")]
    EnvironmentBlocked,
    #[error("the fixture or recording queue has no response")]
    QueueExhausted,
    #[error("the provider response failed the Layer-1 integrity fence")]
    InvalidResponse,
}

impl AwsSecurityLakeTransportError {
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::AccessDenied | Self::Unauthorized | Self::NotFound
        )
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Throttled | Self::ServiceUnavailable | Self::Timeout
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSecurityLakeError {
    #[error("invalid {field} identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid Security Lake scope")]
    InvalidScope,
    #[error("invalid opaque SigV4 SecretReference")]
    InvalidSecretReference,
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid consent scope")]
    InvalidConsent,
    #[error("provider or API revision drifted")]
    ProviderDrift,
    #[error("invalid reversible registration")]
    InvalidRegistration,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration has already been reversed")]
    RegistrationReversed,
    #[error("registration scope does not match the consumer scope")]
    ScopeMismatch,
    #[error("registration permission fence does not match")]
    PermissionMismatch,
    #[error("registration lake fence does not match")]
    LakeMismatch,
    #[error("registration evidence fence does not match")]
    EvidenceMismatch,
    #[error("request is outside the declared allowlist")]
    RequestOutsideAllowlist,
    #[error("pagination token is expired")]
    PaginationExpired,
    #[error("pagination token does not match the request fence")]
    PaginationDrift,
    #[error("pagination loop detected")]
    PaginationLoop,
    #[error("pagination remained partial after the Layer-1 page bound")]
    PaginationPartial,
    #[error("exception retention window was not satisfied")]
    RetentionGap,
    #[error("evidence is incomplete, unknown, or not adoptable")]
    NonAdoptableEvidence,
    #[error("evidence failed its digest or authority fence")]
    TamperedEvidence,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("unsupported operation")]
    UnsupportedOperation,
    #[error("transport: {0}")]
    Transport(#[from] AwsSecurityLakeTransportError),
}
