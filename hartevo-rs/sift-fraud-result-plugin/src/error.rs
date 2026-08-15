//! Typed failures for the bounded Sift result boundary.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SiftFraudResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SiftTransportError {
    #[error("access was denied")]
    Denied,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("provider rate limited the read; retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u32 },
    #[error("provider is unknown")]
    ProviderUnknown,
    #[error("provider request timed out")]
    TimedOut,
    #[error("provider object was not found")]
    NotFound,
    #[error("provider returned an unauthorized response")]
    Unauthorized,
    #[error("provider returned a forbidden response")]
    Forbidden,
    #[error("provider returned a conflicting revision")]
    Conflict,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("the environment does not permit native Sift access: BLOCKED_ENV")]
    BlockedEnv,
}

impl SiftTransportError {
    pub const fn is_non_adoptable(&self) -> bool {
        true
    }

    pub const fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RateLimited { .. })
    }

    pub fn diagnostic(&self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::AccessLoss => "access_loss",
            Self::RateLimited { .. } => "rate_limited",
            Self::ProviderUnknown => "provider_unknown",
            Self::TimedOut => "timed_out",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::MalformedResponse => "malformed_response",
            Self::ResponseTooLarge => "response_too_large",
            Self::BlockedEnv => crate::BLOCKED_ENV,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SiftFraudResultError {
    #[error("invalid {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("invalid Sift fraud result scope: {0}")]
    InvalidScope(&'static str),
    #[error("invalid consent scope")]
    InvalidConsent,
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid opaque API-key reference")]
    InvalidSecretReference,
    #[error("invalid request")]
    InvalidRequest,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is already revoked")]
    RegistrationAlreadyRevoked,
    #[error("registration is not revoked")]
    RegistrationNotRevoked,
    #[error("registration is already reversed")]
    RegistrationReversed,
    #[error("registration revision overflowed")]
    RegistrationRevisionOverflow,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("Project/Mission/Work Product revision mismatch")]
    RevisionMismatch,
    #[error("consent mismatch or expiry")]
    ConsentMismatch,
    #[error("provider definition drift")]
    ProviderDefinitionDrift,
    #[error("response is too large")]
    ResponseTooLarge,
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("provider transport failed: {0}")]
    Provider(#[from] SiftTransportError),
    #[error("evidence is tampered")]
    TamperedEvidence,
    #[error("proposal is tampered")]
    TamperedProposal,
    #[error("proposal replay was rejected")]
    ReplayDetected,
    #[error("recording idempotency key conflicts with another proposal")]
    RecordingConflict,
    #[error("contract identity mismatch")]
    ContractMismatch,
    #[error("unsupported external mutation: {0}")]
    UnsupportedMutation(&'static str),
}
