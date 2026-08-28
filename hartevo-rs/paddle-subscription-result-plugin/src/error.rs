use thiserror::Error;

/// Errors exposed by the Paddle Layer-1 boundary.  Variants carry only
/// bounded field names, status codes, and digests; provider bodies and
/// credential material never cross this boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PaddleSubscriptionResultError {
    #[error("{field} is empty, malformed, or exceeds its bound")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is invalid or exceeds its bound")]
    InvalidText { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("the Paddle subscription scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("the Paddle API binding is invalid")]
    InvalidApiBinding,
    #[error("the Paddle read permission binding is invalid")]
    InvalidPermission,
    #[error("the bounded Paddle read request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("the provider response is malformed or violates the typed contract: {0}")]
    InvalidResponse(&'static str),
    #[error("the provider returned unsupported HTTP status {0}")]
    UnsupportedStatus(u16),
    #[error("the provider response exceeded the {maximum}-byte cap (observed {actual} bytes)")]
    ResponseTooLarge { actual: usize, maximum: usize },
    #[error("provider error: {0}")]
    Provider(#[from] PaddleBillingProviderError),
    #[error("the requested Paddle scope does not match the registered scope: {0}")]
    ScopeMismatch(&'static str),
    #[error("the provider identity drifted from the registered provider")]
    ProviderDrift,
    #[error("the Paddle API binding drifted from the registered API")]
    ApiDrift,
    #[error("the Paddle permission lease drifted")]
    PermissionDrift,
    #[error("the project, Mission, Work Product, or scope revision drifted")]
    RevisionDrift,
    #[error("the response snapshot is stale")]
    StaleResult,
    #[error("the registration is required")]
    RegistrationRequired,
    #[error("the registration has been revoked")]
    RegistrationRevoked,
    #[error("the registration digest or binding was tampered")]
    RegistrationTampered,
    #[error("the opaque API-key SecretReference is revoked")]
    SecretRevoked,
    #[error("the opaque API-key SecretReference is not bound to this scope")]
    SecretReferenceMismatch,
    #[error("the proposal digest or binding was tampered")]
    ProposalTampered,
    #[error("the evidence digest or binding was tampered")]
    EvidenceTampered,
    #[error("the returned account is outside the exact scope")]
    AccountMismatch,
    #[error("the requested subscription is outside the exact scope")]
    SubscriptionMismatch,
    #[error("the requested transaction is outside the exact scope")]
    TransactionMismatch,
    #[error("the returned event is outside the exact scope")]
    EventMismatch,
    #[error("the pagination cursor is outside the exact scope")]
    CursorMismatch,
    #[error("the pagination cursor has expired")]
    CursorExpired,
    #[error("the pagination cursor repeated")]
    CursorLoop,
    #[error("the bounded page limit was exceeded")]
    PageLimitExceeded,
    #[error("a recorded response was replayed with a divergent fingerprint")]
    ReplayDetected,
    #[error("the operation {0} is outside the read-only Layer-1 authority")]
    MutationForbidden(&'static str),
}

/// Provider faults are typed projections.  No raw provider error body is
/// retained or returned.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PaddleBillingProviderError {
    #[error("BLOCKED_ENV: native Paddle API-key resolution or HTTPS transport is unavailable")]
    BlockedEnv,
    #[error("Paddle returned HTTP 401")]
    Unauthorized,
    #[error("Paddle returned HTTP 403")]
    Forbidden,
    #[error("Paddle returned HTTP 404")]
    NotFound,
    #[error("Paddle returned HTTP 409")]
    Conflict,
    #[error("Paddle returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Paddle request timed out")]
    Timeout,
    #[error("Paddle returned HTTP {status}")]
    ServerError { status: u16 },
    #[error("the Paddle transport is unavailable")]
    TransportUnavailable,
    #[error("Paddle access was lost")]
    AccessLoss,
    #[error("the Paddle response was malformed: {0}")]
    MalformedResponse(&'static str),
    #[error("the Paddle response was partial")]
    PartialResponse,
    #[error("the Paddle response fingerprint was tampered")]
    ResponseTampered,
    #[error("the provider returned an unsupported status")]
    UnexpectedStatus { status: u16 },
}

impl PaddleBillingProviderError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::TransportUnavailable
            | Self::AccessLoss
            | Self::MalformedResponse(_)
            | Self::PartialResponse
            | Self::ResponseTampered
            | Self::UnexpectedStatus { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::NotFound | Self::AccessLoss
        )
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. }
                | Self::Timeout
                | Self::ServerError { .. }
                | Self::TransportUnavailable
        )
    }
}

pub type Result<T> = std::result::Result<T, PaddleSubscriptionResultError>;
