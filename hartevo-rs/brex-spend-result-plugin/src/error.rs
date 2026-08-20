use thiserror::Error;

/// Provider failures are intentionally typed and bounded. No variant carries
/// a raw Brex response body, card number, merchant text, or credential value.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrexSpendTransportError {
    #[error("transport is blocked by BLOCKED_ENV")]
    BlockedEnv,
    #[error("provider denied the bounded read")]
    Denied { status_code: Option<u16> },
    #[error("provider authorization was not available")]
    Unauthorized { status_code: Option<u16> },
    #[error("provider read permission was denied")]
    Forbidden { status_code: Option<u16> },
    #[error("provider observation is expired")]
    Expired,
    #[error("provider returned a partial observation")]
    Partial,
    #[error("provider is unknown or unavailable")]
    ProviderUnknown { status_code: Option<u16> },
    #[error("provider rate limit was reached")]
    RateLimited {
        status_code: Option<u16>,
        retry_after_seconds: Option<u32>,
    },
    #[error("provider read timed out")]
    Timeout,
    #[error("provider object was not found")]
    NotFound { status_code: Option<u16> },
    #[error("provider rejected the bounded request")]
    BadRequest { status_code: Option<u16> },
    #[error("provider response failed the integrity fence")]
    Tampered,
    #[error("provider response was malformed")]
    Malformed,
    #[error("provider response exceeded the Layer-1 byte bound")]
    ResponseTooLarge { response_bytes: u64 },
    #[error("provider rejected a duplicate idempotency key")]
    Duplicate,
}

impl BrexSpendTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Denied { status_code }
            | Self::Unauthorized { status_code }
            | Self::Forbidden { status_code }
            | Self::ProviderUnknown { status_code }
            | Self::RateLimited { status_code, .. }
            | Self::NotFound { status_code }
            | Self::BadRequest { status_code } => *status_code,
            Self::BlockedEnv
            | Self::Expired
            | Self::Partial
            | Self::Timeout
            | Self::Tampered
            | Self::Malformed
            | Self::ResponseTooLarge { .. }
            | Self::Duplicate => None,
        }
    }

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u32> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }

    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::Denied { .. } => "denied",
            Self::Unauthorized { .. } => "unauthorized",
            Self::Forbidden { .. } => "forbidden",
            Self::Expired => "expired",
            Self::Partial => "partial",
            Self::ProviderUnknown { .. } => "provider_unknown",
            Self::RateLimited { .. } => "rate_limited",
            Self::Timeout => "timeout",
            Self::NotFound { .. } => "not_found",
            Self::BadRequest { .. } => "bad_request",
            Self::Tampered => "tampered",
            Self::Malformed => "malformed",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::Duplicate => "duplicate",
        }
    }
}

/// Small crate-level error for callers that do not need the service/provider
/// detail. The typed service and provider errors remain available directly.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrexSpendError {
    #[error("invalid Brex spend-result input")]
    InvalidInput,
    #[error(transparent)]
    Transport(#[from] BrexSpendTransportError),
}

pub type Result<T> = std::result::Result<T, BrexSpendError>;
