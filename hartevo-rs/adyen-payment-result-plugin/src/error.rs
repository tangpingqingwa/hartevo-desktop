use thiserror::Error;

/// Metadata-only errors for the Layer-1 Adyen payment result seam. Raw
/// response bodies, URLs, payment instruments, customer fields, and API keys
/// are intentionally absent from every error variant.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdyenPaymentResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid identifier for {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("Adyen payment result contract drifted")]
    ContractDrift,
    #[error("Adyen payment registration is revoked")]
    RegistrationRevoked,
    #[error("Adyen payment registration is already revoked")]
    AlreadyRevoked,
    #[error("Adyen payment scope mismatch")]
    ScopeMismatch,
    #[error("Adyen merchant account mismatch")]
    MerchantMismatch,
    #[error("Adyen account mismatch")]
    AccountMismatch,
    #[error("Adyen payment reference mismatch")]
    PaymentReferenceMismatch,
    #[error("Adyen payment amount mismatch")]
    AmountMismatch,
    #[error("Adyen payment currency mismatch")]
    CurrencyMismatch,
    #[error("Adyen customer fingerprint mismatch")]
    CustomerFingerprintMismatch,
    #[error("Adyen payment status transition is invalid")]
    InvalidStatusTransition,
    #[error("Adyen payment status regressed")]
    StatusRegression,
    #[error("Adyen payment identity changed")]
    SamePaymentReplacement,
    #[error("Adyen Mission revision is stale")]
    StaleMission,
    #[error("Adyen Project revision is stale")]
    StaleProject,
    #[error("Adyen Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Adyen provider revision is stale")]
    StaleProviderRevision,
    #[error("Adyen evidence digest mismatch for {field}")]
    EvidenceDigestMismatch { field: &'static str },
    #[error("Adyen registration digest mismatch")]
    RegistrationDigestMismatch,
    #[error("Adyen proposal digest mismatch")]
    ProposalDigestMismatch,
    #[error("Adyen receipt digest mismatch")]
    ReceiptDigestMismatch,
    #[error("Adyen read-back digest mismatch")]
    ReadBackMismatch,
    #[error("Adyen evidence is invalid")]
    InvalidEvidence,
    #[error("Adyen provider version mismatch")]
    ProviderVersionMismatch,
    #[error("Adyen API permission snapshot is insufficient")]
    MissingPermission,
    #[error("Adyen deterministic idempotency key mismatch")]
    IdempotencyMismatch,
    #[error("Adyen Layer 1 forbids {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("Adyen credential environment is blocked")]
    BlockedEnv,
    #[error("Adyen request was unauthorized")]
    Unauthorized,
    #[error("Adyen request was forbidden")]
    Forbidden,
    #[error("Adyen resource was not found or authorization was obscured")]
    NotFoundOrUnauthorized,
    #[error("Adyen resource was not found")]
    NotFound,
    #[error("Adyen request conflicted")]
    Conflict,
    #[error("Adyen request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Adyen service was unavailable")]
    ServerUnavailable,
    #[error("Adyen request timed out")]
    Timeout,
    #[error("Adyen network request failed")]
    Network,
    #[error("Adyen response could not be decoded")]
    Decode,
    #[error("Adyen transport configuration is invalid")]
    InvalidConfiguration,
    #[error("Adyen response exceeded the bounded metadata limit")]
    ResponseTooLarge,
}

pub type Result<T> = std::result::Result<T, AdyenPaymentResultError>;

/// HTTP/transport classification without response bodies or request URLs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdyenPaymentTransportError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found or unauthorized")]
    NotFoundOrUnauthorized,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("server unavailable")]
    ServerUnavailable,
    #[error("timeout")]
    Timeout,
    #[error("network")]
    Network,
    #[error("response could not be decoded")]
    Decode,
    #[error("response exceeded the bounded metadata limit")]
    ResponseTooLarge,
    #[error("invalid transport configuration")]
    InvalidConfiguration,
}

impl From<AdyenPaymentTransportError> for AdyenPaymentResultError {
    fn from(error: AdyenPaymentTransportError) -> Self {
        match error {
            AdyenPaymentTransportError::Unauthorized => Self::Unauthorized,
            AdyenPaymentTransportError::Forbidden => Self::Forbidden,
            AdyenPaymentTransportError::NotFoundOrUnauthorized => Self::NotFoundOrUnauthorized,
            AdyenPaymentTransportError::NotFound => Self::NotFound,
            AdyenPaymentTransportError::Conflict => Self::Conflict,
            AdyenPaymentTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            AdyenPaymentTransportError::ServerUnavailable => Self::ServerUnavailable,
            AdyenPaymentTransportError::Timeout => Self::Timeout,
            AdyenPaymentTransportError::Network => Self::Network,
            AdyenPaymentTransportError::Decode => Self::Decode,
            AdyenPaymentTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            AdyenPaymentTransportError::InvalidConfiguration => Self::InvalidConfiguration,
        }
    }
}
