use thiserror::Error;

/// Errors at the typed Terraform Cloud Layer 1 boundary.  Variants avoid
/// carrying provider bodies, URLs with credentials, raw plans, or sensitive
/// log material into callers' error paths.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TerraformCloudRunError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("Terraform Cloud hostname must be an exact HTTPS hostname")]
    InvalidHostname,
    #[error("Terraform Cloud registration is invalid")]
    InvalidRegistration,
    #[error("Terraform Cloud registration is revoked")]
    RegistrationRevoked,
    #[error("Terraform Cloud registration digest does not match")]
    RegistrationDigestMismatch,
    #[error("Terraform Cloud provider version does not match")]
    ProviderVersionMismatch,
    #[error("Terraform Cloud scope does not match the registration")]
    ScopeMismatch,
    #[error("Terraform Cloud workspace revision or lock identity is stale")]
    StaleWorkspace,
    #[error("Terraform Cloud configuration version is stale")]
    StaleConfiguration,
    #[error("Terraform Cloud run is stale")]
    StaleRun,
    #[error("provider returned an unknown Terraform state")]
    ProviderUnknown,
    #[error("provider returned an authorization-obscured 404")]
    NotFoundOrUnauthorized,
    #[error("provider rejected authentication")]
    Unauthorized,
    #[error("BLOCKED_ENV: Terraform Cloud credentials are unavailable")]
    BlockedEnv,
    #[error("provider reported a conflicting workspace or run state")]
    Conflict,
    #[error("provider rejected the typed request")]
    UnprocessableEntity,
    #[error("provider rate limit exceeded")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider transport failed")]
    Transport,
    #[error("provider response could not be decoded")]
    Decode,
    #[error("provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("bounded retry budget was exhausted")]
    RetryExhausted,
    #[error("an external create operation is ambiguous and must be reconciled")]
    AmbiguousCreate,
    #[error("the provider evidence is invalid or tampered")]
    InvalidEvidence,
    #[error("the provider evidence was truncated")]
    TruncatedEvidence,
    #[error("an equivalent run receipt already exists with a different fingerprint")]
    DuplicateFingerprint,
    #[error("the run receipt was not recorded by this provider")]
    ReceiptNotRecorded,
    #[error("the run receipt does not match the exact provider evidence")]
    ReceiptMismatch,
    #[error("apply proposal requires an explicit consent grant")]
    ConsentRequired,
    #[error("apply proposal requires a non-speculative run")]
    SpeculativeApply,
    #[error("apply proposal is blocked by policy")]
    PolicyBlocked,
    #[error("apply proposal requires an available cost estimate")]
    CostUnavailable,
    #[error("partial cost evidence cannot authorize an apply proposal")]
    CostPartial,
    #[error("Layer 1 is read-only; {operation} is reserved for Layer 2")]
    MutationForbidden { operation: &'static str },
    #[error("native Connected evidence is not available in Layer 1")]
    NativeConnectedForbidden,
}

/// Transport failures preserve HCP Terraform's authorization-obscured 404
/// semantics instead of guessing whether the token or resource was invalid.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TerraformCloudTransportError {
    #[error("authorization-obscured not found")]
    NotFoundOrUnauthorized,
    #[error("unauthorized")]
    Unauthorized,
    #[error("conflict")]
    Conflict,
    #[error("unprocessable entity")]
    UnprocessableEntity,
    #[error("rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("request timed out")]
    Timeout,
    #[error("server unavailable")]
    ServerUnavailable,
    #[error("network failure")]
    Network,
    #[error("response could not be decoded")]
    Decode,
    #[error("response exceeded the bounded size")]
    ResponseTooLarge,
    #[error("transport configuration is invalid")]
    InvalidConfiguration,
}

impl From<TerraformCloudTransportError> for TerraformCloudRunError {
    fn from(error: TerraformCloudTransportError) -> Self {
        match error {
            TerraformCloudTransportError::NotFoundOrUnauthorized => Self::NotFoundOrUnauthorized,
            TerraformCloudTransportError::Unauthorized => Self::Unauthorized,
            TerraformCloudTransportError::Conflict => Self::Conflict,
            TerraformCloudTransportError::UnprocessableEntity => Self::UnprocessableEntity,
            TerraformCloudTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            TerraformCloudTransportError::Timeout => Self::Timeout,
            TerraformCloudTransportError::ServerUnavailable => Self::RetryExhausted,
            TerraformCloudTransportError::Network => Self::Transport,
            TerraformCloudTransportError::Decode => Self::Decode,
            TerraformCloudTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            TerraformCloudTransportError::InvalidConfiguration => Self::InvalidHostname,
        }
    }
}
