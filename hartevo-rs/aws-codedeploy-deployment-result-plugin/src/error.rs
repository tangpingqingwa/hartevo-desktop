use thiserror::Error;

/// Errors returned by the typed CodeDeploy Layer-1 seam.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodeDeployDeploymentResultError {
    #[error("{field} is invalid: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} is not a valid SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("contract validation failed: {0}")]
    ContractInvalid(&'static str),
    #[error("registration is invalid or tampered")]
    InvalidRegistration,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("secret reference is revoked")]
    SecretReferenceRevoked,
    #[error("scope does not match the registered exact scope")]
    ScopeMismatch,
    #[error("deployment revision does not match the registered revision fence")]
    RevisionMismatch,
    #[error("permission snapshot does not match the registered permission fence")]
    PermissionDrift,
    #[error("provider identity or API revision drifted")]
    ProviderDrift,
    #[error("pagination cursor was replayed")]
    PaginationLoop,
    #[error("pagination page bound was exceeded")]
    PageLimitExceeded,
    #[error("evidence item bound was exceeded")]
    ItemLimitExceeded,
    #[error("provider response byte bound was exceeded")]
    ResponseTooLarge,
    #[error("provider returned an exact deployment that is not in scope")]
    DeploymentNotFound,
    #[error("provider returned a target that is not in the exact deployment scope")]
    TargetScopeMismatch,
    #[error("evidence is incomplete or truncated")]
    IncompleteEvidence,
    #[error("evidence digest or typed field fingerprint does not verify")]
    EvidenceTampered,
    #[error("proposal or receipt does not match evidence")]
    ReceiptMismatch,
    #[error("evidence has already been recorded with a different fingerprint")]
    DuplicateEvidence,
    #[error("receipt has not been recorded")]
    ReceiptNotRecorded,
    #[error("provider replayed a conflicting deployment result")]
    ReplayConflict,
    #[error("consumer binding does not match the Mission scope")]
    ConsumerScopeMismatch,
    #[error("provider operation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("transport error: {0}")]
    Transport(#[from] AwsCodeDeployTransportError),
}

/// Typed provider/transport failures. No raw provider payload or credential
/// material is carried by this enum.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodeDeployTransportError {
    #[error("BLOCKED_ENV: native CodeDeploy transport is not available")]
    BlockedEnv,
    #[error("access was denied or authorization was obscured")]
    AccessLoss,
    #[error("deployment was not found or is not visible")]
    NotFound,
    #[error("provider throttled the bounded read")]
    Throttled,
    #[error("provider returned a conflict")]
    Conflict,
    #[error("provider response was malformed: {0}")]
    Malformed(&'static str),
    #[error("provider response was too large")]
    ResponseTooLarge,
    #[error("provider network is unavailable")]
    NetworkUnavailable,
    #[error("provider request timed out")]
    Timeout,
    #[error("provider cursor looped")]
    PaginationLoop,
    #[error("provider returned an unexpected operation")]
    UnexpectedOperation,
}

pub type CodeDeployDeploymentResultError = AwsCodeDeployDeploymentResultError;
pub type CodeDeployTransportError = AwsCodeDeployTransportError;
pub type AwsCodeDeployError = AwsCodeDeployDeploymentResultError;
