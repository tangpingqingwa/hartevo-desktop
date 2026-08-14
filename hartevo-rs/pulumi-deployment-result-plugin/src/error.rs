use thiserror::Error;

/// Errors returned by the typed Pulumi Cloud transport seam.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PulumiCloudTransportError {
    #[error("Pulumi Cloud access is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("recording or fixture response is not configured")]
    FixtureMissing,
    #[error("Pulumi Cloud returned HTTP status {status}{request_id}")]
    HttpStatus { status: u16, request_id: String },
    #[error("Pulumi Cloud authorization is unavailable")]
    Unauthorized,
    #[error("Pulumi Cloud request was forbidden")]
    Forbidden,
    #[error("Pulumi Cloud request was not found or unauthorized")]
    NotFoundOrUnauthorized,
    #[error("Pulumi Cloud request conflicted with a newer revision")]
    Conflict,
    #[error("Pulumi Cloud rate limit was reached")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Pulumi Cloud request timed out")]
    Timeout,
    #[error("Pulumi Cloud service is unavailable")]
    ServerUnavailable,
    #[error("Pulumi Cloud network transport failed")]
    Network,
    #[error("Pulumi Cloud response could not be decoded")]
    Decode,
    #[error("Pulumi Cloud response exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("bounded pagination repeated a cursor")]
    PaginationLoop,
    #[error("bounded pagination exceeded its page budget")]
    PaginationExceeded,
}

impl PulumiCloudTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFoundOrUnauthorized => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Conflict
                | Self::RateLimited { .. }
                | Self::Timeout
                | Self::ServerUnavailable
                | Self::Network
                | Self::HttpStatus {
                    status: 409..=599,
                    ..
                }
        )
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized
                | Self::Forbidden
                | Self::NotFoundOrUnauthorized
                | Self::HttpStatus {
                    status: 401 | 403 | 404,
                    ..
                }
        )
    }
}

/// Errors returned by the Pulumi deployment-result model, provider, service,
/// and Mission proposal seam.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PulumiDeploymentResultError {
    #[error("invalid identifier for {0}")]
    InvalidIdentifier(String),
    #[error("invalid digest for {0}")]
    InvalidDigest(String),
    #[error("invalid HTTPS Pulumi Cloud endpoint")]
    InvalidEndpoint,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid status transition")]
    InvalidStatusTransition,
    #[error("invalid bounded evidence")]
    InvalidEvidence,
    #[error("invalid page")]
    InvalidPage,
    #[error("opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("secret reference is not bound to the exact Pulumi scope")]
    AuthScopeMismatch,
    #[error("secret reference has been revoked")]
    CredentialRevoked,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration digest does not match its immutable contents")]
    RegistrationDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration version is invalid")]
    RegistrationVersionMismatch,
    #[error("provider version is invalid")]
    ProviderVersionMismatch,
    #[error("contract digest is invalid")]
    ContractDigestMismatch,
    #[error("permission snapshot drifted from registration")]
    PermissionDrift,
    #[error("organization scope mismatch")]
    OrganizationMismatch,
    #[error("Pulumi project scope mismatch")]
    ProjectMismatch,
    #[error("stack scope mismatch")]
    StackMismatch,
    #[error("stack revision is stale")]
    StaleStackRevision,
    #[error("deployment scope mismatch")]
    DeploymentMismatch,
    #[error("source scope mismatch")]
    SourceMismatch,
    #[error("commit scope mismatch")]
    CommitMismatch,
    #[error("update scope mismatch")]
    UpdateMismatch,
    #[error("policy evidence drifted from registration")]
    PolicyDrift,
    #[error("Mission scope mismatch")]
    MissionScopeMismatch,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("provider returned an unknown status")]
    ProviderUnknown,
    #[error("provider access was lost")]
    AccessLost,
    #[error("duplicate deployment identity carried a different evidence fingerprint")]
    DuplicateDeployment,
    #[error("deployment evidence was not recorded")]
    ReceiptNotRecorded,
    #[error("deployment receipt does not match recorded evidence")]
    ReceiptMismatch,
    #[error("evidence was truncated and cannot be verified")]
    IncompleteEvidence,
    #[error("provider result is not eligible for a verified proposal")]
    UnverifiedResult,
    #[error("mutation is forbidden for Layer 1 operation {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("native/Connected evidence is forbidden in Layer 1")]
    NativeClaimForbidden,
    #[error("Outcome adoption and kernel authority are forbidden in Layer 1")]
    OutcomeAdoptionForbidden,
    #[error("transport error: {0}")]
    Transport(#[from] PulumiCloudTransportError),
    #[error("provider error: {0}")]
    Provider(String),
}

impl PulumiDeploymentResultError {
    pub const fn retryable(&self) -> bool {
        match self {
            Self::Transport(error) => error.retryable(),
            _ => false,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Transport(error) => error.status_code(),
            _ => None,
        }
    }
}

impl From<ModelError> for PulumiDeploymentResultError {
    fn from(error: ModelError) -> Self {
        match error {
            ModelError::InvalidIdentifier(value) => Self::InvalidIdentifier(value),
            ModelError::InvalidDigest(value) => Self::InvalidDigest(value),
            ModelError::InvalidEndpoint => Self::InvalidEndpoint,
            ModelError::InvalidScope => Self::InvalidScope,
            ModelError::InvalidTimestamp => Self::InvalidTimestamp,
            ModelError::InvalidStatusTransition => Self::InvalidStatusTransition,
            ModelError::InvalidEvidence => Self::InvalidEvidence,
            ModelError::InvalidPage => Self::InvalidPage,
            ModelError::InvalidSecretReference => Self::InvalidSecretReference,
            ModelError::AuthScopeMismatch => Self::AuthScopeMismatch,
            ModelError::CredentialRevoked => Self::CredentialRevoked,
            ModelError::InvalidRegistration => Self::InvalidRegistration,
            ModelError::RegistrationDrift => Self::RegistrationDrift,
            ModelError::RegistrationRevoked => Self::RegistrationRevoked,
            ModelError::PermissionDrift => Self::PermissionDrift,
            ModelError::ScopeMismatch => Self::MissionScopeMismatch,
        }
    }
}

/// A compact model error used internally so public provider errors stay typed
/// without exposing provider payloads or secret material.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    #[error("invalid endpoint")]
    InvalidEndpoint,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid status transition")]
    InvalidStatusTransition,
    #[error("invalid evidence")]
    InvalidEvidence,
    #[error("invalid page")]
    InvalidPage,
    #[error("invalid secret reference")]
    InvalidSecretReference,
    #[error("auth scope mismatch")]
    AuthScopeMismatch,
    #[error("credential revoked")]
    CredentialRevoked,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("registration drift")]
    RegistrationDrift,
    #[error("registration revoked")]
    RegistrationRevoked,
    #[error("permission drift")]
    PermissionDrift,
    #[error("scope mismatch")]
    ScopeMismatch,
}
