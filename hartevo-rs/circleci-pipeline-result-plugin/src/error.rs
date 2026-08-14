use thiserror::Error;

/// Provider-facing failures. They deliberately do not contain upstream
/// response bodies, bearer material, raw logs, or artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CircleCiProviderError {
    #[error("CircleCI rejected the request with 400")]
    BadRequest,
    #[error("CircleCI rejected the request with 401")]
    Unauthorized,
    #[error("CircleCI rejected the request with 403")]
    Forbidden,
    #[error("CircleCI returned 404")]
    NotFound,
    #[error("CircleCI returned a conflicting revision with 409")]
    Conflict,
    #[error("CircleCI rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("CircleCI request timed out")]
    Timeout,
    #[error("CircleCI returned a server failure")]
    ServerFailure { status: u16 },
    #[error("native CircleCI environment is unavailable")]
    BlockedEnv,
    #[error("CircleCI response was malformed")]
    MalformedResponse,
    #[error("CircleCI access was lost")]
    AccessLost,
    #[error("CircleCI transport is unavailable")]
    TransportUnavailable,
}

/// Typed validation, fence, and proposal failures for the Layer-1 boundary.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CircleCiPipelineResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid CircleCI scope")]
    InvalidScope,
    #[error("invalid CircleCI permission registration")]
    InvalidPermissionRegistration,
    #[error("invalid or revoked CircleCI SecretReference")]
    InvalidSecretReference,
    #[error("CircleCI registration is revoked")]
    RegistrationRevoked,
    #[error("CircleCI registration is reversed")]
    RegistrationReversed,
    #[error("CircleCI registration version, contract, provider, or permission drifted")]
    RegistrationDrift,
    #[error("provider and consumer scopes differ")]
    ScopeMismatch,
    #[error("CircleCI host drifted")]
    HostDrift,
    #[error("CircleCI organization drifted")]
    OrganizationDrift,
    #[error("CircleCI project drifted")]
    ProjectDrift,
    #[error("CircleCI pipeline drifted")]
    PipelineDrift,
    #[error("CircleCI workflow drifted")]
    WorkflowDrift,
    #[error("CircleCI job drifted")]
    JobDrift,
    #[error("CircleCI attempt drifted")]
    AttemptDrift,
    #[error("CircleCI commit drifted")]
    CommitDrift,
    #[error("{resource} revision drifted")]
    RevisionDrift { resource: &'static str },
    #[error("CircleCI permission snapshot drifted")]
    PermissionDrift,
    #[error("CircleCI evidence was replayed")]
    ReplayDetected,
    #[error("CircleCI evidence was tampered")]
    TamperedEvidence,
    #[error("CircleCI evidence was truncated or exceeded a bound")]
    TruncatedEvidence,
    #[error("CircleCI evidence is inaccessible")]
    AccessLost,
    #[error("CircleCI page-token pagination exceeded its bound")]
    PaginationExceeded,
    #[error("CircleCI page token repeated")]
    PageTokenRepeated,
    #[error("CircleCI {resource} evidence is missing")]
    MissingEvidence { resource: &'static str },
    #[error("CircleCI evidence is empty")]
    EmptyEvidence,
    #[error("CircleCI evidence bound exceeded for {resource}")]
    BoundExceeded { resource: &'static str },
    #[error("raw logs or artifact bytes were retained")]
    ForbiddenPayloadRetention,
    #[error("Mission revision drifted")]
    MissionRevisionDrift,
    #[error("Project revision drifted")]
    ProjectRevisionDrift,
    #[error("Work Product revision drifted")]
    WorkProductRevisionDrift,
    #[error("proposal digest mismatch")]
    ProposalMismatch,
    #[error("receipt digest mismatch")]
    ReceiptMismatch,
    #[error("stale or unverifiable evidence")]
    StaleEvidence,
    #[error("empty or unusable evidence cannot become a proposal")]
    EmptyProposalEvidence,
    #[error("provider error: {0}")]
    Provider(#[from] CircleCiProviderError),
}
