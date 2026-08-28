use thiserror::Error;

/// Errors produced by the Layer 1 Firecrawl research-evidence boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FirecrawlResearchEvidenceError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("invalid SHA-256 digest for {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid Firecrawl contract: {reason}")]
    InvalidContract { reason: &'static str },
    #[error("URL refused: {reason}")]
    UrlRefused { reason: &'static str },
    #[error("host is not allowlisted: {host}")]
    HostNotAllowlisted { host: String },
    #[error("URL is not allowlisted: {url}")]
    UrlNotAllowlisted { url: String },
    #[error("login or authentication page is not allowed")]
    LoginPageRefused,
    #[error("subdomain expansion is not allowed")]
    SubdomainExpansionRefused,
    #[error("external-link expansion is not allowed")]
    ExternalLinkExpansionRefused,
    #[error("crawl limit exceeded: {field}")]
    CrawlLimitExceeded { field: &'static str },
    #[error("unsupported Layer 1 content format")]
    UnsupportedContentFormat,
    #[error("content type is not allowed: {content_type}")]
    ContentTypeRefused { content_type: String },
    #[error("content is too large")]
    ContentTooLarge,
    #[error("base64 or media content is not retained")]
    MediaRetentionRefused,
    #[error("stale cache entry")]
    CacheExpired,
    #[error("cache-only request had no cache entry")]
    CacheMiss,
    #[error("request timed out")]
    Timeout,
    #[error("duplicate job")]
    DuplicateJob,
    #[error("request replay detected")]
    ReplayDetected,
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("partial provider response")]
    PartialResponse,
    #[error("page digest mismatch")]
    PageDigestMismatch,
    #[error("job digest mismatch")]
    JobDigestMismatch,
    #[error("content digest mismatch")]
    ContentDigestMismatch,
    #[error("citation mismatch")]
    CitationMismatch,
    #[error("extraction-schema digest mismatch")]
    ExtractionSchemaDigestMismatch,
    #[error("registration digest mismatch")]
    RegistrationDigestMismatch,
    #[error("permission digest mismatch")]
    PermissionDigestMismatch,
    #[error("stale Mission revision: expected {expected}, got {actual}")]
    StaleMissionRevision { expected: u64, actual: u64 },
    #[error("stale Project revision: expected {expected}, got {actual}")]
    StaleProjectRevision { expected: u64, actual: u64 },
    #[error("stale Work Product revision: expected {expected}, got {actual}")]
    StaleWorkProductRevision { expected: u64, actual: u64 },
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("provider access was lost")]
    AccessLost,
    #[error("job status is not source evidence: {status}")]
    StatusNotSourceEvidence { status: String },
    #[error("proposal cannot be adopted by Layer 1")]
    AdoptionForbidden,
    #[error("provider error: {0}")]
    Provider(#[from] FirecrawlProviderError),
    #[error("credential error: {0}")]
    Credential(#[from] FirecrawlCredentialError),
    #[error("transport error: {0}")]
    Transport(#[from] FirecrawlTransportError),
}

/// Typed upstream HTTP and job failures. Response bodies never enter this
/// error type.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FirecrawlProviderError {
    #[error("unauthorized ({status})")]
    Unauthorized { status: u16 },
    #[error("forbidden ({status})")]
    Forbidden { status: u16 },
    #[error("not found ({status})")]
    NotFound { status: u16 },
    #[error("conflict ({status})")]
    Conflict { status: u16 },
    #[error("rate limited ({status})")]
    RateLimited {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("server failure ({status})")]
    ServerFailure { status: u16 },
    #[error("provider returned an unsupported HTTP status ({status})")]
    UnexpectedStatus { status: u16 },
    #[error("credential resolution is blocked by the environment")]
    BlockedEnv,
    #[error("API-key SecretReference is required")]
    SecretReferenceRequired,
    #[error("API-key SecretReference is invalid")]
    InvalidSecretReference,
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider returned an unknown job status")]
    ProviderUnknown,
    #[error("duplicate provider job")]
    DuplicateJob,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider response was partial")]
    PartialResponse,
    #[error("provider returned an unacceptable content type")]
    ContentTypeRefused,
    #[error("provider response was stale")]
    CacheExpired,
    #[error("provider request timed out")]
    Timeout,
}

impl FirecrawlProviderError {
    /// Return the HTTP status when this error came from an HTTP response.
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized { status }
            | Self::Forbidden { status }
            | Self::NotFound { status }
            | Self::Conflict { status }
            | Self::RateLimited { status, .. }
            | Self::ServerFailure { status }
            | Self::UnexpectedStatus { status } => Some(*status),
            _ => None,
        }
    }

    /// Map a Firecrawl HTTP status without retaining its response body.
    pub fn from_status(status: u16, retry_after_seconds: Option<u64>) -> Self {
        match status {
            401 => Self::Unauthorized { status },
            403 => Self::Forbidden { status },
            404 => Self::NotFound { status },
            409 => Self::Conflict { status },
            429 => Self::RateLimited {
                status,
                retry_after_seconds,
            },
            500 | 502 | 503 | 504 => Self::ServerFailure { status },
            _ => Self::UnexpectedStatus { status },
        }
    }
}

/// Errors from the local transport seam.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FirecrawlTransportError {
    #[error("transport timed out")]
    Timeout,
    #[error("transport unavailable")]
    Unavailable,
    #[error("transport returned a malformed fixture")]
    Malformed,
    #[error("transport failure")]
    Failed,
}

/// Errors from the host-owned credential-resolution seam.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FirecrawlCredentialError {
    #[error("environment does not provide a credential")]
    BlockedEnv,
    #[error("SecretReference is not available")]
    Unavailable,
    #[error("SecretReference scope does not match")]
    ScopeMismatch,
    #[error("SecretReference revision is stale")]
    RevisionMismatch,
}

/// Operation names used by typed provider/transport diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirecrawlOperationKind {
    DescribeUrl,
    DescribeJob,
    Scrape,
    Crawl,
    CrawlStatus,
    CompileProposal,
    RecordReceipt,
    VerifyEvidence,
}
