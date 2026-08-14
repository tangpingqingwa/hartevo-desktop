use thiserror::Error;

/// Construction, scope, proposal, and integrity failures for this Layer-1
/// contract. Error variants intentionally do not carry provider response text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AssemblyAiResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid exact AssemblyAI HTTPS host")]
    InvalidHost,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("invalid exact AssemblyAI/Mission scope")]
    InvalidScope,
    #[error("invalid read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid opaque API-key SecretReference")]
    InvalidSecretReference,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration binding or revision drifted")]
    RegistrationDrift,
    #[error("opaque API-key SecretReference is revoked")]
    SecretRevoked,
    #[error("scope does not match the exact registered scope")]
    ScopeMismatch,
    #[error("duplicate proposal fingerprint")]
    DuplicateProposal,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("provider response is malformed")]
    MalformedResponse,
    #[error("provider response is partial")]
    PartialResponse,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider pagination token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider segment count exceeded its bound")]
    SegmentLimit,
    #[error("provider returned an invalid confidence value")]
    InvalidConfidence,
    #[error("provider returned unredacted content")]
    UnredactedContent,
    #[error("provider segment digest did not match the bounded segment evidence")]
    SegmentMismatch,
    #[error("provider content digest did not match the bounded content evidence")]
    ContentMismatch,
    #[error("provider status changed during one bounded read")]
    StatusMismatch,
    #[error("provider digest was invalid or did not match")]
    DigestMismatch,
    #[error("provider speaker label was invalid or mutated")]
    SpeakerIdentityMismatch,
    #[error("provider evidence was not complete enough for the requested projection")]
    IncompleteEvidence,
}

/// Finite transport classifications for the fixture/recording/loopback seam.
/// No variant stores unbounded response bodies, credentials, or provider error
/// strings.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AssemblyAiTransportError {
    #[error("environment is blocked for native AssemblyAI access")]
    EnvironmentBlocked,
    #[error("AssemblyAI returned HTTP 401 Unauthorized")]
    Unauthorized401,
    #[error("AssemblyAI returned HTTP 403 Forbidden")]
    Forbidden403,
    #[error("AssemblyAI returned HTTP 404 Not Found")]
    NotFound404,
    #[error("AssemblyAI returned HTTP 409 Conflict")]
    Conflict409,
    #[error("AssemblyAI returned HTTP 429 Rate Limited")]
    RateLimited429,
    #[error("AssemblyAI request timed out")]
    Timeout,
    #[error("AssemblyAI returned server HTTP {status}")]
    Server5xx { status: u16 },
    #[error("AssemblyAI access was lost during the read")]
    AccessLost,
    #[error("AssemblyAI response was malformed")]
    MalformedResponse,
    #[error("AssemblyAI response was partial")]
    PartialResponse,
}

impl AssemblyAiTransportError {
    pub fn server(status: u16) -> Option<Self> {
        (500..=599)
            .contains(&status)
            .then_some(Self::Server5xx { status })
    }
}

/// Provider-bound failures keep transport classification separate from exact
/// scope and evidence validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AssemblyAiProviderError {
    #[error("provider registration is invalid: {0}")]
    Registration(#[from] AssemblyAiResultError),
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration is reversed")]
    RegistrationReversed,
    #[error("provider registration drifted")]
    RegistrationDrift,
    #[error("opaque API-key SecretReference is revoked")]
    SecretRevoked,
    #[error("requested scope does not match the exact provider registration")]
    ScopeMismatch,
    #[error("AssemblyAI host drifted")]
    HostDrift,
    #[error("AssemblyAI account drifted")]
    AccountDrift,
    #[error("source identity or revision drifted")]
    SourceDrift,
    #[error("transcript identity or revision drifted")]
    TranscriptDrift,
    #[error("model identity or revision drifted")]
    ModelDrift,
    #[error("transcript configuration drifted")]
    ConfigurationDrift,
    #[error("segment scope or revision drifted")]
    SegmentScopeDrift,
    #[error("Mission identity or revision drifted")]
    MissionDrift,
    #[error("Hartevo Project identity or revision drifted")]
    ProjectDrift,
    #[error("Work Product identity or revision drifted")]
    WorkProductDrift,
    #[error("read permission snapshot drifted")]
    PermissionDrift,
    #[error("provider status changed during one bounded read")]
    StatusDrift,
    #[error("provider returned duplicate segment evidence")]
    DuplicateSegment,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider response was partial")]
    PartialResponse,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider pagination token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider segment count exceeded its bound")]
    SegmentLimit,
    #[error("provider confidence value was invalid")]
    InvalidConfidence,
    #[error("provider evidence was unredacted")]
    UnredactedContent,
    #[error("provider speaker label was invalid or mutated")]
    SpeakerIdentityMismatch,
    #[error("provider segment digest did not match")]
    SegmentMismatch,
    #[error("provider content digest did not match")]
    ContentMismatch,
    #[error("provider status digest did not match")]
    StatusMismatch,
    #[error("provider registration digest did not match")]
    RegistrationDigestMismatch,
    #[error("provider evidence was incomplete")]
    IncompleteEvidence,
    #[error("provider transport failed: {0}")]
    Transport(#[from] AssemblyAiTransportError),
}
