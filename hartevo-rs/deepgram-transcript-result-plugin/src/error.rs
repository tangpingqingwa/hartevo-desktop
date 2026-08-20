use thiserror::Error;

/// Construction, scope, registration, proposal, and evidence failures. These
/// variants intentionally carry no provider payload or credential material.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeepgramResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid exact Deepgram HTTPS host")]
    InvalidHost,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("invalid exact transcript-result scope")]
    InvalidScope,
    #[error("invalid consent reference")]
    InvalidConsent,
    #[error("invalid opaque SecretReference")]
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
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("scope or consent does not match the exact registration")]
    ScopeMismatch,
    #[error("duplicate proposal digest")]
    DuplicateProposal,
    #[error("idempotency key was replayed with different evidence")]
    IdempotencyConflict,
    #[error("invalid redacted proposal")]
    InvalidProposal,
    #[error("provider response was malformed or tampered")]
    Tamper,
    #[error("provider response was partial")]
    Partial,
    #[error("provider response was expired")]
    Expired,
    #[error("provider denied the bounded read")]
    Denied,
    #[error("provider rate limit exceeded")]
    RateLimited,
    #[error("provider returned an unknown status")]
    ProviderUnknown,
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
    #[error("provider returned unredacted transcript evidence")]
    UnredactedContent,
    #[error("provider segment digest did not match bounded evidence")]
    SegmentMismatch,
    #[error("provider content digest did not match bounded evidence")]
    ContentMismatch,
    #[error("provider status changed during one bounded read")]
    StatusDrift,
    #[error("provider metadata revision changed during one bounded read")]
    RevisionDrift,
    #[error("provider evidence digest did not match")]
    DigestMismatch,
    #[error("duplicate segment evidence")]
    DuplicateSegment,
}

/// Finite transport classifications used by fixture, recording, fake,
/// loopback, and BLOCKED_ENV seams. No variant stores raw response text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeepgramTransportError {
    #[error("environment is blocked for native Deepgram access")]
    EnvironmentBlocked,
    #[error("Deepgram denied the request with HTTP 401")]
    Unauthorized401,
    #[error("Deepgram denied the request with HTTP 403")]
    Forbidden403,
    #[error("Deepgram returned HTTP 404 Not Found")]
    NotFound404,
    #[error("Deepgram returned HTTP 409 Conflict")]
    Conflict409,
    #[error("Deepgram returned HTTP 429 Rate Limited")]
    RateLimited { retry_after_seconds: u32 },
    #[error("Deepgram request timed out")]
    Timeout,
    #[error("Deepgram returned server HTTP {status}")]
    Server5xx { status: u16 },
    #[error("Deepgram result expired")]
    Expired,
    #[error("Deepgram access was lost")]
    AccessLost,
    #[error("Deepgram response was malformed")]
    MalformedResponse,
    #[error("Deepgram response was partial")]
    PartialResponse,
}

impl DeepgramTransportError {
    #[must_use]
    pub fn server(status: u16) -> Option<Self> {
        (500..=599)
            .contains(&status)
            .then_some(Self::Server5xx { status })
    }

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u32> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            _ => None,
        }
    }
}

/// Provider-bound failures keep transport classification separate from exact
/// scope, revision, redaction, and digest validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeepgramProviderError {
    #[error("provider registration is invalid: {0}")]
    Registration(#[from] DeepgramResultError),
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration is reversed")]
    RegistrationReversed,
    #[error("provider registration drifted")]
    RegistrationDrift,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("requested scope does not match exact registration")]
    ScopeMismatch,
    #[error("Deepgram host drifted")]
    HostDrift,
    #[error("Deepgram project drifted")]
    ProjectDrift,
    #[error("request identity or revision drifted")]
    RequestDrift,
    #[error("model identity or revision drifted")]
    ModelDrift,
    #[error("audio fingerprint drifted")]
    AudioFingerprintDrift,
    #[error("utterance window drifted")]
    UtteranceWindowDrift,
    #[error("Hartevo Project drifted")]
    HartevoProjectDrift,
    #[error("Mission drifted")]
    MissionDrift,
    #[error("Work Product drifted")]
    WorkProductDrift,
    #[error("consent drifted")]
    ConsentDrift,
    #[error("provider status changed during one bounded read")]
    StatusDrift,
    #[error("provider metadata revision changed during one bounded read")]
    RevisionDrift,
    #[error("provider returned duplicate segment evidence")]
    DuplicateSegment,
    #[error("provider response was malformed or tampered")]
    Tamper,
    #[error("provider response was partial")]
    Partial,
    #[error("provider response was expired")]
    Expired,
    #[error("provider denied the bounded read")]
    Denied,
    #[error("provider rate limit remained after bounded retries")]
    RateLimited {
        retry_after_seconds: u32,
        attempts: u8,
    },
    #[error("provider returned an unknown status")]
    ProviderUnknown,
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
    Transport(#[from] DeepgramTransportError),
}
