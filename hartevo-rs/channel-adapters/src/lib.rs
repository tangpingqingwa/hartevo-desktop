//! TikTok authenticated read plugin.
//!
//! This package is intentionally self-contained on the bootstrap branch. It
//! exposes an official TikTok Display API provider boundary, an authenticated
//! read service, and a fail-closed Mission consumer. OAuth tokens never enter
//! this package: callers pass an opaque [`SecretReference`] that an external
//! credential service resolves at dispatch time.

#![forbid(unsafe_code)]

pub mod tiktok;
pub mod transport;

pub use tiktok::{
    BusinessId, DEFAULT_VIDEO_PAGE_SIZE, EvidenceProvenance, MissionTiktokReadConsumer,
    OAuthCredential, ProviderId, SecretReference, TenantId, TiktokAccountId, TiktokAccountIdentity,
    TiktokApiOperation, TiktokAuthenticatedReadService, TiktokConnectionState, TiktokCursor,
    TiktokCursorDisposition, TiktokDisplayApiProvider, TiktokError, TiktokFreshness,
    TiktokFreshnessPolicy, TiktokMissionAcceptedRead, TiktokOAuthScope, TiktokObservationEnvelope,
    TiktokQuotaLedger, TiktokReadObservation, TiktokReadScope, TiktokRealReadGate,
    TiktokRevisionIdentity, TiktokVideoId, TiktokVideoListCursor, TiktokVideoObservation,
    TiktokVideoPageEnvelope,
};
pub use transport::{
    HttpMethod, ProviderReadRequest, ProviderResponse, ReadOnlyTransport, ScopeName, TransportError,
};
