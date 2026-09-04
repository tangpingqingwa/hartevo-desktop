//! Provider-specific read-only channel adapter contracts.
//!
//! The TikTok plugin keeps its independent authenticated-read service,
//! provider, and Mission consumer boundary while sharing the bootstrap
//! crate's YouTube read-only root. No module here owns credentials,
//! persistence, Effect authority, or a central connector registry.

#![forbid(unsafe_code)]

pub mod identity;
pub mod testkit;
pub mod tiktok;
pub mod transport;
pub mod youtube;
pub mod youtube_read;
pub mod youtube_sync;

pub use identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, ProviderId, RevisionIdentity,
};

pub use tiktok::{
    BusinessId, DEFAULT_VIDEO_PAGE_SIZE, EvidenceProvenance, MAX_VIDEO_SEQUENCE_PAGES,
    MissionTiktokReadConsumer, OAuthCredential, SecretReference, TenantId, TiktokAccountId,
    TiktokAccountIdentity, TiktokApiOperation, TiktokAuthenticatedReadService,
    TiktokConnectionState, TiktokCursor, TiktokCursorDisposition, TiktokCursorInvalidationReason,
    TiktokCursorLifecycle, TiktokDisplayApiProvider, TiktokError, TiktokFreshness,
    TiktokFreshnessPolicy, TiktokMissionAcceptedRead, TiktokMissionAcceptedSequence,
    TiktokOAuthScope, TiktokObservationEnvelope, TiktokPageSequence,
    TiktokProviderResetObservation, TiktokQuotaLedger, TiktokReadObservation, TiktokReadScope,
    TiktokRealReadGate, TiktokRetryAfterReceipt, TiktokRevisionIdentity, TiktokVideoId,
    TiktokVideoListCursor, TiktokVideoObservation, TiktokVideoPageEnvelope, execute_real_read_gate,
};
pub use transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderKind,
    ProviderReadRequest, ProviderResponse, ReadOnlyTransport, ReadOperation, ScopeName,
    TransportError,
};
