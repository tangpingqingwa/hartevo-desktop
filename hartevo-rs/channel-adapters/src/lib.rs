//! YouTube read-only channel contracts plus the controlled publish adapter.
//!
//! The publish vertical stops at a provider-specific dispatch/readback
//! boundary. It does not depend on, implement, or grant Effect authority.
//! The protected bootstrap read-only identity and transport contracts remain
//! available to the YouTube read service and Mission consumer.

#![forbid(unsafe_code)]

pub mod identity;
pub mod testkit;
pub mod transport;
#[path = "youtube/mod.rs"]
pub mod youtube;
pub mod youtube_read;

pub use identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, ProviderId, RevisionIdentity,
};
pub use transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOnlyTransport, ReadOperation, ScopeName, TransportError,
    YouTubeSecretReference,
};

pub use youtube::{
    DraftVideoPublishRequest, MissionYouTubePublishConsumer, YouTubeAccountId,
    YouTubeApprovalRevision, YouTubeAssetDescriptor, YouTubeAssetDigest, YouTubeAuthenticatedProbe,
    YouTubeBusinessId, YouTubeChannelId, YouTubeCredential, YouTubeCredentialInvalidationReason,
    YouTubeDataApiProvider, YouTubeDispatchOperation, YouTubeError, YouTubeEvidenceProvenance,
    YouTubeHttpMethod, YouTubeIdempotencyKey, YouTubeMissionAcceptedPublish, YouTubeOAuthScope,
    YouTubeProductionTransport, YouTubeProviderId, YouTubeProviderReceipt, YouTubeProviderRequest,
    YouTubeProviderResponse, YouTubePublishBinding, YouTubePublishCheckpoint,
    YouTubePublishDispatchResult, YouTubePublishPhase, YouTubePublishService,
    YouTubePublishTransport, YouTubePublishedVideo, YouTubeQuotaBucket, YouTubeQuotaLedger,
    YouTubeReadbackReceipt, YouTubeRealPublishGate, YouTubeReconciliationReason,
    YouTubeReconciliationReceipt, YouTubeRetryAfterReceipt, YouTubeSchedule, YouTubeTenantId,
    YouTubeUploadProgress, YouTubeUploadSessionReference, YouTubeVideoId,
    YouTubeVideoProcessingState, YouTubeVisibility, execute_real_publish_gate,
};
