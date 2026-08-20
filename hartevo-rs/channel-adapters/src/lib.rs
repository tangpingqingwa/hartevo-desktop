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
    DraftVideoPublishRequest, MissionYouTubePublishConsumer, YOUTUBE_PUBLISH_PLUGIN_ID,
    YOUTUBE_PUBLISH_PLUGIN_REVISION, YouTubeAccountId, YouTubeApprovalRevision,
    YouTubeAssetDescriptor, YouTubeAssetDigest, YouTubeAuthenticatedProbe,
    YouTubeAuthorizedPublishEffect, YouTubeBusinessId, YouTubeChannelId, YouTubeCredential,
    YouTubeCredentialInvalidationReason, YouTubeDataApiProvider, YouTubeDispatchOperation,
    YouTubeEffectId, YouTubeError, YouTubeEvidenceId, YouTubeEvidenceProvenance, YouTubeHttpMethod,
    YouTubeIdempotencyKey, YouTubeMissionAcceptedPublish, YouTubeOAuthScope, YouTubePluginIdentity,
    YouTubeProductionTransport, YouTubeProviderId, YouTubeProviderReceipt, YouTubeProviderRequest,
    YouTubeProviderResponse, YouTubePublishBinding, YouTubePublishCheckpoint,
    YouTubePublishDispatchResult, YouTubePublishOutcomeEvidence, YouTubePublishPhase,
    YouTubePublishReceiptEvidence, YouTubePublishService, YouTubePublishTransport,
    YouTubePublishVerificationCheckpoint, YouTubePublishVerificationDispatchResult,
    YouTubePublishVerificationEvidence, YouTubePublishVerificationPhase,
    YouTubePublishVerificationService, YouTubePublishedVideo, YouTubeQuotaBucket,
    YouTubeQuotaLedger, YouTubeReadbackReceipt, YouTubeRealPublishGate,
    YouTubeReconciliationReason, YouTubeReconciliationReceipt, YouTubeRetryAfterReceipt,
    YouTubeSchedule, YouTubeTenantId, YouTubeUploadProgress, YouTubeUploadSessionReference,
    YouTubeVerificationInvalidationReason, YouTubeVerificationStatus, YouTubeVideoId,
    YouTubeVideoProcessingState, YouTubeVisibility, execute_real_publish_gate,
    execute_real_publish_verification_gate,
};
