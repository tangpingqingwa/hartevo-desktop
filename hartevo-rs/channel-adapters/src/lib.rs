//! YouTube controlled publish effect plugin.
//!
//! This standalone package deliberately stops at a provider-specific
//! dispatch/readback boundary. It does not depend on, implement, or grant
//! Effect authority. Callers provide an already-approved draft, an opaque
//! credential reference, and a transport that owns the actual authenticated
//! YouTube HTTP client.

#![forbid(unsafe_code)]

pub mod transport;
pub mod youtube;

pub use transport::{TransportError, YouTubeSecretReference};
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
