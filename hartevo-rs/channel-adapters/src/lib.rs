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
