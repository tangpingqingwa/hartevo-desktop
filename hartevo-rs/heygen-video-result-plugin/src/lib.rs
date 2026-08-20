//! Layer-1 HeyGen video-result capability for Hartevo.
//!
//! This crate is intentionally standalone and proposal/read/recording-only.
//! It provides typed service, provider, and Mission-consumer boundaries for
//! composing an exact asynchronous video request and evaluating recorded
//! receipts. It does not create a live video, upload or clone an identity,
//! poll a live operation, accept a webhook, download media, persist media, or
//! claim native Connected evidence.

#![forbid(unsafe_code)]

mod canonical;
mod consumer;
mod provider;
mod registration;
mod service;
mod types;

pub use consumer::{AdoptionDecision, AdoptionProposal, ConsumerError, MissionVideoResultConsumer};
pub use provider::{
    ArtifactReceipt, ArtifactReceiptBuilder, AvatarProbeReceipt, BlockedEnvTransport, Capability,
    CapabilityProbeReceipt, FixtureHttpsTransport, FixtureResponse, HeyGenVideoProvider,
    HttpsOperation, HttpsRequest, HttpsRequestResource, HttpsResponse, HttpsTransport,
    IdentityProbeReceipt, LoopbackHttpsTransport, OperationReceipt, ProviderError,
    ProviderErrorKind, ProviderEvidence, ProviderProvenance, ProviderStatus, RecordingExchange,
    RecordingHttpsTransport, StatusReceipt, TemplateProbeReceipt, TransportError, TransportFailure,
    UrlExpiryReceipt,
};
pub use registration::{
    HeyGenVideoResultRegistration, RegistrationError, RegistrationReceipt, RegistrationState,
    RevocationReceipt,
};
pub use service::{HeyGenVideoResultService, ServiceError};
pub use types::{
    AdoptionFingerprint, ArtifactId, ArtifactMetadata, AssetId, AsyncVideoStatus, AvatarId,
    AvatarSelection, CaptionExpectation, ConsentReference, CredentialScope, Digest,
    DurationExpectation, GenerationProposal, GenerationStatusProjection, IdempotencyFence,
    IdentityKind, InputAsset, Locale, MediaType, MediaUrl, MissionId, MissionScope,
    MissionVideoSource, OperationId, PluginVersion, ProjectId, RenderExpectations, Scene,
    ScriptText, SecretReference, SourceDigests, TemplateId, TemplateVariable, TypeError,
    VariableName, VariableValue, VideoDimensions, VideoId, VoiceId, VoiceSelection, WorkspaceId,
};

/// Versioned contract document shipped with the plugin.
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/heygen-video-result/heygen-video-result.v1.json");
/// Stable schema identifier for the Layer-1 contract.
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-heygen-video-result-contract/v1";
/// Stable contract revision for this crate.
pub const CONTRACT_VERSION: &str = "heygen-video-result-layer1/v1";
/// Stable plugin identity.
pub const PLUGIN_ID: &str = "heygen.video.result";
/// Typed service identity.
pub const SERVICE_ID: &str = "video.result.heygen";
/// Typed provider identity.
pub const PROVIDER_ID: &str = "provider.heygen.video-result";
/// Typed Mission consumer identity.
pub const CONSUMER_ID: &str = "mission.video-result.heygen";
/// Layer-1 evidence level. No native Connected claim is made at this level.
pub const EVIDENCE_LEVEL: &str = "L1";

/// Returns the SHA-256 digest of the checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON)
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, EVIDENCE_LEVEL,
        PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_versioned_layer1_and_non_native() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["serviceId"], SERVICE_ID);
        assert_eq!(contract["providerId"], PROVIDER_ID);
        assert_eq!(contract["consumerId"], CONSUMER_ID);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["nativeConnectedClaim"], false);
        assert_eq!(contract["liveGeneration"], false);
        assert_eq!(contract["liveUpload"], false);
        assert_eq!(contract["livePoll"], false);
        assert_eq!(contract["webhookAcceptance"], false);
        assert_eq!(contract["mediaDownload"], false);
        assert_eq!(contract["mediaStore"], false);
        assert!(contract_digest().is_valid());
    }
}
