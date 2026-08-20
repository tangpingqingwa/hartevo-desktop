//! Standalone Layer-1 Deepgram transcript-result boundary.
//!
//! The crate stops at bounded, redacted provider evidence and a review-only
//! Mission proposal. It deliberately has no live HTTP client, audio/media
//! authority, raw transcript retention, credential resolution, durable native
//! receipt, independent readback, or Work Product/Outcome adoption authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::float_cmp)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    DeepgramProposalDisposition, DeepgramTranscriptProposalRecording,
    DeepgramTranscriptResultObservation, DeepgramTranscriptResultProposal,
    MissionDeepgramTranscriptConsumer, MissionDeepgramTranscriptResult,
};
pub use error::{DeepgramProviderError, DeepgramResultError, DeepgramTransportError};
pub use model::{
    AudioFingerprint, ConsentId, ConsentReference, DeepgramHost, DeepgramLanguageIndicator,
    DeepgramModelFeatures, DeepgramModelProjection, DeepgramModelRevision, DeepgramPageToken,
    DeepgramProjectId, DeepgramProjectReference, DeepgramProviderIdentity,
    DeepgramQualityIndicators, DeepgramRequestReference, DeepgramScope, DeepgramTranscriptMetadata,
    DeepgramTranscriptResultEvidence, DeepgramTranscriptResultScope, DeepgramUtteranceWindow,
    Digest, LanguageCode, MissionId, MissionReference, ModelId, PluginVersion, ProjectId,
    ProjectReference, ProviderProjectId, RedactionState, RegistrationId, RegistrationReceipt,
    RegistrationState, RequestId, RequestOperation, SecretKind, SecretReference, SegmentEvidence,
    SegmentId, TranscriptStatus, TransportProvenance, WorkProductId, WorkProductReference,
    canonical_digest, content_digest_for, evidence_digest_for, segment_digest_for,
};
pub use provider::{
    BlockedEnvCredentialResolver, DeepgramCredentialResolver, DeepgramProvider,
    DeepgramProviderScopeDescription, DeepgramProviderState, DeepgramRetryPolicy,
    StaticApiKeyCredentialResolver,
};
pub use service::{
    CapabilityDescription, DeepgramRegistration, DeepgramRegistrationRegistry,
    DeepgramTranscriptResultService,
};
pub use transport::{
    BlockedEnvTransport, DeepgramReadRequest, DeepgramTransport, DeepgramTransportOperation,
    FakeTransport, FixtureTransport, LoopbackTransport, RawSegment, RawTranscriptPage,
    RawTranscriptSnapshot, RecordingTransport, SecretMaterial, TranscriptFixture,
};

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.deepgram-transcript-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-DEEPGRAM-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.deepgram-transcript-result/v1|layer=1|service=DeepgramTranscriptResultService|provider=DeepgramProvider|consumer=MissionDeepgramTranscriptConsumer";
pub const CONTRACT_DIGEST: &str =
    "9c8819bdd54f0933d81f7769e7d39a6ed1dcfe5f6ba1f8c08caba056b09e14cf";
pub const PLUGIN_ID: &str = "deepgram.transcript-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const SERVICE_ID: &str = "deepgram.transcript-result.read";
pub const PROVIDER_ID: &str = "deepgram.transcript-result.listen";
pub const PROVIDER_API_REVISION: &str = "deepgram-listen-pre-recorded-read-1";
pub const CONSUMER_ID: &str = "mission.deepgram-transcript-result.consumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_WINDOW_PAGES: usize = 16;
pub const MAX_UTTERANCE_SEGMENTS: usize = 512;
pub const MAX_BACKOFF_SECONDS: u32 = 30;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;

/// The contract digest is derived from a stable identity input rather than a
/// self-referential JSON file hash.
#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/deepgram-transcript-result/deepgram-transcript-result.v1.json"
);

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, PROVIDER_ID, contract_digest,
    };

    #[test]
    fn checked_in_contract_is_layer_one_and_fully_non_native() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["contractDigestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract["layer"], 1);
        assert_eq!(
            contract["typedSurface"]["service"],
            "DeepgramTranscriptResultService"
        );
        assert_eq!(contract["typedSurface"]["provider"], "DeepgramProvider");
        assert_eq!(
            contract["typedSurface"]["consumer"],
            "MissionDeepgramTranscriptConsumer"
        );
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["rawAudioRetention"], false);
        assert_eq!(contract["authority"]["rawTranscriptRetention"], false);
        assert_eq!(contract["nativeGap"]["status"], BLOCKED_ENV);
        assert!(!contract_digest().as_str().is_empty());
    }
}
