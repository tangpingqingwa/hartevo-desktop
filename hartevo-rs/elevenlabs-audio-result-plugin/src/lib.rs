//! Layer-1 ElevenLabs audio-result capability for Hartevo.
//!
//! This crate is intentionally standalone and proposal/read/recording-only.
//! It binds exact text, voice, model, language, format, configuration, host,
//! Mission, Project, and Work Product scope to bounded status, usage, and
//! digest evidence. It does not synthesize live audio, accept or retain raw
//! audio bytes, clone or delete voices, expose API-key material, poll a live
//! operation, perform external writes, or claim native Connected evidence.

#![forbid(unsafe_code)]

mod canonical;
mod consumer;
mod provider;
mod registration;
mod service;
mod types;

pub use consumer::{
    AdoptionDecision, AdoptionProposal, AudioWorkProductProposal, ConsumerError,
    MissionAudioResultConsumer,
};
pub use provider::{
    AudioContentEvidence, AudioStatus, AudioStatusProjection, BlockedEnvTransport,
    ElevenLabsProvider, FixtureHttpsTransport, FixtureResponse, GenerationStatusProjection,
    HttpsOperation, HttpsRequest, HttpsResponse, HttpsTransport, LoopbackHttpsTransport,
    ProviderError, ProviderErrorKind, ProviderEvidence, ProviderProvenance, ProviderStatus,
    RecordedSynthesis, RecordingExchange, RecordingHttpsTransport, RedactionState, StatusReceipt,
    SynthesisReceipt, SynthesisResponse, SynthesisStatus, TransportError, TransportFailure,
    UsageEvidence,
};
pub use registration::{
    ElevenLabsAudioResultRegistration, RegistrationError, RegistrationReceipt, RegistrationState,
    RevocationReceipt,
};
pub use service::{ElevenLabsAudioResultService, ServiceError};
pub use types::{
    ApiHost, AudioConfig, AudioCreationObjective, AudioGenerationProposal, AudioObjective, Digest,
    IdempotencyFence, LanguageCode, MAX_AUDIO_DURATION_MILLISECONDS, MAX_RECORDED_USAGE_CHARACTERS,
    MAX_TEXT_CHARACTERS, MissionId, MissionScope, ModelId, ModelSelection, ObjectiveId,
    OperationId, OutputFormat, PluginVersion, ProjectId, ProjectScope, ScriptText, SecretReference,
    SynthesisBinding, TextNormalization, TypeError, VoiceId, VoiceSelection, VoiceSettings,
    WorkProductId, WorkProductScope, WorkspaceId,
};

/// Versioned contract document shipped with the plugin.
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/elevenlabs-audio-result/elevenlabs-audio-result.v1.json"
);
/// Stable schema identifier for the Layer-1 contract.
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-elevenlabs-audio-result-contract/v1";
/// Stable contract revision for this crate.
pub const CONTRACT_VERSION: &str = "elevenlabs-audio-result-layer1/v1";
/// Stable plugin identity.
pub const PLUGIN_ID: &str = "elevenlabs.audio.result";
/// Typed service identity.
pub const SERVICE_ID: &str = "audio.result.elevenlabs";
/// Typed provider identity.
pub const PROVIDER_ID: &str = "provider.elevenlabs.audio-result";
/// Typed Mission consumer identity.
pub const CONSUMER_ID: &str = "mission.audio-result.elevenlabs";
/// Official API host bound by every scope.
pub const OFFICIAL_HOST: &str = "https://api.elevenlabs.io";
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
        OFFICIAL_HOST, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
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
        assert_eq!(contract["officialHost"], OFFICIAL_HOST);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["nativeConnectedClaim"], false);
        assert_eq!(contract["liveSynthesis"], false);
        assert_eq!(contract["liveStatusPolling"], false);
        assert_eq!(contract["voiceClone"], false);
        assert_eq!(contract["voiceDelete"], false);
        assert_eq!(contract["modelRegistry"], false);
        assert_eq!(contract["rawAudioAccepted"], false);
        assert_eq!(contract["rawAudioRetained"], false);
        assert_eq!(contract["rawAudioDownloaded"], false);
        assert_eq!(contract["externalWrite"], false);
        assert_eq!(contract["durableWorkProductAdoption"], false);
        assert!(contract_digest().is_valid());
    }
}
