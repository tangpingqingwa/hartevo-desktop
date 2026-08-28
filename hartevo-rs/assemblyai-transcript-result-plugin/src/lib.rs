//! Standalone Layer-1 AssemblyAI transcript-result boundary.
//!
//! This crate stops at bounded, redacted provider evidence plus a proposal and
//! recording seam for the next Mission decision. It deliberately has no live
//! HTTP client, audio upload or fetch, raw transcript retention, API-key
//! resolution, durable receipt, independent readback, or Work Product adoption
//! authority.

#![forbid(unsafe_code)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionTranscriptResultConsumer, ProposalDisposition, RecordedTranscriptProposal,
    TranscriptProposalRecording, TranscriptWorkProductProposal,
};
pub use error::{AssemblyAiProviderError, AssemblyAiResultError, AssemblyAiTransportError};
pub use model::{
    AccountId, AssemblyAiHost, AssemblyAiPermissionSnapshot, AssemblyAiProviderIdentity,
    AssemblyAiScope, AssemblyAiTranscriptResultScope, ChapterMetadata, ConfidenceSummary, ConfigId,
    ConfigurationProjection, Digest, MissionId, MissionReference, ModelId, ModelProjection,
    ModelRevision, PermissionRevision, PluginVersion, ProjectId, ProjectReference,
    ProviderUnknownStatus, RedactionState, RegistrationId, RegistrationReceipt, RegistrationState,
    SecretKind, SecretReference, SegmentId, SegmentScope, SourceId, SourceReference,
    SummaryMetadata, TranscriptConfigRevision, TranscriptId, TranscriptLanguage,
    TranscriptPageToken, TranscriptReference, TranscriptResultProjection,
    TranscriptStatusProjection, TransportProvenance, UtteranceEvidence, WorkProductId,
    WorkProductReference, canonical_digest, content_digest_for, evidence_digest_for,
    segment_digest_for,
};
pub use provider::{
    AssemblyAiCredentialResolver, AssemblyAiProvider, AssemblyAiProviderState,
    BlockedEnvCredentialResolver, ProviderScopeDescription, StaticApiKeyCredentialResolver,
};
pub use service::{
    AssemblyAiRegistration, AssemblyAiRegistrationRegistry, AssemblyAiTranscriptResultService,
    CapabilityDescription,
};
pub use transport::{
    AssemblyAiTransport, AssemblyAiTransportOperation, BlockedEnvTransport, FakeTransport,
    LoopbackTransport, RawChapter, RawSummary, RawTranscriptPage, RawTranscriptSnapshot,
    RawUtterance, RecordingTransport, SecretMaterial, TranscriptFixture, TranscriptReadRequest,
    TransportOutcome,
};

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.assemblyai-transcript-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-ASSEMBLYAI-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.assemblyai-transcript-result/v1|layer=1|service=AssemblyAiTranscriptResultService|provider=AssemblyAiProvider|consumer=MissionTranscriptResultConsumer";
pub const CONTRACT_DIGEST: &str =
    "39de9b885997882419b227b70910ddc0ccedb6a9a54fe9c90654bd830eeebb40";
pub const PLUGIN_ID: &str = "assemblyai.transcript-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const SERVICE_ID: &str = "assemblyai.transcript-result.read";
pub const PROVIDER_ID: &str = "assemblyai.transcript-result.recording";
pub const PROVIDER_API_REVISION: &str = "assemblyai-transcript-result-read-1";
pub const CONSUMER_ID: &str = "mission.assemblyai-transcript-result.consumer";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/assemblyai-transcript-result/assemblyai-transcript-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGES: usize = 16;
pub const MAX_SEGMENTS: usize = 512;
pub const MAX_CHAPTERS: usize = 32;
pub const MAX_SUMMARY_METADATA_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;

/// The checked-in contract digest is bound to the stable contract identity
/// input, not to a self-referential JSON file hash.
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Layer 1 capabilities are descriptive and never grant native execution.
pub fn capabilities() -> CapabilityDescription {
    CapabilityDescription::layer1()
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA_VERSION,
        CONTRACT_VERSION, capabilities, contract_digest,
    };

    #[test]
    fn checked_in_contract_is_layer_one_and_read_only() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["contractDigestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract["layer"], 1);
        assert_eq!(
            contract["service"]["access"],
            "read_proposal_recording_only"
        );
        assert_eq!(contract["authority"]["kernel"], false);
        assert_eq!(contract["authority"]["externalWrite"], false);
        assert_eq!(contract["authority"]["workProductAdoption"], false);
        assert_eq!(contract["provenance"]["connectedClaim"], false);
        assert_eq!(contract["provenance"]["nativeClaim"], false);
        assert_eq!(contract["provenance"]["firstPartyClaim"], false);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
    }

    #[test]
    fn capability_description_has_no_native_or_write_authority() {
        let capability = capabilities();
        assert!(capability.read_only);
        assert!(capability.can_read_transcript);
        assert!(capability.can_propose_work_product);
        assert!(capability.can_record_proposal);
        assert!(!capability.connected);
        assert!(!capability.native);
        assert!(!capability.first_party);
        assert!(!capability.can_upload_audio);
        assert!(!capability.can_fetch_arbitrary_media);
        assert!(!capability.can_submit_transcript);
        assert!(!capability.can_poll_transcript);
        assert!(!capability.can_adopt_work_product);
        assert!(!capability.can_adopt_outcome);
        assert!(!capability.external_write);
    }
}
