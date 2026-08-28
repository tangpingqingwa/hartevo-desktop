//! Standalone Layer-1 Dovetail customer-research result boundary.
//!
//! The crate owns exact version/provider/workspace/project/folder/data/Mission/
//! Work Product/Consent scope, bounded metadata-only GET plans, redacted
//! provider projections, review-only proposals, and local idempotent
//! recordings. It does not resolve a Dovetail token, retain research bodies,
//! access transcripts or media, perform writes/exports/webhooks, or assert
//! Connected/native/provider-truth authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::return_self_not_must_use,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unused_self
)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{
    DovetailMissionResearchResult, DovetailResearchProposal, DovetailResearchRecording,
    DovetailResearchRecordingLog, MissionDovetailResearchConsumer, ProposalDisposition,
};
pub use error::{
    DovetailProviderError, DovetailResearchResultError, DovetailTransportError, Result,
};
pub use model::{
    ConsentDataClass, ConsentId, ConsentScope, DOVETAIL_API_BASE_URL, DOVETAIL_DATA_PATH,
    DOVETAIL_DOCS_PATH, DOVETAIL_FOLDERS_PATH, DOVETAIL_HIGHLIGHTS_PATH, DOVETAIL_INSIGHTS_PATH,
    DOVETAIL_PROJECTS_PATH, DOVETAIL_SECRET_REFERENCE_ENV, DOVETAIL_TAGS_PATH, DataContentKind,
    DataId, DataPointMetadata, Digest, DocId, DocumentMetadata, DovetailDataScope,
    DovetailFolderBinding, DovetailPermissionSnapshot, DovetailProjectBinding, DovetailProjectId,
    DovetailProviderIdentity, DovetailReadBounds, DovetailReadOperation, DovetailReadPermission,
    DovetailResearchObservation, DovetailResearchReadRequest, DovetailResearchScope,
    DovetailWorkspaceBinding, FolderBinding, FolderId, HartevoProjectBinding, HartevoProjectId,
    HighlightId, HighlightSummary, InsightId, InsightMetadata, MAX_BACKOFF_MS, MAX_CURSOR_BYTES,
    MAX_DATA_IDS, MAX_IDENTIFIER_BYTES, MAX_ITEMS_PER_OPERATION, MAX_PAGE_SIZE,
    MAX_PAGES_PER_OPERATION, MAX_RESPONSE_BYTES, MAX_RETRIES, MissionBinding, MissionId,
    MissionScope, ObservationCompleteness, ObservationCounts, PluginVersion, ProjectBinding,
    ProjectId, ProjectMetadata, ResearchEvidenceState, ResearchTimeWindow, RevisionDigests,
    SecretKind, SecretReference, TagId, ThemeSummary, TransportProvenance, WorkProductBinding,
    WorkProductId, WorkProductScope, WorkspaceBinding, WorkspaceId,
};
pub use provider::{
    BlockedEnvDovetailTransport, DovetailFixtureTransport, DovetailGetRequest, DovetailHttpMethod,
    DovetailLoopbackTransport, DovetailProvider, DovetailRecordingTransport, DovetailTransport,
    DovetailTransportResponse, FixtureTransport, LoopbackTransport, RecordingTransport,
};
pub use service::{
    DovetailRegistration, DovetailRegistrationRegistry, DovetailRegistrationStatus,
    DovetailResearchResultService, DovetailResearchResultServiceDefinition,
    DovetailResearchResultServiceOperation, RegistrationReceipt,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.dovetail-research-result-contract/v1";
pub const CONTRACT_VERSION: &str = "EXT-DOVETAIL-01-L1/v1";
pub const PLUGIN_ID: &str = "dovetail.research-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const SERVICE_ID: &str = "DovetailResearchResultService";
pub const PROVIDER_ID: &str = "DovetailProvider";
pub const CONSUMER_ID: &str = "MissionDovetailResearchConsumer";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/dovetail-research-result/dovetail-research-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON.as_bytes())
}

/// Layer-1 authority is intentionally metadata-read, proposal, and local
/// recording only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn export_or_download() -> bool {
        false
    }

    pub const fn webhooks() -> bool {
        false
    }

    pub const fn transcripts() -> bool {
        false
    }

    pub const fn media() -> bool {
        false
    }

    pub const fn participant_pii() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION,
        PROVIDER_ID, ReadOnlyAuthority, SERVICE_ID, contract_digest,
    };

    #[test]
    fn versioned_contract_is_layer_one_and_redaction_safe() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("Dovetail contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginVersion"], PLUGIN_VERSION.to_string());
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["service"]["providerId"], PROVIDER_ID);
        assert_eq!(contract["service"]["consumerId"], CONSUMER_ID);
        assert_eq!(contract["provider"]["connected"], false);
        assert_eq!(contract["provider"]["native"], false);
        assert_eq!(contract["redaction"]["transcripts"], false);
        assert_eq!(contract["redaction"]["audioVideoMedia"], false);
        assert_eq!(contract["redaction"]["participantNames"], false);
        assert_eq!(contract["redaction"]["participantContactData"], false);
        assert_eq!(contract["redaction"]["rawNotes"], false);
        assert_eq!(contract["redaction"]["comments"], false);
        assert_eq!(contract["redaction"]["freeFormInsightBodies"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["exportOrDownload"], false);
        assert_eq!(contract["authority"]["webhooks"], false);
        assert_eq!(contract["authority"]["kernelAuthority"], false);
        assert_eq!(contract["nativeGap"]["status"], "BLOCKED_ENV");
        assert_eq!(contract["nativeGap"]["fixtureConnected"], false);
        assert_eq!(contract["nativeGap"]["recordingNative"], false);
        assert_eq!(contract["nativeGap"]["loopbackConnected"], false);
        assert_eq!(contract["nativeGap"]["blockedEnvNative"], false);
        assert_eq!(contract["reads"]["method"], "GET");
        assert_eq!(contract["reads"]["arbitraryPath"], false);
        assert_eq!(contract["reads"]["arbitraryQuery"], false);
        assert_eq!(contract["reads"]["maxPageSize"], 100);
        assert_eq!(contract["reads"]["maxPagesPerOperation"], 8);
        assert_eq!(contract["reads"]["maxRetries"], 3);
        assert_eq!(contract["scope"]["digestBound"], true);
        assert_eq!(contract["scope"]["consentBound"], true);
        assert_eq!(contract["proposal"]["reviewOnly"], true);
        assert_eq!(contract["proposal"]["sentimentTruth"], false);
        assert_eq!(contract["recording"]["localOnly"], true);
        assert_eq!(contract["recording"]["rawProviderPayload"], false);
        assert_eq!(contract["forbidden"].as_array().map(Vec::len), Some(15));
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::native());
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::export_or_download());
        assert!(!ReadOnlyAuthority::webhooks());
        assert!(!ReadOnlyAuthority::transcripts());
        assert!(!ReadOnlyAuthority::media());
        assert!(!ReadOnlyAuthority::participant_pii());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::outcome_adoption());
        assert_eq!(PLUGIN_ID, "dovetail.research-result");
    }
}
