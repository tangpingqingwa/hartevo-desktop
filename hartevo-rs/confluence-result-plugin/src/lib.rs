//! Standalone Layer 1 Confluence Cloud knowledge-result plugin.
//!
//! The crate owns only the typed service/provider/Mission consumer seam and
//! its contract. It can read bounded fixture/recording/loopback projections,
//! compile a redacted revision-fenced proposal, record a local receipt, and
//! verify that receipt. It never creates, updates, archives, or adopts a
//! Confluence page; native Atlassian credentials and HTTPS are Layer 2 gaps.

#![deny(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::MissionConfluenceKnowledgeConsumer;
pub use error::{
    ConfluenceCredentialError, ConfluenceKnowledgeResultError, ConfluenceProviderError,
    ConfluenceTransportError,
};
pub use model::{
    AtlassianAccountId, AuthMethod, BodyField, BodyRepresentation, CONFLUENCE_API_BASE_PATH,
    CONFLUENCE_API_VERSION, CONFLUENCE_SECRET_REFERENCE_ENV, CloudId, ConfluenceCapability,
    ConfluenceContentId, ConfluencePageId, ConfluencePageReadRequest, ConfluencePluginRegistration,
    ConfluenceProviderManifest, ConfluenceScope, ConfluenceScopeDescription,
    ConfluenceSearchCursor, ConfluenceSearchRequest, ConfluenceSite, ConfluenceSpaceId,
    ConsentBinding, CqlTemplate, Digest, KnowledgeEvidence, KnowledgeProposalStatus,
    KnowledgeReadbackField, KnowledgeResultProposal, KnowledgeResultReceipt,
    KnowledgeSearchEvidence, KnowledgeSearchHit, LabelDigest, MAX_ANCESTORS, MAX_BODY_BYTES,
    MAX_CHILDREN, MAX_CQL_BYTES, MAX_CQL_TERM_BYTES, MAX_LABELS, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_SEARCH_HITS, MissionId, MissionWorkProduct, PageEvidence, PageLink, PageMetadata,
    PageState, PageVersion, ProjectId, ProviderProvenance, RegistrationRevocation, SecretReference,
    SelectedBody, VerifiedKnowledgeResult, WorkProductId, canonical_digest, digest_parts,
    is_sha256, sha256_digest,
};
pub use model::{
    KnowledgeSearchEvidence as ConfluenceSearchEvidence, KnowledgeSearchHit as ConfluenceSearchHit,
};
pub use provider::{
    BlockedEnvCredentialResolver, ConfluenceCloudProvider, ConfluenceCredentialResolver,
    ConfluenceProviderCall, ConfluenceProviderState, FakeConfluenceProvider,
    RecordingConfluenceProvider, SecretMaterial, StaticConfluenceCredentialResolver,
};
pub use service::{
    ConfluenceKnowledgeResultOperation, ConfluenceKnowledgeResultService,
    ConfluenceKnowledgeResultServiceDefinition,
};
pub use transport::{
    ConfluenceFixture, ConfluenceTransport, ConfluenceTransportOperation, FakeConfluenceTransport,
    FixtureConfluenceTransport, FixtureFailure, FixturePage, FixturePageLink,
    LoopbackConfluenceTransport, RawPageResponse, RawSearchHit, RawSearchResponse,
    RecordingConfluenceTransport,
};

pub const CONFLUENCE_RESULT_SCHEMA_VERSION: &str = "hartevo.confluence-result/v1";
pub const CONFLUENCE_RESULT_CONTRACT_VERSION: &str = "EXT-CONFLUENCE-01-L1/v1";
pub const CONFLUENCE_PLUGIN_ID: &str = "confluence-result.knowledge-result";
pub const CONFLUENCE_PLUGIN_VERSION: u64 = 1;
pub const CONFLUENCE_ADAPTER_VERSION: u64 = 1;
pub const CONFLUENCE_PROVIDER_ID: &str = "ConfluenceCloudProvider";
pub const CONFLUENCE_PROVIDER_VERSION: u64 = 1;
pub const CONFLUENCE_SERVICE_ID: &str = "ConfluenceKnowledgeResultService";
pub const CONFLUENCE_MISSION_CONSUMER_ID: &str = "MissionConfluenceKnowledgeConsumer";
pub const CONFLUENCE_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/confluence-result/confluence-result.v1.json");

pub fn contract_digest() -> Digest {
    sha256_digest(CONFLUENCE_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 has no external-write, Store, keyring, Browser Profile, Effect,
/// durable native receipt, or kernel Outcome authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_write() -> bool {
        false
    }

    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn browser_profile() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn kernel_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONFLUENCE_RESULT_CONTRACT_JSON, CONFLUENCE_RESULT_CONTRACT_VERSION,
        CONFLUENCE_RESULT_SCHEMA_VERSION, ConfluenceKnowledgeResultServiceDefinition,
        ReadOnlyAuthority, contract_digest,
    };

    #[test]
    fn contract_freezes_layer_one_scope_redaction_and_native_gap() {
        let contract: Value = serde_json::from_str(CONFLUENCE_RESULT_CONTRACT_JSON)
            .expect("Confluence contract JSON");
        assert_eq!(contract["schemaVersion"], CONFLUENCE_RESULT_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            CONFLUENCE_RESULT_CONTRACT_VERSION
        );
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["scope"]["pageVersionFenced"], true);
        assert_eq!(contract["scope"]["permissionFenced"], true);
        assert_eq!(contract["scope"]["cursorFenced"], true);
        assert_eq!(contract["redaction"]["rawBodyInReceipt"], false);
        assert_eq!(contract["redaction"]["rawComments"], false);
        assert_eq!(contract["redaction"]["attachments"], false);
        assert_eq!(contract["authority"]["externalWrite"], false);
        assert_eq!(contract["authority"]["kernelOutcome"], false);
        assert_eq!(contract["native"]["fixtureConnected"], false);
        assert_eq!(contract["native"]["recordingConnected"], false);
        assert_eq!(contract["native"]["loopbackConnected"], false);
        assert_eq!(contract["native"]["blockedEnvConnected"], false);
        assert_eq!(contract_digest().len(), 64);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::effect());
        assert!(!ReadOnlyAuthority::durable_native_receipt());
        assert!(!ReadOnlyAuthority::kernel_outcome());
    }

    #[test]
    fn service_definition_is_typed_and_read_only() {
        let definition = ConfluenceKnowledgeResultServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 6);
        assert!(definition.read_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_native_receipts);
        assert!(!definition.independent_readback);
        assert!(!definition.kernel_outcome_authority);
    }
}
