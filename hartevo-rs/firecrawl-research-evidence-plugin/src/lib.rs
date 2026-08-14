//! Standalone Layer 1 Firecrawl public research-evidence boundary.
//!
//! This crate owns only typed URL/job scope, bounded fixture/recording
//! provider projections, Mission proposals, local recording receipts, and
//! digest verification. It never performs live Firecrawl HTTPS, resolves a
//! native API key, opens a browser, executes code, follows arbitrary URLs,
//! writes externally, or adopts a Work Product.

#![deny(unsafe_code)]
#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
    clippy::semicolon_if_nothing_returned,
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
mod transport;

pub use consumer::{FirecrawlMissionEvidenceResult, MissionFirecrawlResearchConsumer};
pub use error::{
    FirecrawlCredentialError, FirecrawlOperationKind, FirecrawlProviderError,
    FirecrawlResearchEvidenceError, FirecrawlTransportError,
};
pub use model::{
    CanonicalUrl, ClaimId, ContentFormat, Digest, FIRECRAWL_API_BASE_URL, FIRECRAWL_API_VERSION,
    FIRECRAWL_CRAWL_PATH, FIRECRAWL_CRAWL_STATUS_PATH, FIRECRAWL_SCRAPE_PATH,
    FIRECRAWL_SECRET_REFERENCE_ENV, FirecrawlAllowlistRule, FirecrawlAuthMode, FirecrawlCacheMode,
    FirecrawlCachePolicy, FirecrawlCitation, FirecrawlContentFormat, FirecrawlCrawlOptions,
    FirecrawlExtractionSchema, FirecrawlJob, FirecrawlJobDescription, FirecrawlJobId,
    FirecrawlJobKind, FirecrawlJobRequest, FirecrawlJobSpec, FirecrawlJobStatus,
    FirecrawlMissionId, FirecrawlPermissionRegistration, FirecrawlPluginRegistration,
    FirecrawlProjectId, FirecrawlProvenance, FirecrawlProviderManifest, FirecrawlReadbackField,
    FirecrawlRequest, FirecrawlResearchEvidence, FirecrawlResearchProposal,
    FirecrawlResearchReceipt, FirecrawlResearchRequest, FirecrawlResearchScope, FirecrawlScope,
    FirecrawlScrapeOptions, FirecrawlUrl, FirecrawlUrlAllowlist, FirecrawlUrlDescription,
    FirecrawlWorkProductId, MAX_ALLOWLIST_RULES, MAX_CACHE_AGE_MS, MAX_CRAWL_DEPTH,
    MAX_CRAWL_PAGES, MAX_JOB_ID_BYTES, MAX_MARKDOWN_BYTES, MAX_POLL_ATTEMPTS, MAX_SNIPPET_BYTES,
    MAX_TIMEOUT_MS, MissionFirecrawlResearchRequest, MissionId, MissionWorkProduct, NativeStatus,
    PluginVersion, ProjectId, ProviderProvenance, ResultId, SecretKind, SecretReference,
    VerifiedFirecrawlResearchResult, WorkProductId, canonical_digest, digest_parts, is_sha256,
    sha256_digest,
};
pub use provider::{
    BlockedEnvCredentialResolver, FirecrawlCredentialResolver, FirecrawlProvider,
    FirecrawlProviderCall, FirecrawlProviderState, FirecrawlRegistrationRevocation,
    FirecrawlRequestPlan, SecretMaterial, StaticFirecrawlCredentialResolver,
};
pub use service::{
    FirecrawlResearchEvidenceOperation, FirecrawlResearchEvidenceService,
    FirecrawlResearchEvidenceServiceDefinition,
};
pub use transport::{
    FakeFirecrawlTransport, FirecrawlFixture, FirecrawlTransport, FirecrawlTransportOperation,
    FixtureFailure, FixtureFirecrawlTransport, LoopbackFirecrawlTransport, RawFirecrawlPage,
    RawFirecrawlResponse, RecordingFirecrawlTransport, transport_digest,
};

pub const FIRECRAWL_RESEARCH_EVIDENCE_SCHEMA_VERSION: &str =
    "hartevo.firecrawl-research-evidence/v1";
pub const FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_VERSION: &str = "EXT-FIRECRAWL-01-L1/v1";
pub const FIRECRAWL_PLUGIN_ID: &str = "firecrawl.research-evidence";
pub const FIRECRAWL_PLUGIN_VERSION: PluginVersion = PluginVersion::V1;
pub const FIRECRAWL_PROVIDER_ID: &str = "FirecrawlProvider";
pub const FIRECRAWL_PROVIDER_VERSION: u64 = 1;
pub const FIRECRAWL_SERVICE_ID: &str = "FirecrawlResearchEvidenceService";
pub const FIRECRAWL_MISSION_CONSUMER_ID: &str = "MissionFirecrawlResearchConsumer";
pub const FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/firecrawl-research-evidence/firecrawl-research-evidence.v1.json"
);

pub fn contract_digest() -> Digest {
    sha256_digest(FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_JSON.as_bytes())
}

/// Layer 1 authority is intentionally read/proposal/local-recording only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_write() -> bool {
        false
    }

    pub const fn browser_actions() -> bool {
        false
    }

    pub const fn arbitrary_code() -> bool {
        false
    }

    pub const fn generic_search_registry() -> bool {
        false
    }

    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn adoption() -> bool {
        false
    }

    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_JSON, FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_VERSION,
        FIRECRAWL_RESEARCH_EVIDENCE_SCHEMA_VERSION, ReadOnlyAuthority, contract_digest,
    };

    #[test]
    fn contract_is_layer_one_and_native_honesty_is_frozen() {
        let contract: Value = serde_json::from_str(FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_JSON)
            .expect("Firecrawl contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            FIRECRAWL_RESEARCH_EVIDENCE_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            FIRECRAWL_RESEARCH_EVIDENCE_CONTRACT_VERSION
        );
        assert_eq!(contract["layer"], 1);
        assert_eq!(
            contract["content"]["formats"],
            serde_json::json!(["markdown"])
        );
        assert_eq!(contract["scope"]["arbitraryUrlExpansion"], false);
        assert_eq!(contract["authority"]["externalWrite"], false);
        assert_eq!(contract["authority"]["browserActions"], false);
        assert_eq!(contract["authority"]["arbitraryCode"], false);
        assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
        assert_eq!(contract["testSeams"]["connected"], false);
        assert_eq!(contract["testSeams"]["native"], false);
        assert_eq!(contract_digest().len(), 64);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::browser_actions());
        assert!(!ReadOnlyAuthority::arbitrary_code());
        assert!(!ReadOnlyAuthority::generic_search_registry());
        assert!(!ReadOnlyAuthority::adoption());
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::native());
        assert!(!ReadOnlyAuthority::first_party());
    }
}
