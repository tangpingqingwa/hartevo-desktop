//! Layer 1 Notion knowledge-result adoption boundary.
//!
//! The crate is intentionally standalone until a later Integration Manager
//! owns composition.  It compiles a Mission WorkProduct projection into a
//! scope/consent-bound page or data-source proposal, supports read/describe,
//! and verifies content-free page receipts/read-backs.  It never performs a
//! native Notion write, stores a token, consumes a webhook, or acquires
//! Hartevo Store/Effect/Browser Profile authority.

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::MissionNotionResultConsumer;
pub use error::{NotionProviderError, NotionResultError};
pub use model::{
    Digest, MAX_CONTENT_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_POLLS, MissionId, MissionWorkProduct,
    NOTION_ACCESS_TOKEN_ENV, NOTION_API_BASE_URL, NOTION_API_VERSION,
    NOTION_RESULT_CONTRACT_VERSION, NOTION_RESULT_SCHEMA_VERSION, NativeStatus, NotionApiVersion,
    NotionAsyncMode, NotionAsyncTemplate, NotionBlockType, NotionCapability, NotionConsent,
    NotionContentBlock, NotionCursor, NotionDataSourceId, NotionDescribeRequest,
    NotionEndpointEffect, NotionEndpointOperation, NotionEndpointTemplate, NotionEvidenceSource,
    NotionHttpMethod, NotionPageId, NotionPagePayload, NotionPageReceipt, NotionPageUrl,
    NotionPaginationReceipt, NotionPaginationTemplate, NotionParent, NotionPropertyKey,
    NotionPropertyValue, NotionProposalEffect, NotionProviderManifest, NotionPublishDestination,
    NotionPublishOperation, NotionPublishProposal, NotionReadRequest, NotionReadback,
    NotionReadbackField, NotionResourceKind, NotionRevision, NotionRichText, NotionScope,
    NotionScopeDescription, NotionVerifiedReadback, PluginVersion, ProjectId, TenantId,
    WorkProductId, canonical_digest, sha256_digest,
};
pub use provider::{
    FakeNotionProvider, NotionProviderCall, NotionResultProvider, RecordingNotionProvider,
    SecretReference,
};
pub use service::NotionResultService;

pub const NOTION_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/notion-result/notion-result.v1.json");

/// Layer 1 has no external write, Store, keyring, Browser Profile, or Effect
/// authority.  The explicit value is useful to integration tests before any
/// root-workspace wiring exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        MAX_PAGE_SIZE, MAX_PAGES, MAX_POLLS, NOTION_API_VERSION, NOTION_RESULT_CONTRACT_JSON,
        NOTION_RESULT_CONTRACT_VERSION, NOTION_RESULT_SCHEMA_VERSION, ReadOnlyAuthority,
    };

    #[test]
    fn contract_freezes_layer_one_honesty_and_native_gap() {
        let contract: Value =
            serde_json::from_str(NOTION_RESULT_CONTRACT_JSON).expect("Notion contract JSON");
        assert_eq!(contract["schemaVersion"], NOTION_RESULT_SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], NOTION_RESULT_CONTRACT_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["api"]["version"], NOTION_API_VERSION);
        assert_eq!(contract["api"]["databaseAndDataSourceDistinct"], true);
        assert_eq!(contract["authority"]["externalWrite"], false);
        assert_eq!(contract["authority"]["storeAuthority"], false);
        assert_eq!(contract["authority"]["keyringAuthority"], false);
        assert_eq!(contract["authority"]["browserProfileAuthority"], false);
        assert_eq!(contract["authority"]["effectAuthority"], false);
        assert_eq!(contract["native"]["write"], "BLOCKED_ENV");
        assert_eq!(contract["native"]["credentials"], "BLOCKED_ENV");
        assert_eq!(contract["native"]["webhook"], "BLOCKED_ENV");
        assert_eq!(contract["pagination"]["maxPageSize"], MAX_PAGE_SIZE);
        assert_eq!(contract["pagination"]["maxPages"], MAX_PAGES);
        assert_eq!(contract["async"]["maxPolls"], MAX_POLLS);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::effect());
    }
}
