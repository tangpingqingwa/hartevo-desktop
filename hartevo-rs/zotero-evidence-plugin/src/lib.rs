//! Layer 1 Zotero versioned research-evidence and citation proposal boundary.
//!
//! The crate is intentionally standalone until a later Integration Manager
//! owns composition. It exposes typed Web API v3 and official localhost API
//! v3 request-planning seams, bounded fixture/recording/loopback providers,
//! and a Mission consumer that can only produce a reversible proposal. It
//! never performs live private authentication, writes, deletes, uploads,
//! OAuth, streaming, unbounded full-text reads, or a Connected/native claim.

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::MissionResearchEvidenceConsumer;
pub use error::{ZoteroEvidenceError, ZoteroOperationKind, ZoteroProviderError};
pub use model::{
    ClaimId, Digest, MAX_ATTACHMENT_REFERENCES, MAX_BACKOFF_SECONDS, MAX_DIGEST_INPUT_BYTES,
    MAX_FORMATTED_CITATION_BYTES, MAX_PAGE_SIZE, MAX_RESPONSE_ITEMS, MissionClaimResultBinding,
    MissionId, MissionResearchEvidenceRequest, NativeStatus, PluginVersion,
    ResearchEvidenceProposal, ResultId, ZOTERO_EVIDENCE_CONTRACT_VERSION,
    ZOTERO_EVIDENCE_SCHEMA_VERSION, ZOTERO_LOCAL_API_BASE_URL, ZOTERO_PLUGIN_VERSION,
    ZOTERO_PROVIDER_ID, ZOTERO_WEB_API_BASE_URL, ZOTERO_WEB_API_VERSION, ZoteroAccessLoss,
    ZoteroApiVersion, ZoteroAttachmentReferences, ZoteroAuthenticationMode, ZoteroBackoff,
    ZoteroCapability, ZoteroCapabilityProbeRequest, ZoteroCapabilityProbeResponse,
    ZoteroCitationArtifact, ZoteroCitationFormat, ZoteroCitationLocale, ZoteroCitationMetadata,
    ZoteroCitationRequest, ZoteroCitationResponse, ZoteroCitationStyle, ZoteroCollectionKey,
    ZoteroConditionalRequest, ZoteroConflictReason, ZoteroEvidenceCompleteness,
    ZoteroEvidenceDisposition, ZoteroEvidenceProposal, ZoteroEvidenceScope, ZoteroGroupId,
    ZoteroHttpMethod, ZoteroItemEvidence, ZoteroItemKey, ZoteroLibraryId, ZoteroLibraryVisibility,
    ZoteroObjectIdentity, ZoteroObjectKind, ZoteroObjectLifecycle, ZoteroPage,
    ZoteroPreconditionFailure, ZoteroPreconditionKind, ZoteroProvenance, ZoteroProviderManifest,
    ZoteroReadRequest, ZoteroReadResponse, ZoteroReadSelection, ZoteroReadStatus, ZoteroReadTarget,
    ZoteroRegistration, ZoteroServerId, ZoteroSinceCursor, ZoteroTransportKind,
    ZoteroTransportOperation, ZoteroUserId, ZoteroVersion, canonical_digest, sha256_digest,
};
pub use provider::{
    FakeZoteroProvider, FixtureZoteroProvider, LoopbackZoteroProvider, RecordingZoteroProvider,
    SecretReference, ZoteroApiTransport, ZoteroEvidenceProvider, ZoteroOfficialLocalApiV3Transport,
    ZoteroProviderCall, ZoteroRequestPlan, ZoteroWebApiV3Transport,
};
pub use service::ZoteroEvidenceService;

pub const ZOTERO_EVIDENCE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/zotero-evidence/zotero-evidence.v1.json");

/// Layer 1 has no external write, Store, keyring, Effect, streaming, or
/// native Connected authority.
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

    pub const fn oauth() -> bool {
        false
    }

    pub const fn streaming() -> bool {
        false
    }

    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        MAX_ATTACHMENT_REFERENCES, MAX_PAGE_SIZE, NativeStatus, ReadOnlyAuthority,
        ZOTERO_EVIDENCE_CONTRACT_JSON, ZOTERO_EVIDENCE_CONTRACT_VERSION,
        ZOTERO_EVIDENCE_SCHEMA_VERSION, ZOTERO_LOCAL_API_BASE_URL, ZOTERO_WEB_API_VERSION,
    };

    #[test]
    fn contract_is_layer_one_and_honest_about_native_gap() {
        let contract: Value = serde_json::from_str(ZOTERO_EVIDENCE_CONTRACT_JSON)
            .expect("Zotero evidence contract JSON");
        assert_eq!(contract["schemaVersion"], ZOTERO_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            ZOTERO_EVIDENCE_CONTRACT_VERSION
        );
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["api"]["web"]["version"], ZOTERO_WEB_API_VERSION);
        assert_eq!(
            contract["api"]["local"]["baseUrl"],
            ZOTERO_LOCAL_API_BASE_URL
        );
        assert_eq!(contract["authority"]["externalWrite"], false);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
        assert_eq!(contract["bounds"]["maxPageSize"], MAX_PAGE_SIZE);
        assert_eq!(
            contract["bounds"]["maxAttachmentReferences"],
            MAX_ATTACHMENT_REFERENCES
        );
        assert_eq!(NativeStatus::BlockedEnv, NativeStatus::BlockedEnv);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::oauth());
        assert!(!ReadOnlyAuthority::streaming());
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::native());
    }
}
