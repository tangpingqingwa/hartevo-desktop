//! Layer-1 governed Semantic Scholar research-result evidence seam.
//!
//! This crate is a standalone nested workspace. It models bounded Academic
//! Graph GET proposals and redacted paper/author/venue/citation metadata over
//! fixture, fake, recording, loopback, and `BLOCKED_ENV` transports. It does
//! not resolve API keys, perform native HTTPS, fetch PDFs/full text, export
//! datasets, mutate graph records, assert research quality or truth, create a
//! durable native receipt, or adopt a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AdoptionAvailability, ConsumerError, MissionResearchResultState,
    MissionSemanticScholarResearchConsumer, MissionSemanticScholarResearchResult,
    ScholarlyMetadataAuthority,
};
pub use model::{
    AbstractState, ApiHost, ApiKeyPermission, ApiVersion, AuthorId, AuthorIdentityState,
    AuthorMetadata, AuthorMetadataInput, BoundedText, CitationDirection, CitationRecord,
    ConsentDataClass, ConsentScope, ContractBinding, Digest, EndpointKind, FieldSelection,
    HttpMethod, Layer1Authority, MAX_AUTHORS_PER_PAPER, MAX_BACKOFF_SECONDS,
    MAX_CITATIONS_OR_REFERENCES, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_QUERY_BYTES, MAX_RECORDS, MAX_RESPONSE_BYTES, MAX_RETRIES, MAX_SCOPE_IDS, MAX_TITLE_BYTES,
    MAX_VENUE_BYTES, MissionId, ModelError, NativeTransportProvenance, OpaqueCursor, PageRequest,
    PaperId, PaperMetadata, PaperMetadataInput, PluginVersion, ProjectId, ProviderErrorEvidence,
    QueryKind, QueryText, RecommendationPool, RecommendationRecord, RedactionNotice,
    RegistrationState, ResearchQuery, ResearchResultStatus, RetractionState, RetryEvidence,
    RetryPolicy, Revision, SafeField, SecretKind, SecretReference, SemanticScholarScope,
    SemanticScholarScopeInput, VenueId, VenueKind, VenueMetadata, VenueMetadataInput,
    WorkProductId,
};
pub use provider::{
    ApiGetRequest, AuthorPage, BlockedEnvTransport, CitationPage, FakeSemanticScholarTransport,
    FixtureSemanticScholarTransport, LoopbackSemanticScholarTransport, PaperPage, ProviderError,
    ProviderProvenance, RecommendationPage, RecordingSemanticScholarTransport, RequestParameter,
    ResponseKind, SemanticScholarProvider, SemanticScholarProviderDefinition,
    SemanticScholarResponse, SemanticScholarTransport, TransportError,
};
pub use service::{
    RequestReceipt, SemanticScholarOperation, SemanticScholarRegistration,
    SemanticScholarResearchEvidence, SemanticScholarResearchProposalRequest,
    SemanticScholarResearchResult, SemanticScholarResearchResultEvidence,
    SemanticScholarResearchResultProposal, SemanticScholarResearchResultService,
    SemanticScholarResearchResultServiceDefinition, ServiceError,
};

pub const SEMANTIC_SCHOLAR_SCHEMA_VERSION: &str = "hartevo.semantic-scholar-research-result/v1";
pub const SEMANTIC_SCHOLAR_CONTRACT_VERSION: &str = "EXT-SEMANTIC-SCHOLAR-01-L1/v1";
pub const SEMANTIC_SCHOLAR_PLUGIN_VERSION: &str = "1.0.0";
pub const SEMANTIC_SCHOLAR_SERVICE_ID: &str = "semantic-scholar.research-result";
pub const SEMANTIC_SCHOLAR_PROVIDER_ID: &str = "semantic-scholar.academic-graph";
pub const MISSION_SEMANTIC_SCHOLAR_CONSUMER_ID: &str = "mission.semantic-scholar.research-result";
pub const SEMANTIC_SCHOLAR_API_HOST: &str = "api.semanticscholar.org";
pub const SEMANTIC_SCHOLAR_API_VERSION: &str = "v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.semantic-scholar-research-result/v1|layer=1|service=semantic-scholar.research-result|provider=semantic-scholar.academic-graph|consumer=mission.semantic-scholar.research-result|contract=EXT-SEMANTIC-SCHOLAR-01-L1/v1";
pub const CONTRACT_PATH: &str =
    "contracts/plugins/semantic-scholar-research-result/semantic-scholar-research-result.v1.json";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/semantic-scholar-research-result/semantic-scholar-research-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_document_is_layer_one_and_matches_typed_ids() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], SEMANTIC_SCHOLAR_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            SEMANTIC_SCHOLAR_CONTRACT_VERSION
        );
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["contractDigestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], contract_digest().as_str());
        assert_eq!(
            contract["service"]["type"],
            "SemanticScholarResearchResultService"
        );
        assert_eq!(contract["provider"]["type"], "SemanticScholarProvider");
        assert_eq!(
            contract["consumer"]["type"],
            "MissionSemanticScholarResearchConsumer"
        );
        assert_eq!(
            contract["provider"]["allowedMethods"],
            serde_json::json!(["GET"])
        );
        assert_eq!(contract["provider"]["native"], false);
        assert_eq!(contract["provider"]["connected"], false);
        assert_eq!(contract["authority"]["truth"], false);
        assert_eq!(contract["authority"]["workProductAdoption"], false);
        assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
        assert_eq!(contract["authentication"]["serialized"], false);
        assert_eq!(contract["transport"]["allNonNative"], true);
        assert!(
            contract["queryPolicy"]["forbiddenFields"]
                .as_array()
                .expect("forbidden fields")
                .iter()
                .any(|field| field == "abstract")
        );
    }

    #[test]
    fn all_layer_one_transport_provenances_are_honest() {
        for provenance in [
            ProviderProvenance::Fixture,
            ProviderProvenance::Fake,
            ProviderProvenance::Recording,
            ProviderProvenance::Loopback,
            ProviderProvenance::BlockedEnv,
        ] {
            assert!(!provenance.connected());
            assert!(!provenance.native());
        }
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::truth());
        assert!(!Layer1Authority::adopted());
    }
}

#[cfg(test)]
mod adversarial_tests;
