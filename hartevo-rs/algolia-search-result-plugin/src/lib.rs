//! Standalone Layer-1 governed Algolia search-quality result plugin.
//!
//! The crate exposes typed aggregate-only seams for
//! [`AlgoliaSearchQualityService`], [`AlgoliaAnalyticsProvider`], and
//! [`MissionAlgoliaSearchConsumer`]. It never resolves native credentials,
//! sends analytics events, exports raw query or user data, mutates an index,
//! creates a kernel receipt, or adopts an Outcome.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::float_cmp)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionAlgoliaSearchConsumer, MissionAlgoliaSearchConsumerError, MissionAlgoliaSearchResult,
    MissionAlgoliaSearchResultState, MissionResultState,
};
pub use model::{
    AlgoliaAnalyticsAcl, AlgoliaAnalyticsDay, AlgoliaAnalyticsPayload, AlgoliaAnalyticsPermission,
    AlgoliaAnalyticsRequestReceipt, AlgoliaApplicationId, AlgoliaDailyAggregate,
    AlgoliaEvidenceDigests, AlgoliaEvidenceState, AlgoliaHttpMethod, AlgoliaIndexName,
    AlgoliaRateLimitReceipt, AlgoliaReadbackReceipt, AlgoliaRegion, AlgoliaRegistration,
    AlgoliaSearchQualityAggregate, AlgoliaSearchQualityEvidence, AlgoliaSearchQualityMetric,
    AlgoliaSearchQualityProposal, AlgoliaSearchQualityRecommendation, AlgoliaSearchQualityScope,
    AlgoliaSearchQualityScopeSpec, AnalyticsTag, AnalyticsWindow, ConsentScope, Digest,
    EvidenceClassification, IdentityBinding, IndexRevision, MAX_ANALYTICS_WINDOW_DAYS,
    MAX_DAILY_POINTS, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, MAX_TAG_BYTES, MAX_TAGS, MissionBinding,
    MissionId, MissionRevision, ModelError, ObservationReceipt, ProjectBinding, ProjectId,
    RecommendationDisposition, RegistrationRevocationReceipt, RegistrationState, Revision,
    SecretReference, TransportProvenance, WorkProductBinding, WorkProductId, WorkProductRevision,
    canonical_digest, sha256_digest,
};
pub use provider::{
    AlgoliaAnalyticsProvider, AlgoliaAnalyticsRequest, AlgoliaAnalyticsResponse,
    AlgoliaAnalyticsTransport, AlgoliaProviderDefinition, AlgoliaProviderError,
    AlgoliaProviderRead, AlgoliaSearchQualityProvider, AlgoliaTransportError,
    BlockedEnvAlgoliaAnalyticsTransport, FixtureAlgoliaAnalyticsTransport,
    LoopbackAlgoliaAnalyticsTransport, RecordingAlgoliaAnalyticsTransport,
};
pub use service::{
    AlgoliaSearchQualityService, AlgoliaSearchQualityServiceDefinition,
    AlgoliaSearchQualityServiceError, AlgoliaServiceError,
};

pub type AlgoliaSearchMetric = AlgoliaSearchQualityMetric;
pub type AlgoliaAnalyticsWindow = AnalyticsWindow;
pub type AlgoliaTag = AnalyticsTag;
pub type ApplicationId = AlgoliaApplicationId;
pub type IndexName = AlgoliaIndexName;
pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;
pub type Tag = AnalyticsTag;
pub type AlgoliaScope = AlgoliaSearchQualityScope;
pub type AlgoliaScopeSpec = AlgoliaSearchQualityScopeSpec;
pub type AlgoliaConsentScope = ConsentScope;
pub type MissionAlgoliaSearchQualityConsumer<T> = MissionAlgoliaSearchConsumer<T>;

pub const ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION: &str = "hartevo.algolia-search-result/v1";
pub const ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION: &str = "algolia-search-result-e1/v1";
pub const ALGOLIA_SEARCH_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const ALGOLIA_SEARCH_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/algolia-search-result/algolia-search-result.v1.json";
pub const ALGOLIA_SEARCH_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/algolia-search-result/algolia-search-result.v1.json");
pub const ALGOLIA_SEARCH_QUALITY_SERVICE_ID: &str = "algolia.search-quality.result";
pub const ALGOLIA_ANALYTICS_PROVIDER_ID: &str = "algolia.analytics.search-quality";
pub const ALGOLIA_ANALYTICS_PROVIDER_VERSION: &str = "1.0.0";
pub const ALGOLIA_ANALYTICS_API_REVISION: &str = "algolia-analytics-api-v2";
pub const MISSION_ALGOLIA_SEARCH_CONSUMER_ID: &str = "mission.algolia.search-quality";
pub const ALGOLIA_ANALYTICS_ACL: &str = "analytics";
pub const ALGOLIA_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(ALGOLIA_SEARCH_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native or kernel authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        ALGOLIA_ANALYTICS_ACL, ALGOLIA_ANALYTICS_API_REVISION, ALGOLIA_ANALYTICS_PROVIDER_ID,
        ALGOLIA_SEARCH_QUALITY_SERVICE_ID, ALGOLIA_SEARCH_RESULT_CONTRACT_JSON,
        ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION, ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION,
        Layer1Authority, MISSION_ALGOLIA_SEARCH_CONSUMER_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(ALGOLIA_SEARCH_RESULT_CONTRACT_JSON)
            .expect("Algolia contract JSON");
        assert_eq!(
            document["schemaVersion"],
            ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], ALGOLIA_SEARCH_QUALITY_SERVICE_ID);
        assert_eq!(document["provider"]["id"], ALGOLIA_ANALYTICS_PROVIDER_ID);
        assert_eq!(
            document["provider"]["apiRevision"],
            ALGOLIA_ANALYTICS_API_REVISION
        );
        assert_eq!(document["provider"]["requiredAcl"], ALGOLIA_ANALYTICS_ACL);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_ALGOLIA_SEARCH_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["outcomeAuthority"], false);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(document["provider"]["maxRequestsPerMinute"], 100);
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
