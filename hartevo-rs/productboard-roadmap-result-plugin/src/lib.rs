//! Standalone Layer-1 governed Productboard roadmap and insight result plugin.
//!
//! The crate exposes typed read-only seams for
//! [`ProductboardRoadmapResultService`], [`ProductboardProvider`], and
//! [`MissionProductboardRoadmapConsumer`]. It does not resolve credentials,
//! open native HTTPS, mutate Productboard records, notify users, create
//! durable provider receipts, or claim kernel authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionProductboardRoadmapConsumer, MissionProductboardRoadmapConsumerError,
    MissionProductboardRoadmapResult, MissionProductboardRoadmapResultState,
    MissionProductboardRoadmapState, MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvProductboardRoadmapTransport, BlockedEnvProductboardTransport,
    FakeProductboardRoadmapTransport, FakeProductboardTransport,
    FixtureProductboardRoadmapTransport, FixtureProductboardTransport,
    LoopbackProductboardRoadmapTransport, LoopbackProductboardTransport, ProductboardHttpMethod,
    ProductboardHttpResponse, ProductboardProvider, ProductboardProviderDefinition,
    ProductboardProviderError, ProductboardProviderRead, ProductboardProviderRequest,
    ProductboardResponse, ProductboardRoadmapProvider, ProductboardRoadmapProviderRequest,
    ProductboardRoadmapResponse, ProductboardTransport, ProductboardTransportError,
    RecordingProductboardRoadmapTransport, RecordingProductboardTransport,
};
pub use service::{
    ProductboardRoadmapEvidence, ProductboardRoadmapProviderRegistration,
    ProductboardRoadmapResult, ProductboardRoadmapResultProposal, ProductboardRoadmapResultReceipt,
    ProductboardRoadmapResultService, ProductboardRoadmapResultServiceDefinition,
    ProductboardRoadmapResultServiceError, ProductboardRoadmapSecretReference, mutation_forbidden,
};

pub const PRODUCTBOARD_ROADMAP_RESULT_SCHEMA_VERSION: &str =
    "hartevo.productboard-roadmap-result/v1";
pub const PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION: &str = "EXT-PRODUCTBOARD-01-L1/v1";
pub const PRODUCTBOARD_ROADMAP_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/productboard-roadmap-result/productboard-roadmap-result.v1.json";
pub const PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/productboard-roadmap-result/productboard-roadmap-result.v1.json"
);
pub const PRODUCTBOARD_ROADMAP_RESULT_SERVICE_ID: &str = "productboard.roadmap-result.read";
pub const PRODUCTBOARD_PROVIDER_ID: &str = "productboard.roadmap.read";
pub const PRODUCTBOARD_PROVIDER_VERSION: &str = "1.0.0";
pub const PRODUCTBOARD_PROVIDER_API_REVISION: &str =
    "productboard-rest-api-v2-read-roadmap-insight";
pub const PRODUCTBOARD_API_HOST: &str = "https://api.productboard.com";
pub const PRODUCTBOARD_API_BASE_URL: &str = "https://api.productboard.com/v2";
pub const PRODUCTBOARD_API_DOCUMENTATION_URL: &str =
    "https://developer.productboard.com/reference/introduction";
pub const MISSION_PRODUCTBOARD_ROADMAP_CONSUMER_ID: &str =
    "mission.productboard-roadmap-result.consumer";
pub const PRODUCTBOARD_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const PRODUCTBOARD_LAYER2_GAP: &str = "BLOCKED_ENV: native Productboard Public API-token resolution, live HTTPS transport, durable provider receipts, native independent readback, note/entity/relationship mutation, webhooks, verified adoption, and kernel Truth/Consent/Effect/Receipt/Verification/Outcome authority remain later-layer gaps";

pub type ProductboardScope = ProductboardRoadmapScope;
pub type ProductboardScopeSpec = ProductboardRoadmapScopeSpec;
pub type ProductboardSecretReference = SecretReference;
pub type ProductboardRoadmapResultValue = ProductboardRoadmapResultProposal;
pub type ProductboardProviderAlias<T> = ProductboardRoadmapProvider<T>;

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native, connected, first-party, kernel,
/// Outcome, or external-write authority.
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
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
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

    use super::*;

    #[test]
    fn contract_is_machine_readable_and_honest_about_layer_one() {
        let document: Value = serde_json::from_str(PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_JSON)
            .expect("Productboard contract JSON");
        assert_eq!(
            document["schemaVersion"],
            PRODUCTBOARD_ROADMAP_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            PRODUCTBOARD_ROADMAP_RESULT_SERVICE_ID
        );
        assert_eq!(document["provider"]["id"], PRODUCTBOARD_PROVIDER_ID);
        assert_eq!(
            document["provider"]["apiRevision"],
            PRODUCTBOARD_PROVIDER_API_REVISION
        );
        assert_eq!(
            document["provider"]["documentation"],
            PRODUCTBOARD_API_DOCUMENTATION_URL
        );
        assert_eq!(
            document["consumer"]["id"],
            MISSION_PRODUCTBOARD_ROADMAP_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["firstParty"], false);
        assert_eq!(document["authority"]["kernelOutcome"], false);
        assert_eq!(document["scope"]["exactResourceScope"], true);
        assert_eq!(
            document["scope"]["required"].as_array().map(Vec::len),
            Some(14)
        );
        assert_eq!(
            document["provider"]["readAllowlist"]
                .as_array()
                .map(Vec::len),
            Some(9)
        );
        assert_eq!(contract_digest().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
