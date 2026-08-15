//! Standalone Layer-1 governed Aha! Roadmaps result proposal plugin.
//!
//! The crate exposes typed read-only seams for [`AhaRoadmapResultService`],
//! [`AhaRoadmapProvider`], and [`MissionAhaRoadmapConsumer`]. It does not
//! resolve credentials, open native HTTPS, mutate roadmap records, notify
//! users, create durable provider receipts, or claim kernel authority.

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
    MissionAhaRoadmapConsumer, MissionAhaRoadmapConsumerError, MissionAhaRoadmapResult,
    MissionAhaRoadmapResultState, MissionAhaRoadmapState, MissionResultState,
};
pub use model::*;
pub use provider::{
    AhaHttpMethod, AhaHttpResponse, AhaProviderDefinition, AhaProviderError, AhaProviderRead,
    AhaProviderRequest, AhaResponse, AhaRoadmapProvider, AhaRoadmapProviderRequest,
    AhaRoadmapResponse, AhaTransport, AhaTransportError, BlockedEnvAhaRoadmapTransport,
    BlockedEnvAhaTransport, FakeAhaTransport, FixtureAhaRoadmapTransport, FixtureAhaTransport,
    LoopbackAhaRoadmapTransport, LoopbackAhaTransport, RecordingAhaRoadmapTransport,
    RecordingAhaTransport,
};
pub use service::{
    AhaRoadmapEvidence, AhaRoadmapProviderRegistration, AhaRoadmapResult, AhaRoadmapResultProposal,
    AhaRoadmapResultReceipt, AhaRoadmapResultService, AhaRoadmapResultServiceDefinition,
    AhaRoadmapResultServiceError, AhaRoadmapSecretReference, mutation_forbidden,
};

pub const AHA_ROADMAP_RESULT_SCHEMA_VERSION: &str = "hartevo.aha-roadmap-result/v1";
pub const AHA_ROADMAP_RESULT_CONTRACT_VERSION: &str = "EXT-AHA-01-L1/v1";
pub const AHA_ROADMAP_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const AHA_ROADMAP_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/aha-roadmap-result/aha-roadmap-result.v1.json";
pub const AHA_ROADMAP_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aha-roadmap-result/aha-roadmap-result.v1.json");
pub const AHA_ROADMAP_RESULT_SERVICE_ID: &str = "aha.roadmap-result.read";
pub const AHA_PROVIDER_ID: &str = "aha.roadmap.read";
pub const AHA_PROVIDER_VERSION: &str = "1.0.0";
pub const AHA_PROVIDER_API_REVISION: &str = "aha-rest-api-v1-read-roadmap";
pub const AHA_API_DOCUMENTATION_URL: &str = "https://www.aha.io/api";
pub const MISSION_AHA_ROADMAP_CONSUMER_ID: &str = "mission.aha-roadmap-result.consumer";
pub const AHA_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AHA_LAYER2_GAP: &str = "BLOCKED_ENV: native Aha API-token resolution, live HTTPS transport, native independent readback, durable provider receipts, roadmap prioritization/release edits, notifications, and kernel Truth/Consent/Effect/Receipt/Verification/Outcome authority remain later-layer gaps";

pub type AhaScope = AhaRoadmapScope;
pub type AhaScopeSpec = AhaRoadmapScopeSpec;
pub type AhaSecretReference = SecretReference;
pub type AhaRoadmapResultValue = AhaRoadmapResultProposal;
pub type AhaProvider<T> = AhaRoadmapProvider<T>;
pub type AhaRequest = AhaRoadmapRequest;

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(AHA_ROADMAP_RESULT_CONTRACT_JSON.as_bytes())
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
        let document: Value = serde_json::from_str(AHA_ROADMAP_RESULT_CONTRACT_JSON)
            .expect("Aha roadmap contract JSON");
        assert_eq!(document["schemaVersion"], AHA_ROADMAP_RESULT_SCHEMA_VERSION);
        assert_eq!(
            document["contractVersion"],
            AHA_ROADMAP_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], AHA_ROADMAP_RESULT_SERVICE_ID);
        assert_eq!(document["provider"]["id"], AHA_PROVIDER_ID);
        assert_eq!(
            document["provider"]["apiRevision"],
            AHA_PROVIDER_API_REVISION
        );
        assert_eq!(
            document["provider"]["documentation"],
            AHA_API_DOCUMENTATION_URL
        );
        assert_eq!(document["consumer"]["id"], MISSION_AHA_ROADMAP_CONSUMER_ID);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["firstParty"], false);
        assert_eq!(document["authority"]["kernelOutcome"], false);
        assert_eq!(document["scope"]["exactResourceScope"], true);
        assert_eq!(
            document["scope"]["required"].as_array().map(Vec::len),
            Some(12)
        );
        assert_eq!(
            document["provider"]["readAllowlist"]
                .as_array()
                .map(Vec::len),
            Some(10)
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
