//! Standalone Layer 1 PlanetScale branch-result plugin.
//!
//! The crate exposes bounded, digest-fenced PlanetScale branch/deploy/schema
//! posture proposals and redacted recording/verification seams. It never
//! resolves credentials, opens a native transport, mutates a branch or deploy
//! request, deploys schema, executes a query, or adopts a Work Product.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionPlanetScaleBranchConsumer, MissionPlanetScaleBranchResult,
    MissionResultState,
};
pub use error::{InputViolation, PlanetScaleBranchResultError, PlanetScaleProviderError};
pub use model::*;
pub use provider::{
    BlockedEnvPlanetScaleTransport, FakePlanetScaleTransport, FixturePlanetScaleTransport,
    LoopbackPlanetScaleTransport, PlanetScaleProvider, PlanetScaleTransport, PostureResponse,
    RecordingPlanetScaleTransport,
};
pub use service::{
    PlanetScaleBranchResultService, PlanetScaleServiceDefinition, PlanetScaleServiceError,
};

pub type PlanetScaleBranchResultProvider<T> = PlanetScaleProvider<T>;
pub type PlanetScaleBranchResultRegistration = PlanetScaleRegistration;
pub type PlanetScaleProviderRegistration = PlanetScaleRegistration;

pub const PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION: &str = "hartevo.planetscale-branch-result/v1";
pub const PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION: &str = "EXT-PLANETSCALE-01-L1/v1";
pub const PLANETSCALE_BRANCH_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/planetscale-branch-result/planetscale-branch-result.v1.json";
pub const PLANETSCALE_BRANCH_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/planetscale-branch-result/planetscale-branch-result.v1.json"
);
pub const PLANETSCALE_PLUGIN_ID: &str = "hartevo.planetscale-branch-result";
pub const PLANETSCALE_PROVIDER_ID: &str = "planetscale.branch-result";
pub const PLANETSCALE_SERVICE_ID: &str = "planetscale-branch-result.service";
pub const MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID: &str =
    "mission.planetscale-branch-result.consumer";
pub const PLANETSCALE_API_REVISION: &str = "planetscale-api-read-posture-v1";
pub const PLANETSCALE_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native PlanetScale secret resolution, live API transport, durable provider receipt, independent live readback, consented branch/deploy effects, schema deploy, query execution, and verified Work Product adoption remain Layer 2 gaps";

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(PLANETSCALE_BRANCH_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 has no Connected, native, kernel, or Work Product authority.
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
    pub const fn work_product_adoption() -> bool {
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
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(PLANETSCALE_BRANCH_RESULT_CONTRACT_JSON)
            .expect("PlanetScale contract JSON");
        assert_eq!(
            document["schemaVersion"],
            PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["provider"]["id"], PLANETSCALE_PROVIDER_ID);
        assert_eq!(document["service"]["id"], PLANETSCALE_SERVICE_ID);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID
        );
        assert_eq!(document["authority"]["queryAuthority"], false);
        assert_eq!(document["authority"]["deployAuthority"], false);
        assert_eq!(document["evidence"]["connected"], false);
        assert_eq!(document["evidence"]["native"], false);
        assert_eq!(
            document["provider"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!contract_digest().as_str().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::external_writes());
    }
}
