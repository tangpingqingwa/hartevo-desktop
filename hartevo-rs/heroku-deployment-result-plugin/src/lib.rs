//! Standalone Layer-1 Heroku deployment-result capability.
//!
//! The crate owns bounded, read-only app/build/release/slug/dyno metadata,
//! typed proposal and recording seams, and exact Mission scope fences. It
//! imports no Hartevo application, desktop, domain, storage, catalog, keyring,
//! browser, kernel, generic hosting registry, or existing connector authority.
//! There is no native HTTP client and no external-effect implementation.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
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

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionHerokuDeploymentConsumer, MissionHerokuDeploymentResult, ProposalDisposition,
    RecordedHerokuDeploymentResult,
};
pub use error::{HerokuDeploymentError, HerokuTransportError, Result};
pub use model::*;
pub use provider::{
    HEROKU_API_BASE_URL, HEROKU_OFFICIAL_API_REFERENCE, HEROKU_PROVIDER_API_REVISION,
    HerokuAppFixture, HerokuBuildFixture, HerokuDynoFixture, HerokuProvider,
    HerokuProviderDefinition, HerokuProviderSnapshot, HerokuReleaseFixture,
    HerokuReleasePageFixture, HerokuSlugFixture,
};
pub use service::{
    EvidenceDigests, FailureEvidence, HerokuCapabilityDescription, HerokuDeploymentEvidence,
    HerokuDeploymentProposal, HerokuDeploymentReceipt, HerokuDeploymentRegistration,
    HerokuDeploymentResultService, HerokuDeploymentServiceDefinition,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};
pub use transport::{
    BlockedEnvTransport, FakeTransport, FixtureTransport, HerokuOperation, HerokuRequest,
    HerokuResponse, HerokuTransport, LoopbackTransport, OpaqueCursor, RecordingTransport,
    RetryPolicy,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.heroku-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-HEROKU-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.heroku-deployment-result/v1|layer=1|service=heroku.deployment-result.read|provider=heroku.deployment-result.recording|consumer=mission.heroku-deployment.consumer";
pub const CONTRACT_DIGEST: &str =
    "7f25d8730536d875594cc1c82de8080960cf7b31a5aee5f54648940cca0348e5";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/heroku-deployment-result/contract.v1.json");
pub const PLUGIN_ID: &str = "heroku.deployment-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "heroku.deployment-result.read";
pub const PROVIDER_ID: &str = "heroku.deployment-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const MISSION_CONSUMER_ID: &str = "mission.heroku-deployment.consumer";
pub const CONSUMER_ID: &str = MISSION_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native OAuth/token resolution, live Heroku HTTPS reads, durable provider receipts, independent release/readback verification, consented effects, and verified Work Product/Outcome adoption remain Layer 2 gaps";

#[must_use]
pub fn contract_digest() -> String {
    model::sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// Layer 1 deliberately reports no connected, native, first-party, kernel,
/// external-effect, receipt, or adoption authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
    pub const fn first_party_provider() -> bool {
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
    pub const fn work_product_adoption() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_is_versioned_bounded_and_layer_one_honest() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("Heroku contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract["service"]["type"], "HerokuDeploymentResultService");
        assert_eq!(contract["provider"]["type"], "HerokuProvider");
        assert_eq!(
            contract["consumer"]["type"],
            "MissionHerokuDeploymentConsumer"
        );
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["nativeProvider"], false);
        assert_eq!(contract["authority"]["firstPartyProvider"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["consumer"]["adoptsOutcome"], false);
        assert_eq!(contract["consumer"]["adoptsWorkProduct"], false);
        assert_eq!(contract["bounds"]["maxPages"], 4);
        assert_eq!(contract["bounds"]["maxRetryAttempts"], 3);
        assert_eq!(contract["provider"]["baseUrl"], HEROKU_API_BASE_URL);
        assert_eq!(
            contract["provider"]["officialReference"],
            HEROKU_OFFICIAL_API_REFERENCE
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party_provider());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::external_writes());
    }
}
