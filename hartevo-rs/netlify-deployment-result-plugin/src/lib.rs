//! Standalone Layer-1 governed Netlify deployment-result boundary.
//!
//! This crate owns only bounded site/deployment metadata reads, digest-fenced
//! proposals, redacted observation recording, and Mission projection. Fixture,
//! recording, loopback, and `BLOCKED_ENV` transports are always non-connected,
//! non-native, and non-first-party.

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

pub use consumer::{
    MissionNetlifyDeploymentConsumer, MissionNetlifyDeploymentResult, ProposalDisposition,
    RecordedNetlifyDeploymentResult,
};
pub use error::{NetlifyDeploymentError, NetlifyTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, FixtureTransport, LoopbackTransport, NetlifyDeployFixture,
    NetlifyDeployPage, NetlifyDeployPageFixture, NetlifyLinkHeader, NetlifyOperation,
    NetlifyProvider, NetlifyProviderDefinition, NetlifyRequest, NetlifyResponse, NetlifyTransport,
    RecordingTransport,
};
pub use service::{
    CapabilityDescription, EvidenceDigests, FailureEvidence, NetlifyDeploymentEvidence,
    NetlifyDeploymentProposal, NetlifyDeploymentRegistration, NetlifyDeploymentService,
    NetlifyDeploymentServiceDefinition, NetlifyPreviewDecision, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.netlify-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-NETLIFY-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.netlify-deployment-result/v1|layer=1|service=netlify.deployment-result.read|provider=netlify.deployment-result.recording|consumer=mission.netlify-deployment.consumer";
pub const CONTRACT_DIGEST: &str =
    "625653bf1372c4ee1b5226ce0c1a3d4f9b5638ae9c3bcf88acbe43f078544b54";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/netlify-deployment-result/contract.v1.json");
pub const PLUGIN_ID: &str = "netlify.deployment-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "netlify.deployment-result.read";
pub const PROVIDER_ID: &str = "netlify.deployment-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const NETLIFY_PROVIDER_API_REVISION: &str = "netlify-sites-deploys-v1";
pub const MISSION_CONSUMER_ID: &str = "mission.netlify-deployment.consumer";
pub const CONSUMER_ID: &str = MISSION_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";

#[must_use]
pub fn contract_digest() -> String {
    model::sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// Layer 1 deliberately reports no native, connected, first-party, or kernel
/// authority regardless of the deterministic transport selected.
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
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority, NETLIFY_PROVIDER_API_REVISION,
        PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_versioned_bounded_and_layer_one_honest() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("Netlify contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(
            contract["provider"]["apiRevision"],
            NETLIFY_PROVIDER_API_REVISION
        );
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["nativeProvider"], false);
        assert_eq!(contract["authority"]["firstPartyProvider"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["consumer"]["adoptsOutcome"], false);
        assert_eq!(contract["consumer"]["adoptsWorkProduct"], false);
        assert_eq!(
            contract["provider"]["allowedTransportProvenance"]
                .as_array()
                .map(Vec::len),
            Some(4)
        );
        assert_eq!(contract["bounds"]["maxPages"], 4);
        assert_eq!(contract["bounds"]["maxPollAttempts"], 3);
        assert_eq!(
            contract["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party_provider());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
