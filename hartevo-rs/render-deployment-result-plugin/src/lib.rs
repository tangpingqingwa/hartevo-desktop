//! Standalone Layer-1 Render deployment-result capability.
//!
//! The crate owns bounded, read-only service/deploy/health metadata, typed
//! proposal and recording seams, and exact Mission scope fences. It imports no
//! Hartevo application, desktop, domain, storage, catalog, keyring, browser,
//! kernel, or provider authority and contains no native HTTP client.

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
    MissionRenderDeploymentConsumer, MissionRenderDeploymentResult, ProposalDisposition,
    RecordedRenderDeploymentResult,
};
pub use error::{RenderDeploymentError, RenderTransportError, Result};
pub use model::*;
pub use provider::{
    RenderDeployFixture, RenderDeployPageFixture, RenderDeploySnapshot, RenderHealthFixture,
    RenderHealthSnapshot, RenderProvider, RenderProviderDefinition, RenderServiceFixture,
    RenderServiceSnapshot,
};
pub use service::{
    EvidenceDigests, FailureEvidence, RenderCapabilityDescription, RenderDeploymentEvidence,
    RenderDeploymentProposal, RenderDeploymentReceipt, RenderDeploymentRegistration,
    RenderDeploymentResultService, RenderDeploymentServiceDefinition, VerificationFailure,
    VerificationReport,
};
pub use transport::{
    BlockedEnvTransport, FakeTransport, FixtureTransport, LoopbackTransport, OpaqueCursor,
    RecordingTransport, RenderOperation, RenderRequest, RenderResponse, RenderTransport,
    RetryPolicy,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.render-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-RENDER-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.render-deployment-result/v1|layer=1|service=render.deployment-result.read|provider=render.deployment-result.recording|consumer=mission.render-deployment.consumer";
pub const CONTRACT_DIGEST: &str =
    "5bfc1081d32e9ef12c12430ec5dbd334aa687eed3e9436984127c35c5cadc90d";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/render-deployment-result/contract.v1.json");
pub const PLUGIN_ID: &str = "render.deployment-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "render.deployment-result.read";
pub const PROVIDER_ID: &str = "render.deployment-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const RENDER_PROVIDER_API_REVISION: &str = "render-services-deploys-health-v1";
pub const MISSION_CONSUMER_ID: &str = "mission.render-deployment.consumer";
pub const CONSUMER_ID: &str = MISSION_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const RENDER_API_BASE_URL: &str = "https://api.render.com";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native OAuth/API-key resolution, live Render HTTPS reads, durable provider receipts, independent health/readback verification, consented deploy/restart/rollback/environment effects, and verified Work Product adoption remain Layer 2 gaps";

#[must_use]
pub fn contract_digest() -> String {
    model::sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// Layer 1 deliberately reports no native, connected, first-party, kernel, or
/// external-effect authority for every deterministic provenance.
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
    fn checked_contract_is_versioned_bounded_and_layer_one_honest() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("Render contract JSON");
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
            RENDER_PROVIDER_API_REVISION
        );
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["nativeProvider"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["consumer"]["adoptsOutcome"], false);
        assert_eq!(contract["consumer"]["adoptsWorkProduct"], false);
        assert_eq!(
            contract["provider"]["allowedTransportProvenance"]
                .as_array()
                .map(Vec::len),
            Some(5)
        );
        assert_eq!(contract["bounds"]["maxPages"], 4);
        assert_eq!(contract["bounds"]["maxRetryAttempts"], 3);
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
