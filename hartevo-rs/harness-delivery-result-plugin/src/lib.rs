//! Standalone Layer-1 governed Harness delivery evidence result boundary.
//!
//! This crate is deliberately limited to bounded metadata reads, proposal and
//! verification seams, reversible digest-bound registration, and redacted
//! recording. It never resolves an API key, connects to Harness, controls a
//! pipeline or execution, exports secrets/environment values, reads raw logs or
//! artifacts, registers generic CI, or adopts Truth, Effect, Outcome, or Work
//! Product authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionHarnessDeliveryConsumer, MissionHarnessDeliveryResult, ProposalDisposition,
    RecordedHarnessDeliveryResult,
};
pub use error::{HarnessDeliveryResultError, HarnessTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, DeploymentResponse, ExecutionPage, FixtureTransport, GetDeploymentRequest,
    HarnessProvider, HarnessProviderDefinition, HarnessProviderError, HarnessTransport,
    ListExecutionsRequest, ListPipelinesRequest, ListServicesRequest, ListStagesRequest,
    LoopbackTransport, PipelinePage, RecordedHarnessRequest, RecordingTransport, ServicePage,
    StagePage,
};
pub use service::{
    BackoffHint, CapabilityDescription, FailureEvidence, HarnessDeliveryEvidenceRequest,
    HarnessDeliveryProposal, HarnessDeliveryRegistration, HarnessDeliveryResultService,
    HarnessRegistration, RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure,
    VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.harness-delivery-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-HARNESS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.harness-delivery-result/v1|layer=1|service=harness.delivery-result.read|provider=harness.delivery-result.recording|consumer=mission.harness-delivery.consumer";
pub const CONTRACT_DIGEST: &str =
    "65304f96bef5f15d7a2025a87369916cd2449f04af4a4485cb5c96241f3ffb85";
pub const PLUGIN_ID: &str = "harness.delivery-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "harness.delivery-result.read";
pub const PROVIDER_ID: &str = "harness.delivery-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "harness-pipeline-execution-stage-service-deployment-read-1";
pub const CONSUMER_ID: &str = "mission.harness-delivery.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/harness-delivery-result/harness-delivery-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_METADATA_ITEMS: usize = 64;

pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "harness:pipelines:read",
    "harness:executions:read",
    "harness:stages:read",
    "harness:services:read",
    "harness:deployments:read",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> Digest {
    Digest::parse(sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes()))
        .expect("SHA-256 output is a valid digest")
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert!(contract["service"]["readOnly"].as_bool().unwrap_or(false));
        assert!(
            contract["service"]["proposalOnly"]
                .as_bool()
                .unwrap_or(false)
        );
        assert!(
            !contract["service"]["externalWrites"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert!(
            !contract["provider"]["connectedEvidence"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !contract["provider"]["nativeEvidence"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert!(
            !contract["consumer"]["adoptsOutcome"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !contract["consumer"]["adoptsWorkProduct"]
                .as_bool()
                .unwrap_or(true)
        );
    }
}
