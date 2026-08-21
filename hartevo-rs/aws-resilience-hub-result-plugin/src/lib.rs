//! Standalone Layer-1 AWS Resilience Hub application assessment result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded application/assessment posture reads, digest fences, reversible
//! registration, and Mission-scoped proposal/record seams. Recording,
//! fixture, fake, loopback, and `BLOCKED_ENV` transports are always
//! non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsResilienceHubConsumer, MissionAwsResilienceHubResult,
    MissionAwsResilienceHubResultConsumer, ProposalDisposition, RecordedAwsResilienceHub,
    RecordedAwsResilienceHubResult,
};
pub use error::{AwsResilienceHubError, AwsResilienceHubTransportError, Result};
pub use model::*;
pub use provider::{
    AwsResilienceHubOperation, AwsResilienceHubProvider, AwsResilienceHubProviderDefinition,
    AwsResilienceHubTransport, BlockedEnvAwsResilienceHubTransport, BlockedEnvTransport,
    DescribeAppAssessmentRequest, DescribeAppAssessmentResponse, DescribeAppRequest,
    DescribeAppResponse, FakeTransport, FixtureTransport, ListAppAssessmentsRequest,
    ListAppAssessmentsResponse, ListAppsRequest, ListAppsResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsResilienceHubEvidenceRequest, AwsResilienceHubProposal, AwsResilienceHubRead,
    AwsResilienceHubRegistration, AwsResilienceHubResult, AwsResilienceHubResultRegistration,
    AwsResilienceHubService, CapabilityDescription, FailureEvidence, RegistrationStatus,
    RegistrationTransitionEvidence, ResilienceEvidenceState, VerificationFailure,
    VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-resilience-hub-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-RESILIENCE-HUB-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-resilience-hub-result/v1|layer=1|service=aws.resilience-hub.result.read|provider=aws.resilience-hub.result.recording|consumer=mission.aws-resilience-hub.consumer";
pub const CONTRACT_DIGEST: &str =
    "2154d52687ffb5a10e33f08c506749f7c1c5829b8d2735b5b1abeb5daf8cb9d9";
pub const PLUGIN_ID: &str = "aws.resilience-hub.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.resilience-hub.result.read";
pub const PROVIDER_ID: &str = "aws.resilience-hub.result.recording";
pub const PROVIDER_API_REVISION: &str =
    "resilience-hub-list-apps-describe-app-list-app-assessments-describe-app-assessment-1";
pub const CONSUMER_ID: &str = "mission.aws-resilience-hub.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-resilience-hub-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "resiliencehub:ListApps",
    "resiliencehub:DescribeApp",
    "resiliencehub:ListAppAssessments",
    "resiliencehub:DescribeAppAssessment",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["service"]["readOnly"], true);
        assert_eq!(contract["service"]["externalWrites"], false);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["provider"]["connectedEvidence"], false);
        assert_eq!(contract["provider"]["nativeEvidence"], false);
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["consumer"]["adoptsOutcome"], false);
        assert_eq!(contract["consumer"]["adoptsWorkProduct"], false);
    }
}
