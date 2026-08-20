//! Standalone Layer-1 AWS Compute Optimizer recommendation evidence boundary.
//!
//! The crate deliberately stops at bounded reads, a review-only proposal,
//! redacted recording, and integrity verification. It has no credential
//! resolver, SigV4 signer, native HTTP client, preference mutation, resource
//! resize, savings guarantee, raw utilization series, or kernel Outcome
//! authority. Fixture, recording, loopback, and `BLOCKED_ENV` transports are
//! all explicitly non-connected and non-native.

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
    clippy::too_many_lines
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AwsComputeOptimizerConsumer, MissionAwsComputeOptimizerConsumer,
    MissionAwsComputeOptimizerConsumerError, MissionAwsComputeOptimizerResult,
    MissionAwsComputeOptimizerResultState, RecordedAwsComputeOptimizerResult,
};
pub use model::*;
pub use provider::*;
pub use service::*;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-aws-compute-optimizer-result-contract/v1";
pub const CONTRACT_VERSION: &str = "aws-compute-optimizer-result-l1/v1";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "aws.compute-optimizer.result.read";
pub const PROVIDER_ID: &str = "aws.compute-optimizer.result";
pub const PROVIDER_API_REVISION: &str = "aws-compute-optimizer-read-v1";
pub const CONSUMER_ID: &str = "mission.aws.compute-optimizer.result";
pub const PROVIDER_VERSION: &str = "1.0.0";

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-compute-optimizer-result/aws-compute-optimizer-result.v1.json"
);

pub const REQUIRED_PERMISSIONS: [&str; 3] = [
    "compute-optimizer:GetEC2InstanceRecommendations",
    "compute-optimizer:GetAutoScalingGroupRecommendations",
    "mission.scope",
];

// Explicit names used by catalog and contract tooling.
pub const AWS_COMPUTE_OPTIMIZER_SCHEMA_VERSION: &str = CONTRACT_SCHEMA_VERSION;
pub const AWS_COMPUTE_OPTIMIZER_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const AWS_COMPUTE_OPTIMIZER_PLUGIN_VERSION: &str = PLUGIN_VERSION;
pub const AWS_COMPUTE_OPTIMIZER_SERVICE_ID: &str = SERVICE_ID;
pub const AWS_COMPUTE_OPTIMIZER_PROVIDER_ID: &str = PROVIDER_ID;
pub const AWS_COMPUTE_OPTIMIZER_API_REVISION: &str = PROVIDER_API_REVISION;
pub const MISSION_AWS_COMPUTE_OPTIMIZER_CONSUMER_ID: &str = CONSUMER_ID;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON)
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, Digest,
        PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_layer_one_read_only_and_non_native() {
        let document = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["service"]["readOnly"], true);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], PROVIDER_API_REVISION);
        assert_eq!(document["provider"]["connected"], false);
        assert_eq!(document["provider"]["native"], false);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["consumer"]["adoptsOutcome"], false);
        assert_eq!(document["authority"]["kernelOutcomeAdoption"], false);
        assert_eq!(
            document["evidenceModes"],
            serde_json::json!(["fixture", "recording", "loopback", "BLOCKED_ENV"])
        );
        assert_eq!(contract_digest(), Digest::from_text(CONTRACT_JSON));
    }
}
