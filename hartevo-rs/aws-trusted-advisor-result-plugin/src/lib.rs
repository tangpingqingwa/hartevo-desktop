//! Standalone Layer-1 AWS Trusted Advisor recommendation-result boundary.
//!
//! The crate deliberately models only bounded AWS Support check evidence and a
//! Mission-scoped proposal/record/verify seam. It never resolves credentials,
//! signs SigV4 requests, refreshes a check, opens a support case, applies a
//! recommendation, exports raw resource metadata, adopts an Outcome, or claims
//! that fixture, recording, loopback, or `BLOCKED_ENV` evidence is native.

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
    MissionAwsTrustedAdvisorConsumer, MissionAwsTrustedAdvisorConsumerError,
    MissionAwsTrustedAdvisorResult, MissionAwsTrustedAdvisorResultState,
    RecordedAwsTrustedAdvisorResult,
};
pub use model::*;
pub use provider::*;
pub use service::*;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-aws-trusted-advisor-result-contract/v1";
pub const CONTRACT_VERSION: &str = "aws-trusted-advisor-result-l1/v1";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "aws.trusted-advisor.result.read";
pub const PROVIDER_ID: &str = "aws.trusted-advisor.result";
pub const PROVIDER_API_REVISION: &str = "aws-support-trusted-advisor-read-v1";
pub const CONSUMER_ID: &str = "mission.aws-trusted-advisor.result";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-trusted-advisor-result/contract.v1.json");

pub const REQUIRED_PERMISSIONS: [&str; 4] = [
    "support:DescribeTrustedAdvisorChecks",
    "support:DescribeTrustedAdvisorCheckRefreshStatuses",
    "support:DescribeTrustedAdvisorCheckResult",
    "mission.scope",
];

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
    fn checked_contract_is_layer_one_and_non_native() {
        let document = serde_json::from_str::<Value>(CONTRACT_JSON).expect("valid contract JSON");
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
