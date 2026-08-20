//! Standalone Layer-1 AWS EMR Serverless job-run result boundary.
//!
//! This crate models bounded `GetApplication`, `GetJobRun`, and `ListJobRuns`
//! reads only. It deliberately stops below Hartevo Truth, Consent, Effect,
//! Receipt, Verification, Outcome, and native Work Product authority. The
//! fixture, recording, loopback, and `BLOCKED_ENV` transports are all offline
//! and always report `connected = false`, `native = false`, and
//! `first_party = false`.

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

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsEmrServerlessConsumer, MissionAwsEmrServerlessResult,
    MissionResultDisposition, MissionResultState,
};
pub use error::{AwsEmrServerlessJobResultError, AwsEmrServerlessTransportError, Result};
pub use model::*;
pub use provider::{
    AwsEmrServerlessOperation, AwsEmrServerlessProvider, AwsEmrServerlessProviderDefinition,
    AwsEmrServerlessTransport, BlockedEnvTransport, FixtureTransport, GetApplicationRequest,
    GetApplicationResponse, GetJobRunRequest, GetJobRunResponse, ListJobRunsRequest,
    ListJobRunsResponse, LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsEmrServerlessJobResultProposal, AwsEmrServerlessJobResultRegistration,
    AwsEmrServerlessJobResultService, AwsEmrServerlessRegistration, RegistrationStatus,
    RegistrationTransitionEvidence,
};

pub type AwsEmrServerlessScope = model::AwsEmrServerlessJobResultScope;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-emr-serverless-job-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-EMR-SERVERLESS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-emr-serverless-job-result/v1|layer=1|service=aws.emr-serverless.job-result.read|provider=aws.emr-serverless.job-result.offline|consumer=mission.aws-emr-serverless-job-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "84d5ee6fa45017835fcee9867431adcbe0a213f13a37b20187c7d1530f185982";
pub const PLUGIN_ID: &str = "aws.emr-serverless.job-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.emr-serverless.job-result.read";
pub const PROVIDER_ID: &str = "aws.emr-serverless.job-result.offline";
pub const PROVIDER_API_REVISION: &str =
    "emr-serverless-get-application-get-job-run-list-job-runs-1";
pub const CONSUMER_ID: &str = "mission.aws-emr-serverless-job-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-emr-serverless-job-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_SUMMARIES_PER_PAGE: usize = 50;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_STATE_DETAILS_BYTES: usize = 4 * 1024;
pub const MAX_RESOURCE_UNITS: u64 = 10_000_000_000;
pub const MAX_COST_MICROS: u64 = 10_000_000_000_000;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "emr-serverless:GetApplication",
    "emr-serverless:GetJobRun",
    "emr-serverless:ListJobRuns",
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
    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .expect("checked EMR Serverless contract");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert!(contract["service"]["readOnly"].as_bool().unwrap_or(false));
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
        assert!(
            !contract["provider"]["firstPartyEvidence"]
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
        assert_eq!(
            contract["lifecycleStates"].as_array().map(Vec::len),
            Some(15)
        );
    }
}
