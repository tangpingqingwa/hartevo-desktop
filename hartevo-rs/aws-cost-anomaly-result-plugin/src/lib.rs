//! Standalone Layer-1 AWS Cost Anomaly Detection result boundary.
//!
//! This crate intentionally stops at typed, bounded, digest-fenced external
//! evidence. It has no AWS SDK, signer, credential resolver, HTTP client,
//! notification path, billing effect, kernel authority, or native Connected
//! claim. Fixture, recording, loopback, and `BLOCKED_ENV` transports are all
//! non-native and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    missing_debug_implementations,
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
    clippy::type_complexity,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsCostAnomalyConsumer, MissionAwsCostAnomalyResult, ProposalDisposition,
    RecordedAwsCostAnomalyResult,
};
pub use error::{AwsCostAnomalyError, AwsCostAnomalyTransportError, Result};
pub use model::*;
pub use provider::{
    AwsCostAnomalyOperation, AwsCostAnomalyProvider, AwsCostAnomalyProviderDefinition,
    AwsCostAnomalyTransport, BlockedEnvTransport, FixtureTransport, GetAnomaliesRequest,
    GetAnomaliesResponse, GetAnomalyMonitorsRequest, GetAnomalyMonitorsResponse,
    GetAnomalySubscriptionsRequest, GetAnomalySubscriptionsResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsCostAnomalyEvidenceRequest, AwsCostAnomalyProposal, AwsCostAnomalyRegistration,
    AwsCostAnomalyService, AwsCostAnomalyVerificationFailure, CapabilityDescription,
    FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-cost-anomaly-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSCOSTANOMALY-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.cost-anomaly.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.cost-anomaly.result.read";
pub const PROVIDER_ID: &str = "aws.cost-anomaly.result.recording";
pub const PROVIDER_API_REVISION: &str =
    "cost-anomaly-get-anomalies-get-monitors-get-subscriptions-1";
pub const CONSUMER_ID: &str = "mission.aws-cost-anomaly.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-cost-anomaly-result/v1|layer=1|service=aws.cost-anomaly.result.read|provider=aws.cost-anomaly.result.recording|consumer=mission.aws-cost-anomaly.consumer";
pub const CONTRACT_DIGEST: &str =
    "93dccd3efce1aea3684923496688c7317a57d1b92d586201aeb3628f013d745b";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-cost-anomaly-result/aws-cost-anomaly-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_RETENTION_DAYS: i64 = 90;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "ce:GetAnomalies",
    "ce:GetAnomalyMonitors",
    "ce:GetAnomalySubscriptions",
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
    use serde::Deserialize;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        layer: u8,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        external_writes: bool,
        kernel_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        native: bool,
        connected: bool,
        first_party: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        truth_authority: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract =
            serde_json::from_str::<ContractDocument>(CONTRACT_JSON).expect("checked contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_version, PLUGIN_VERSION);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.external_writes);
        assert!(!contract.service.kernel_authority);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(!contract.provider.native);
        assert!(!contract.provider.connected);
        assert!(!contract.provider.first_party);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.truth_authority);
    }
}
