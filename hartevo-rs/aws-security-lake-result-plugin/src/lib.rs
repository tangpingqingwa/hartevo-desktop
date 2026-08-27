//! Standalone Layer-1 AWS Security Lake configuration and source-health boundary.
//!
//! This crate owns bounded read/proposal/record/verify seams for lake status,
//! log-source posture, static source snapshots, and recent exception
//! categories. It intentionally has no AWS SDK, SigV4 signer, credential
//! resolver, live HTTPS client, source/subscriber mutation, security-event
//! export, kernel authority, or native Connected claim.

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
    MissionAwsSecurityLakeConsumer, MissionAwsSecurityLakeResult, ProposalDisposition,
    RecordedAwsSecurityLakeResult,
};
pub use error::{AwsSecurityLakeError, AwsSecurityLakeTransportError, Result};
pub use model::*;
pub use provider::{
    AwsSecurityLakeProvider, AwsSecurityLakeProviderDefinition, AwsSecurityLakeTransport,
    BlockedEnvAwsSecurityLakeTransport, BlockedEnvTransport, FixtureAwsSecurityLakeTransport,
    FixtureTransport, LoopbackAwsSecurityLakeTransport, LoopbackTransport, RecordedRequest,
    RecordingAwsSecurityLakeTransport, RecordingTransport,
};
pub use service::{
    AwsSecurityLakeCapabilities, AwsSecurityLakeEvidence, AwsSecurityLakeProposal,
    AwsSecurityLakeRegistration, AwsSecurityLakeService, EvidenceDigests, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-security-lake-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-SECURITY-LAKE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-security-lake-result/v1|layer=1|service=aws.securitylake.result.read|provider=aws.securitylake.result.recording|consumer=mission.aws-security-lake.consumer";
pub const CONTRACT_DIGEST: &str =
    "5cb92d1905d14e87e232666e54b7dbfc01e9db6d18f319d97b3f2ad59a469887";
pub const PLUGIN_ID: &str = "aws.securitylake.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.securitylake.result.read";
pub const PROVIDER_ID: &str = "aws.securitylake.result.recording";
pub const PROVIDER_API_REVISION: &str =
    "securitylake-list-datalakes-list-logsources-get-datalakesources-list-exceptions-1";
pub const CONSUMER_ID: &str = "mission.aws-security-lake.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-security-lake-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TOKEN_BYTES: usize = 2_048;
pub const MAX_TOKEN_TTL_HOURS: i64 = 24;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_ACCOUNTS: usize = 256;
pub const MAX_REGIONS: usize = 32;
pub const MAX_SOURCES: usize = 128;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "securitylake:ListDataLakes",
    "securitylake:ListLogSources",
    "securitylake:GetDataLakeSources",
    "securitylake:ListDataLakeExceptions",
    "mission.scope",
];

pub fn contract_digest() -> String {
    hex::encode(Sha256::digest(CONTRACT_DIGEST_INPUT.as_bytes()))
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
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
        connected: bool,
        native: bool,
        first_party: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        adopts_work_product: bool,
        truth_authority: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract =
            serde_json::from_str::<ContractDocument>(CONTRACT_JSON).expect("checked contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
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
        assert!(!contract.provider.connected);
        assert!(!contract.provider.native);
        assert!(!contract.provider.first_party);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
        assert!(!contract.consumer.truth_authority);
    }
}
