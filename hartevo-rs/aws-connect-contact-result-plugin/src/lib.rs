//! Standalone Layer-1 Amazon Connect contact-result boundary.
//!
//! The crate is below Hartevo Truth, Effect, Receipt, Verification, Work
//! Product, and Outcome authority. It provides bounded typed read proposals
//! and redacted receipt candidates over recording, fixture, loopback, and
//! `BLOCKED_ENV` transports only. None of those transports is Connected or
//! native.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_field_names,
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
    AwsConnectContactReceiptCandidate, MissionAwsConnectContactConsumer,
    MissionAwsConnectContactResult, ProposalDisposition,
};
pub use error::{AwsConnectContactResultError, AwsConnectTransportError, Result};
pub use model::*;
pub use provider::{
    AwsConnectProvider, AwsConnectProviderDefinition, AwsConnectTransport, BlockedEnvTransport,
    FixtureTransport, LoopbackTransport, RecordingTransport,
};
pub use service::{
    AwsConnectContactResultProposal, AwsConnectContactResultRegistration,
    AwsConnectContactResultService, AwsConnectRegistration, CapabilityDescription,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-connect-contact-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSCONNECTCONTACT-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-connect-contact-result/v1|layer=1|service=aws.connect.contact-result.read|provider=aws.connect.contact-result.recording|consumer=mission.aws-connect-contact-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "18b801ab3402be0f076f5c0f91777e942afdc3f7bcea1a923fb0e151e771f653";
pub const PLUGIN_ID: &str = "aws.connect.contact-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.connect.contact-result.read";
pub const PROVIDER_ID: &str = "aws.connect.contact-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "connect-search-contacts-describe-contact-get-contact-attributes-1";
pub const CONSUMER_ID: &str = "mission.aws-connect-contact-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-connect-contact-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_ATTRIBUTES: usize = 16;
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "connect:SearchContacts",
    "connect:DescribeContact",
    "connect:GetContactAttributes",
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
        outcome_adoption: bool,
        work_product_adoption: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        connected_evidence: bool,
        native_evidence: bool,
        live_https: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        adopts_work_product: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked Amazon Connect contract");
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
        assert!(!contract.service.outcome_adoption);
        assert!(!contract.service.work_product_adoption);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.live_https);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
    }
}
