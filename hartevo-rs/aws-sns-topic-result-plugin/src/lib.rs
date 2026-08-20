//! Standalone Layer-1 AWS SNS topic-fanout result boundary.
//!
//! This crate owns only bounded metadata read proposals, redacted recording,
//! verification fences, and reversible registration. It intentionally remains
//! below Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, and
//! Work Product authority. No AWS SDK, SigV4 signer, credential resolver,
//! HTTPS client, message body, endpoint address, or SNS mutation is present.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
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

pub use consumer::{MissionAwsSnsConsumer, MissionAwsSnsResult, RecordedAwsSnsResult};
pub use error::{AwsSnsTopicError, AwsSnsTransportError, Result};
pub use model::*;
pub use provider::{
    AwsSnsOperation, AwsSnsProvider, AwsSnsProviderDefinition, AwsSnsTransport,
    BlockedEnvTransport, FixtureTransport, GetSubscriptionAttributesRequest,
    GetSubscriptionAttributesResponse, GetTopicAttributesRequest, GetTopicAttributesResponse,
    ListSubscriptionsByTopicRequest, ListSubscriptionsByTopicResponse, ListTopicsRequest,
    ListTopicsResponse, LoopbackTransport, OpaqueCursor, RecordedRequest, RecordingTransport,
    SubscriptionRecord, TopicRecord,
};
pub use service::{
    AwsSnsTopicEvidence, AwsSnsTopicProposal, AwsSnsTopicReadRequest, AwsSnsTopicRegistration,
    AwsSnsTopicService, CapabilityDescription, ConsentDisposition, EvidenceState, FailureEvidence,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-sns-topic-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-SNS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-sns-topic-result/v1|layer=1|service=aws.sns.topic-result.read|provider=aws.sns.topic-result.recording|consumer=mission.aws-sns-topic-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "020606b3145add1390a7cab6696dbe72af9268d5ad912637cf7027d6f8a52f53";
pub const PLUGIN_ID: &str = "aws.sns.topic-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.sns.topic-result.read";
pub const PROVIDER_ID: &str = "aws.sns.topic-result.recording";
pub const PROVIDER_API_REVISION: &str = "sns-list-topics-get-topic-attributes-list-subscriptions-by-topic-get-subscription-attributes-1";
pub const CONSUMER_ID: &str = "mission.aws-sns-topic-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-sns-topic-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 2_048;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "sns:ListTopics",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    "sns:GetSubscriptionAttributes",
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
        service: EndpointDocument,
        provider: EndpointDocument,
        consumer: ConsumerDocument,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EndpointDocument {
        id: String,
        read_only: Option<bool>,
        external_writes: Option<bool>,
        connected_evidence: Option<bool>,
        native_evidence: Option<bool>,
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
            .expect("checked AWS SNS contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert_eq!(contract.service.read_only, Some(true));
        assert_eq!(contract.service.external_writes, Some(false));
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert_eq!(contract.provider.connected_evidence, Some(false));
        assert_eq!(contract.provider.native_evidence, Some(false));
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
    }
}
