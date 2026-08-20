//! Standalone Layer-1 governed AWS Kinesis Data Streams posture result boundary.
//!
//! This crate models only bounded `DescribeStreamSummary`, `ListShards`, and
//! optional exact-consumer metadata reads. It has no record path, capacity or
//! retention/encryption/consumer mutation, native SigV4 transport, provider
//! receipt, or Hartevo Truth/Consent/Effect/Receipt/Verification/Outcome or
//! Work Product authority. Fixture, recording, loopback, and `BLOCKED_ENV`
//! transports are always non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsKinesisConsumer, MissionAwsKinesisResult, ProposalDisposition,
    RecordedAwsKinesisResult,
};
pub use error::{
    AwsKinesisProviderError, AwsKinesisStreamResultError, AwsKinesisTransportError, Result,
};
pub use model::*;
pub use provider::{
    AwsKinesisOperation, AwsKinesisProvider, AwsKinesisProviderDefinition, AwsKinesisTransport,
    BlockedEnvTransport, DescribeStreamConsumerRequest, DescribeStreamConsumerResponse,
    DescribeStreamSummaryRequest, DescribeStreamSummaryResponse, FixtureTransport,
    ListShardsRequest, ListShardsResponse, LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsKinesisRegistration, AwsKinesisStreamResultProposal, AwsKinesisStreamResultRegistration,
    AwsKinesisStreamResultService, CapabilityDescription, FailureEvidence, KinesisEvidenceRequest,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub type AwsKinesisScope = AwsKinesisStreamScope;
pub type KinesisScope = AwsKinesisStreamScope;
pub type StreamResultProposal = AwsKinesisStreamResultProposal;
pub type AwsKinesisService<T> = AwsKinesisStreamResultService<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-kinesis-stream-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-KINESIS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-kinesis-stream-result/v1|layer=1|service=aws.kinesis.stream.result.read|provider=aws.kinesis.stream.result.recording|consumer=mission.aws-kinesis-stream-result.consumer|api=kinesis-describe-stream-summary-list-shards-describe-stream-consumer-2013-12-02-r1";
pub const CONTRACT_DIGEST: &str =
    "687a07177a9af75fe4ed7d4b33c62ddf71671de686023b241392487f74d59148";
pub const PLUGIN_ID: &str = "aws.kinesis.stream.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.kinesis.stream.result.read";
pub const PROVIDER_ID: &str = "aws.kinesis.stream.result.recording";
pub const PROVIDER_API_REVISION: &str =
    "kinesis-describe-stream-summary-list-shards-describe-stream-consumer-2013-12-02-r1";
pub const CONSUMER_ID: &str = "mission.aws-kinesis-stream-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_SHARDS: usize = 512;
pub const MAX_MONITORING_METRICS: usize = 32;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const NEXT_TOKEN_TTL_SECONDS: i64 = 300;
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "kinesis:DescribeStreamSummary",
    "kinesis:ListShards",
    "kinesis:DescribeStreamConsumer",
    "mission.scope",
];
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-kinesis-stream-result/aws-kinesis-stream-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn validate_contract() -> Result<()> {
    let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
        .map_err(|_| AwsKinesisStreamResultError::ContractDrift)?;
    let object = value
        .as_object()
        .ok_or(AwsKinesisStreamResultError::ContractDrift)?;
    for key in [
        "schemaVersion",
        "contractVersion",
        "pluginVersion",
        "pluginId",
        "layer",
        "evidenceLevel",
        "digestInput",
        "contractDigest",
        "service",
        "provider",
        "consumer",
        "credentials",
        "scope",
        "registration",
        "projection",
        "provenance",
        "authorityBoundary",
        "layer2Gaps",
    ] {
        if !object.contains_key(key) {
            return Err(AwsKinesisStreamResultError::ContractDrift);
        }
    }
    if object
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        != Some(CONTRACT_SCHEMA)
        || object
            .get("contractVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_VERSION)
        || object
            .get("pluginVersion")
            .and_then(serde_json::Value::as_str)
            != Some(PLUGIN_VERSION)
        || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || object
            .get("evidenceLevel")
            .and_then(serde_json::Value::as_str)
            != Some(EVIDENCE_LEVEL)
        || object
            .get("digestInput")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_DIGEST_INPUT)
        || object
            .get("contractDigest")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_DIGEST)
        || contract_digest() != CONTRACT_DIGEST
    {
        return Err(AwsKinesisStreamResultError::ContractDrift);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsKinesisStreamResultError::ContractDrift)?;
    if provider.get("connected") != Some(&serde_json::Value::Bool(false))
        || provider.get("native") != Some(&serde_json::Value::Bool(false))
        || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsKinesisStreamResultError::ContractDrift);
    }
    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsKinesisStreamResultError::ContractDrift)?;
    if consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
        || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsKinesisStreamResultError::ContractDrift);
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_and_honest() {
        validate_contract().expect("valid Kinesis contract");
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(CONTRACT_JSON).expect("contract JSON")["provider"]
                ["connected"],
            false
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::outcome_authority());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }
    pub const fn native() -> bool {
        false
    }
    pub const fn first_party() -> bool {
        false
    }
    pub const fn truth_authority() -> bool {
        false
    }
    pub const fn consent_authority() -> bool {
        false
    }
    pub const fn effect_authority() -> bool {
        false
    }
    pub const fn receipt_authority() -> bool {
        false
    }
    pub const fn verification_authority() -> bool {
        false
    }
    pub const fn outcome_authority() -> bool {
        false
    }
    pub const fn work_product_adoption() -> bool {
        false
    }
}
