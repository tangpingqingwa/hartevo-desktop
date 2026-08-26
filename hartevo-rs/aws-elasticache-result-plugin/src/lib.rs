//! Standalone Layer-1 AWS ElastiCache health, failover, and update posture
//! result boundary.
//!
//! The crate is intentionally below Hartevo Truth, Effect, Receipt,
//! Verification, Outcome, durable Work Product, and kernel authority. It
//! models bounded read-shaped provider seams, redacted evidence, reversible
//! registration, and Mission review proposals only. Native SigV4 resolution,
//! live HTTPS, provider receipts, native rereads, and cache effects are
//! Layer-2 exits.

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
    ConsumerError, MissionAwsElastiCacheConsumer, MissionAwsElastiCacheConsumerError,
    MissionAwsElastiCacheDecisionState, MissionAwsElastiCacheResult,
};
pub use error::{AwsElastiCacheError, AwsElastiCacheTransportError, Result};
pub use model::*;
pub use provider::{
    AwsElastiCacheOperation, AwsElastiCacheProvider, AwsElastiCacheProviderDefinition,
    AwsElastiCacheTransport, BlockedEnvTransport, DescribeCacheClustersRequest,
    DescribeCacheClustersResponse, DescribeEventsRequest, DescribeEventsResponse,
    DescribeReplicationGroupsRequest, DescribeReplicationGroupsResponse,
    DescribeServiceUpdatesRequest, DescribeServiceUpdatesResponse, FakeAwsElastiCacheTransport,
    FakeTransport, FixtureAwsElastiCacheTransport, FixtureTransport,
    LoopbackAwsElastiCacheTransport, LoopbackTransport, RecordedRequest,
    RecordingAwsElastiCacheTransport, RecordingTransport, transport_error_for_status,
};
pub use service::{
    AwsElastiCacheEvidence, AwsElastiCacheProposal, AwsElastiCacheReadRequest,
    AwsElastiCacheReadResult, AwsElastiCacheRegistration, AwsElastiCacheService,
    CapabilityDescription, FailureEvidence, FailureKind, RecordedAwsElastiCacheResult,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-elasticache-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSELASTICACHE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-elasticache-result/v1|layer=1|service=aws.elasticache.result.read|provider=aws.elasticache.result.recording|consumer=mission.aws-elasticache.consumer";
pub const CONTRACT_DIGEST: &str =
    "c9e9791b4e7a2f030058bf57d2f0bc70bc2c7df89c64cb1c59c11e1ae471a9cd";
pub const PLUGIN_ID: &str = "aws.elasticache.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.elasticache.result.read";
pub const PROVIDER_ID: &str = "aws.elasticache.result.recording";
pub const API_REVISION: &str =
    "elasticache-describe-cache-clusters-replication-groups-events-service-updates-1";
pub const PROVIDER_API_REVISION: &str = API_REVISION;
pub const CONSUMER_ID: &str = "mission.aws-elasticache.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-elasticache-result/aws-elasticache-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_EVENTS: usize = 128;
pub const MAX_SERVICE_UPDATES: usize = 64;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_REQUEST_AGE_SECONDS: u64 = 900;
pub const MAX_STALENESS_SECONDS: u64 = 900;
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "elasticache:DescribeCacheClusters",
    "elasticache:DescribeReplicationGroups",
    "elasticache:DescribeEvents",
    "elasticache:DescribeServiceUpdates",
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
        API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
        SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        plugin_id: String,
        layer: String,
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
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        api_revision: String,
        connected_evidence: bool,
        native_evidence: bool,
        first_party_evidence: bool,
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
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked AWS ElastiCache contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_version, PLUGIN_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, "Layer-1");
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.external_writes);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert_eq!(contract.provider.api_revision, API_REVISION);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.first_party_evidence);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
        assert!(!contract.consumer.truth_authority);
    }
}
