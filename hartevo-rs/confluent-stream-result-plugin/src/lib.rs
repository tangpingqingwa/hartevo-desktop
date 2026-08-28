//! Layer-1 Confluent Cloud stream-result read, proposal, and recording boundary.
//!
//! This crate is deliberately standalone. It models exact Confluent Cloud
//! organization/environment/cluster/topic/connector/consumer-group/partition
//! scope and Mission bindings, but has no HTTP client, credential resolver,
//! Kafka record path, mutation capability, kernel authority, or native claim.
//! Fixture, recording, loopback, and `BLOCKED_ENV` transports are all
//! explicitly non-native and non-connected.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::use_self)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConfluentStreamResultProposal, MissionConfluentStreamConsumer, ProposalDisposition,
    RecordedStreamResult, StreamResultRecordingLog,
};
pub use model::{
    ApiKeyResourceScope, BoundedMetricDigest, ClusterId, ConfluentScope, ConfluentStreamScope,
    ConnectorId, ConnectorStatus, ConnectorStatusProjection, ConnectorTaskProjection,
    ConsumerGroupId, ConsumerGroupLagProjection, ConsumerGroupStatus, Digest, EnvironmentId,
    MetricKind, MetricProjection, MetricWindow, MissionId, OrganizationId, PartitionIdentity,
    PermissionSnapshot, PluginVersion, ProjectId, ProjectionCompleteness, RegistrationId,
    RegistrationStatus, ResourceIdentity, SecretKind, SecretReference, TaskStatus, TopicIdentity,
    TransportProvenance, WorkProductId,
};
pub use provider::{
    BlockedEnvTransport, ConfluentProvider, ConfluentProviderError, ConfluentTransport,
    ConfluentTransportError, ConnectorStatusReadRequest, ConnectorStatusResponse, FakeTransport,
    LagPage, LagReadRequest, LagRecord, LoopbackTransport, MetricPoint, MetricsReadRequest,
    MetricsResponse, RecordingTransport, TaskStatusRecord,
};
pub use service::{
    CapabilityDescription, ConfluentRegistration, ConfluentRegistrationRegistry,
    ConfluentStreamResultService, ProviderIdentity, RegistrationReceipt,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.confluent-stream-result-contract/v1";
pub const CONTRACT_VERSION: &str = "confluent-stream-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.confluent-stream-result-contract/v1|layer=1|service=confluent.stream-result.read|provider=confluent.cloud.stream-result|consumer=mission.confluent-stream-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "b1762e12b736e94d1978756127d0a7725143b2430b4144eaef718a4ee6a8b0a4";
pub const PLUGIN_ID: &str = "confluent.stream-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "confluent.stream-result.read";
pub const PROVIDER_ID: &str = "confluent.cloud.stream-result";
pub const PROVIDER_API_REVISION: &str = "cloud-connect-v1-kafka-v3-metrics-v2";
pub const CONSUMER_ID: &str = "mission.confluent-stream-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONNECTOR_STATUS_ENDPOINT_TEMPLATE: &str = "/connect/v1/environments/{environment_id}/clusters/{cluster_id}/connectors/{connector_id}/status";
pub const CONSUMER_GROUP_LAG_ENDPOINT_TEMPLATE: &str =
    "/kafka/v3/clusters/{cluster_id}/consumer-groups/{consumer_group_id}/lags";
pub const METRICS_QUERY_ENDPOINT: &str =
    "https://api.telemetry.confluent.cloud/v2/metrics/cloud/query";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/confluent-stream-result/contract.v1.json");

pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGES: usize = 16;
pub const MAX_PARTITIONS: usize = 256;
pub const MAX_METRIC_POINTS: usize = 512;
pub const MAX_TIMESTAMP_COUNT: usize = 512;
pub const MAX_OBSERVATION_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;

/// Layer-1 failures are bounded and never carry provider payloads or secret
/// bytes. Provider status classes are represented by the typed transport
/// error below.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfluentStreamResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid lowercase SHA-256 digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS host")]
    InvalidHttpsHost,
    #[error("invalid exact Confluent scope")]
    InvalidScope,
    #[error("invalid opaque resource-scoped API-key SecretReference")]
    InvalidSecretReference,
    #[error("invalid read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration/provider/API/scope/revision binding drifted")]
    RegistrationDrift,
    #[error(
        "scope does not match the exact registered organization/environment/cluster/topic/connector/group/partition scope"
    )]
    ScopeMismatch,
    #[error("organization scope drifted")]
    OrganizationDrift,
    #[error("environment scope drifted")]
    EnvironmentDrift,
    #[error("cluster scope drifted")]
    ClusterDrift,
    #[error("topic scope drifted")]
    TopicDrift,
    #[error("connector scope drifted")]
    ConnectorDrift,
    #[error("consumer-group scope drifted")]
    ConsumerGroupDrift,
    #[error("partition scope drifted")]
    PartitionDrift,
    #[error("Project scope drifted")]
    ProjectDrift,
    #[error("Mission scope drifted")]
    MissionDrift,
    #[error("Work Product scope drifted")]
    WorkProductDrift,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("connector revision or task revision regressed")]
    ConnectorTaskMonotonicity,
    #[error("consumer-group or partition revision regressed")]
    ConsumerGroupMonotonicity,
    #[error("invalid bounded projection")]
    InvalidProjection,
    #[error("metric window is invalid or not closed")]
    InvalidMetricWindow,
    #[error("metric window does not match the exact registered window")]
    MetricWindowMismatch,
    #[error("metric is not in the allowlist")]
    MetricNotAllowlisted,
    #[error("metric window is partial")]
    PartialMetricWindow,
    #[error("pagination repeated an opaque page token")]
    PaginationLoop,
    #[error("pagination exceeded its bound")]
    PaginationLimit,
    #[error("page size is outside the bound")]
    PageSizeLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider request or response failed its tamper check")]
    TamperedEvidence,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("provider error: {0}")]
    Provider(#[from] provider::ConfluentProviderError),
}

pub type Result<T> = std::result::Result<T, ConfluentStreamResultError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("typed contract values serialize");
    sha256_hex(&bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(ConfluentStreamResultError::InvalidDigest { field })
    }
}

pub(crate) fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ConfluentStreamResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        Ok(())
    } else {
        Err(ConfluentStreamResultError::InvalidIdentifier { field })
    }
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, PLUGIN_ID, contract_digest,
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
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract =
            serde_json::from_str::<ContractDocument>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!CONTRACT_JSON.contains("rawSecret"));
    }
}
