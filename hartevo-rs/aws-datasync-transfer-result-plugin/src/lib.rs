//! Standalone Layer-1 AWS DataSync transfer-result boundary.
//!
//! This crate exposes bounded, read-only DataSync task and execution evidence
//! for a Mission review. It deliberately stops below kernel Truth, Effect,
//! Receipt, Verification, Outcome, and durable Work Product authority.
//! Provider inputs are converted immediately into identifier, counter, state,
//! and digest-only projections; paths, object names, reports, logs, PII, and
//! credential material are never retained in the public evidence model.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
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

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsDataSyncConsumer, MissionAwsDataSyncResult, ProposalDisposition,
    RecordedAwsDataSyncResult,
};
pub use error::{AwsDataSyncTransferError, Result};
pub use model::*;
pub use provider::{
    AwsDataSyncOperation, AwsDataSyncProvider, AwsDataSyncProviderDefinition, AwsDataSyncTransport,
    AwsDataSyncTransportError, BlockedEnvTransport, DescribeTaskExecutionRequest,
    DescribeTaskExecutionResponse, DescribeTaskRequest, DescribeTaskResponse, FixtureTransport,
    ListTaskExecutionsRequest, ListTaskExecutionsResponse, ListTasksRequest, ListTasksResponse,
    LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsDataSyncRegistration, AwsDataSyncTransferProposal, AwsDataSyncTransferService,
    CapabilityDescription, RegistrationStatus, RegistrationTransitionEvidence, RetryEvidence,
    TransferEvidenceRequest, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-datasync-transfer-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-DATASYNC-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-datasync-transfer-result/v1|layer=1|service=aws.datasync.transfer-result.read|provider=aws.datasync.transfer-result.recording|consumer=mission.aws-datasync-transfer-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "ceabc8364a08fc80bc121ce235d726d9c477b33db8283e9dd36a7c76a0909a10";
pub const PLUGIN_ID: &str = "aws.datasync.transfer-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.datasync.transfer-result.read";
pub const PROVIDER_ID: &str = "aws.datasync.transfer-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "datasync-describe-task-describe-task-execution-list-tasks-list-task-executions-1";
pub const CONSUMER_ID: &str = "mission.aws-datasync-transfer-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-datasync-transfer-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_COUNTER_VALUE: u64 = 1_000_000_000_000;
pub const MAX_RECEIPTS: usize = 32;
pub const MAX_FAILURES: usize = 16;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "datasync:DescribeTask",
    "datasync:DescribeTaskExecution",
    "datasync:ListTasks",
    "datasync:ListTaskExecutions",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Creates the inert plugin-runtime contribution set for one exact
/// Project/Mission generation. Mounting remains host-owned and reversible.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition> {
    let plugin_id = PluginId::new(PLUGIN_ID)?;
    let service_id = ServiceId::new(SERVICE_ID)?;
    let provider_id = ProviderId::new(PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

pub const SERVICE_SCHEMA: &str = "hartevo.aws-datasync-transfer-result-service/v1";
pub const PROVIDER_SCHEMA: &str = "hartevo.aws-datasync-transfer-result-provider/v1";
pub const CONSUMER_SCHEMA: &str = "hartevo.mission-aws-datasync-transfer-result-consumer/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDataSyncTransferContract {
    #[serde(rename = "$schema")]
    pub schema_url: String,
    #[serde(rename = "$id")]
    pub contract_id: String,
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub layer: u8,
    pub evidence_level: String,
    pub digest_input: String,
    pub contract_digest: String,
    pub service: ContractService,
    pub provider: ContractProvider,
    pub consumer: ContractConsumer,
    pub scope: ContractScope,
    pub evidence: ContractEvidence,
    pub pagination: ContractPagination,
    pub receipts: ContractReceipts,
    pub registration: ContractRegistration,
    pub native_claims: ContractNativeClaims,
    pub layer2_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractService {
    pub id: String,
    pub version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub external_writes: bool,
    pub mutations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractProvider {
    pub id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub accepted_provenance: Vec<String>,
    pub connected_evidence: bool,
    pub native_evidence: bool,
    pub durable_provider_receipt: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractConsumer {
    pub id: String,
    pub mission_bound: bool,
    pub project_bound: bool,
    pub work_product_bound: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub truth_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractScope {
    pub required: Vec<String>,
    pub secret: String,
    pub fences: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractEvidence {
    pub states: Vec<String>,
    pub bounded_counters: bool,
    pub transfer_report: String,
    pub raw_paths: bool,
    pub raw_object_names: bool,
    pub raw_reports: bool,
    pub raw_logs: bool,
    pub pii: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractPagination {
    pub opaque_cursor: bool,
    pub max_page_size: u16,
    pub max_pages: u16,
    pub raw_token_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractReceipts {
    pub request_digest: bool,
    pub response_digest: bool,
    pub path_digest: bool,
    pub status: bool,
    pub response_bytes: bool,
    pub provider_revision: bool,
    pub raw_payload: bool,
    pub raw_report: bool,
    pub raw_logs: bool,
    pub credential_material: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRegistration {
    pub provider_api_contract_version_bound: bool,
    pub permission_bound: bool,
    pub scope_bound: bool,
    pub task_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractNativeClaims {
    pub connected: bool,
    pub native_provider: bool,
    pub durable_receipt: bool,
    pub destination_readback: bool,
    pub consented_transfer_effect: bool,
    pub adopted_outcome: bool,
    pub blocked_environment_is_native: bool,
}

impl AwsDataSyncTransferContract {
    pub fn baseline() -> Result<Self> {
        let contract = serde_json::from_str::<Self>(CONTRACT_JSON)
            .map_err(|error| AwsDataSyncTransferError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> String {
        self.contract_digest.clone()
    }

    pub fn validate(&self) -> Result<()> {
        let expected_operations = [
            "DescribeTask",
            "DescribeTaskExecution",
            "ListTasks",
            "ListTaskExecutions",
            "proposal",
            "record",
            "verify",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_states = [
            "QUEUED",
            "LAUNCHING",
            "PREPARING",
            "TRANSFERRING",
            "VERIFYING",
            "SUCCESS",
            "ERROR",
            "CANCELLING",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if self.schema_url != "https://json-schema.org/draft/2020-12/schema"
            || self.contract_id
                != "https://hartevo.local/contracts/plugins/aws-datasync-transfer-result/contract.v1.json"
            || self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.plugin_id != PLUGIN_ID
            || self.layer != 1
            || self.evidence_level != EVIDENCE_LEVEL
            || self.digest_input != CONTRACT_DIGEST_INPUT
            || self.contract_digest != contract_digest()
            || self.service.id != SERVICE_ID
            || self.service.version != PLUGIN_VERSION
            || self.service.operations != expected_operations
            || !self.service.read_only
            || self.service.external_writes
            || !self.service.mutations.is_empty()
            || self.provider.id != PROVIDER_ID
            || self.provider.api_revision != PROVIDER_API_REVISION
            || self.provider.operations
                != LAYER1_PERMISSIONS[..LAYER1_PERMISSIONS.len() - 1]
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<Vec<_>>()
            || self.provider.accepted_provenance
                != ["recording", "fixture", "loopback", "blocked_env"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            || self.provider.connected_evidence
            || self.provider.native_evidence
            || self.provider.durable_provider_receipt
            || self.consumer.id != CONSUMER_ID
            || !self.consumer.mission_bound
            || !self.consumer.project_bound
            || !self.consumer.work_product_bound
            || self.consumer.adopts_outcome
            || self.consumer.adopts_work_product
            || self.consumer.truth_authority
            || self.scope.secret != "opaque_non_serializing_sigv4_reference"
            || !self.evidence.bounded_counters
            || self.evidence.transfer_report != "digest_only"
            || self.evidence.raw_paths
            || self.evidence.raw_object_names
            || self.evidence.raw_reports
            || self.evidence.raw_logs
            || self.evidence.pii
            || self.evidence.states != expected_states
            || !self.pagination.opaque_cursor
            || self.pagination.max_page_size != MAX_PAGE_SIZE
            || self.pagination.max_pages != MAX_PAGES
            || self.pagination.raw_token_retained
            || !self.receipts.request_digest
            || !self.receipts.response_digest
            || !self.receipts.path_digest
            || !self.receipts.status
            || !self.receipts.response_bytes
            || !self.receipts.provider_revision
            || self.receipts.raw_payload
            || self.receipts.raw_report
            || self.receipts.raw_logs
            || self.receipts.credential_material
            || !self.registration.provider_api_contract_version_bound
            || !self.registration.permission_bound
            || !self.registration.scope_bound
            || !self.registration.task_bound
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.native_claims.connected
            || self.native_claims.native_provider
            || self.native_claims.durable_receipt
            || self.native_claims.destination_readback
            || self.native_claims.consented_transfer_effect
            || self.native_claims.adopted_outcome
            || self.native_claims.blocked_environment_is_native
            || self.layer2_gaps.is_empty()
        {
            return Err(AwsDataSyncTransferError::Contract(
                "checked AWS DataSync Layer-1 contract drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{
        AwsDataSyncTransferContract, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, PLUGIN_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_bounded_and_non_native() {
        let contract = AwsDataSyncTransferContract::baseline().expect("contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, contract_digest());
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.native_claims.blocked_environment_is_native);
        assert!(serde_json::from_str::<serde_json::Value>(CONTRACT_JSON).is_ok());
    }
}
