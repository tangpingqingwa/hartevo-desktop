//! Standalone Layer-1 NetSuite accounting-result proposal boundary.
//!
//! This root exposes typed `NetSuiteAccountingResultService`,
//! `NetSuiteSuiteTalkProvider`, and `MissionNetSuiteAccountingConsumer`
//! seams. It accepts only bounded, allowlisted SuiteTalk record metadata,
//! collection-filter, and selected-record GET-shaped evidence, plus a
//! parameterized SuiteQL proposal that is never executed. Fixture, recording,
//! loopback, and `BLOCKED_ENV` transports remain explicitly non-native and
//! non-Connected. Raw accounting payloads, financial PII, credentials,
//! arbitrary SuiteQL, scripts, RESTlets, and ERP effects are outside Layer 1.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    ConsumerError, MissionNetSuiteAccountingConsumer, MissionNetSuiteAccountingResult,
    MissionNetSuiteAccountingState, MissionNetSuiteSuiteQlResult,
};
pub use model::*;
pub use provider::{
    NetSuiteProviderDefinition, NetSuiteProviderError, NetSuiteProviderRead,
    NetSuiteProviderRevision, NetSuiteReadFailure, NetSuiteReadReceipt, NetSuiteRetryEvidence,
    NetSuiteSuiteTalkProvider, NetSuiteTransportProvenance, ProviderDefinitionError,
};
pub use service::{
    NetSuiteAccountingEvidence, NetSuiteAccountingProposal, NetSuiteAccountingProposalRequest,
    NetSuiteAccountingResultService, NetSuiteAccountingStatus, NetSuiteRedactions,
    NetSuiteRegistration, NetSuiteRegistrationState, NetSuiteServiceDefinition,
    NetSuiteServiceError, NetSuiteSuiteQlProposal, NetSuiteSuiteQlRecord,
};
pub use transport::{
    BlockedEnvNetSuiteTransport, FixtureNetSuiteTransport, LoopbackNetSuiteTransport,
    NetSuiteBlockedEnvTransport, NetSuiteFixtureTransport, NetSuiteGetRequest, NetSuiteGetResponse,
    NetSuiteHttpMethod, NetSuiteLoopbackTransport, NetSuiteSnapshot, NetSuiteSuiteTalkEndpoint,
    NetSuiteTransport, NetSuiteTransportError, NetSuiteTransportErrorKind, OpaqueCursor,
    RecordingNetSuiteTransport,
};

pub const NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION: &str =
    "hartevo.netsuite-accounting-result-contract/v1";
pub const NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION: &str = "netsuite-accounting-result/v1";
pub const NETSUITE_ACCOUNTING_RESULT_PLUGIN_ID: &str = "netsuite-accounting-result";
pub const NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const NETSUITE_ACCOUNTING_RESULT_SERVICE_ID: &str = "netsuite.accounting-result";
pub const NETSUITE_ACCOUNTING_RESULT_SERVICE_NAME: &str = "NetSuiteAccountingResultService";
pub const NETSUITE_PROVIDER_ID: &str = "netsuite.suitetalk";
pub const NETSUITE_PROVIDER_NAME: &str = "NetSuiteSuiteTalkProvider";
pub const MISSION_NETSUITE_ACCOUNTING_CONSUMER_ID: &str = "mission.netsuite-accounting-result";
pub const MISSION_NETSUITE_ACCOUNTING_CONSUMER_NAME: &str = "MissionNetSuiteAccountingConsumer";
pub const NETSUITE_ACCOUNTING_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/netsuite-accounting-result/netsuite-accounting-result.v1.json"
);
pub const NETSUITE_MAX_RESPONSE_BYTES: usize = model::MAX_RESPONSE_BYTES;
pub const NETSUITE_MAX_PAGES: u16 = model::MAX_PAGES;
pub const NETSUITE_PAGE_SIZE: u16 = model::MAX_PAGE_SIZE;
pub const NETSUITE_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// SHA-256 of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_text(NETSUITE_ACCOUNTING_RESULT_CONTRACT_JSON)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl std::fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteContract {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    #[serde(rename = "$id")]
    pub id: String,
    pub title: String,
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service: ContractService,
    pub provider: ContractProvider,
    pub consumer: ContractConsumer,
    pub scope: ContractScope,
    pub reads: ContractReads,
    #[serde(rename = "suiteQl")]
    pub suite_ql: ContractSuiteQl,
    pub evidence: ContractEvidence,
    pub registration: ContractRegistration,
    pub authority: ContractAuthority,
    pub honesty: ContractHonesty,
    pub distinctions: ContractDistinctions,
    pub layer2_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractService {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub live_execution: bool,
    pub writes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractProvider {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub transport: Vec<String>,
    pub operations: Vec<String>,
    pub native: bool,
    pub connected: bool,
    pub live_https: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractConsumer {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub mission_bound: bool,
    pub project_bound: bool,
    pub work_product_bound: bool,
    pub adopts_work_product: bool,
    pub outcome_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractScope {
    pub required: Vec<String>,
    pub secret_reference: String,
    pub digest: String,
    pub registration: String,
    pub record_id_for: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractReads {
    pub allow: Vec<String>,
    pub method: String,
    pub arbitrary_path: bool,
    pub arbitrary_query: bool,
    pub cursor: String,
    pub time_window: String,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractSuiteQl {
    pub allow: Vec<String>,
    pub parameterized: bool,
    pub arbitrary_query: bool,
    pub live_execution: bool,
    pub max_parameters: u8,
    pub max_query_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractEvidence {
    pub retain: Vec<String>,
    pub redact: Vec<String>,
    pub raw_provider_payload: bool,
    pub raw_financial_pii: bool,
    pub raw_suite_ql: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRegistration {
    pub version_bound: bool,
    pub contract_digest_bound: bool,
    pub provider_bound: bool,
    pub provider_definition_digest_bound: bool,
    pub permission_digest_bound: bool,
    pub scope_digest_bound: bool,
    pub secret_reference_bound: bool,
    pub credential_revision_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
    pub duplicate_proposal_rejected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractAuthority {
    pub read_only: bool,
    pub external_writes: bool,
    pub create: bool,
    pub update: bool,
    pub delete: bool,
    pub transform: bool,
    pub approve: bool,
    pub pay: bool,
    pub refund: bool,
    pub close: bool,
    pub dashboard: bool,
    pub erp_authority: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub receipt: bool,
    pub independent_readback: bool,
    pub work_product_adoption: bool,
    pub outcome: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractHonesty {
    pub fixture_native: bool,
    pub recording_native: bool,
    pub loopback_native: bool,
    pub blocked_env_native: bool,
    pub fixture_connected: bool,
    pub recording_connected: bool,
    pub loopback_connected: bool,
    pub blocked_env_connected: bool,
    pub absence_of_record_is_financial_truth: bool,
    pub absence_of_payment_is_settlement: bool,
    pub blocked_environment_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractDistinctions {
    pub not_this_plugin_issues: Vec<String>,
    pub not_this_plugin_providers: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ContractValidationError {
    #[error("checked-in NetSuite contract JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checked-in NetSuite contract does not match the Layer-1 implementation boundary")]
    Invalid,
}

impl NetSuiteContract {
    pub fn baseline() -> Result<Self, ContractValidationError> {
        let contract: Self = serde_json::from_str(NETSUITE_ACCOUNTING_RESULT_CONTRACT_JSON)?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), ContractValidationError> {
        let expected_service_operations = vec![
            "describe_capabilities",
            "register",
            "revoke_registration",
            "revoke_secret",
            "read_record_metadata",
            "read_record_collection",
            "read_selected_record",
            "compile_parameterized_suiteql_proposal",
            "record_suiteql_proposal",
            "consume_suiteql_proposal",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_provider_operations = vec![
            "GET /services/rest/record/v1/metadata-catalog",
            "GET /services/rest/record/v1/{recordType}",
            "GET /services/rest/record/v1/{recordType}/{recordId}",
            "PARAMETERIZED SUITEQL PROPOSAL (not executed)",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_scope = vec![
            "accountId",
            "dataCenter",
            "roleId",
            "recordType",
            "recordId",
            "collectionFilter",
            "observationWindow",
            "permissionDigest",
            "projectId",
            "projectRevision",
            "missionId",
            "missionRevision",
            "workProductId",
            "workProductRevision",
            "consentScope",
            "consentDigest",
            "secretReference",
            "credentialRevision",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let valid = self.schema_uri == "https://json-schema.org/draft/2020-12/schema"
            && self.id
                == "https://hartevo.local/contracts/plugins/netsuite-accounting-result/netsuite-accounting-result.v1.json"
            && self.title == "Hartevo NetSuite governed accounting-result Layer-1 contract"
            && self.schema_version == NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION
            && self.contract_version == NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION
            && self.layer == 1
            && self.service.id == NETSUITE_ACCOUNTING_RESULT_SERVICE_ID
            && self.service.version == NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION
            && self.service.implementation == NETSUITE_ACCOUNTING_RESULT_SERVICE_NAME
            && self.service.operations == expected_service_operations
            && self.service.read_only
            && !self.service.live_execution
            && !self.service.writes
            && self.provider.id == NETSUITE_PROVIDER_ID
            && self.provider.version == NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION
            && self.provider.implementation == NETSUITE_PROVIDER_NAME
            && self.provider.transport
                == vec![
                    "recording".to_owned(),
                    "fixture".to_owned(),
                    "loopback".to_owned(),
                    NETSUITE_BLOCKED_ENV.to_owned(),
                ]
            && self.provider.operations == expected_provider_operations
            && !self.provider.native
            && !self.provider.connected
            && !self.provider.live_https
            && self.consumer.id == MISSION_NETSUITE_ACCOUNTING_CONSUMER_ID
            && self.consumer.version == NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION
            && self.consumer.implementation == MISSION_NETSUITE_ACCOUNTING_CONSUMER_NAME
            && self.consumer.mission_bound
            && self.consumer.project_bound
            && self.consumer.work_product_bound
            && !self.consumer.adopts_work_product
            && !self.consumer.outcome_authority
            && self.scope.required == expected_scope
            && self.scope.secret_reference == "opaque_non_serializable_oauth2_or_tba_reference"
            && self.scope.digest == "sha256_lower_hex"
            && self.scope.registration
                == "version_contract_provider_permission_scope_secret_revision_bound"
            && self.scope.record_id_for == "selected_record_get; absent_only_for_collection_reads"
            && self.reads.allow
                == vec![
                    "bounded_record_metadata_get".to_owned(),
                    "bounded_record_collection_filter_get".to_owned(),
                    "bounded_selected_record_get".to_owned(),
                ]
            && self.reads.method == "GET"
            && !self.reads.arbitrary_path
            && !self.reads.arbitrary_query
            && self.reads.cursor == "opaque_digest_only"
            && self.reads.time_window == "bounded"
            && self.reads.max_pages == NETSUITE_MAX_PAGES
            && self.reads.page_size == NETSUITE_PAGE_SIZE
            && self.reads.max_response_bytes == NETSUITE_MAX_RESPONSE_BYTES
            && self.suite_ql.allow == vec!["parameterized_select_proposal".to_owned()]
            && self.suite_ql.parameterized
            && !self.suite_ql.arbitrary_query
            && !self.suite_ql.live_execution
            && self.suite_ql.max_parameters == model::MAX_SUITEQL_PARAMETERS as u8
            && self.suite_ql.max_query_bytes == model::MAX_SUITEQL_BYTES
            && !self.evidence.raw_provider_payload
            && !self.evidence.raw_financial_pii
            && !self.evidence.raw_suite_ql
            && self.registration.version_bound
            && self.registration.contract_digest_bound
            && self.registration.provider_bound
            && self.registration.provider_definition_digest_bound
            && self.registration.permission_digest_bound
            && self.registration.scope_digest_bound
            && self.registration.secret_reference_bound
            && self.registration.credential_revision_bound
            && self.registration.reversible
            && self.registration.revocable
            && self.registration.fail_closed_on_drift
            && self.registration.duplicate_proposal_rejected
            && self.authority.read_only
            && !self.authority.external_writes
            && !self.authority.create
            && !self.authority.update
            && !self.authority.delete
            && !self.authority.transform
            && !self.authority.approve
            && !self.authority.pay
            && !self.authority.refund
            && !self.authority.close
            && !self.authority.dashboard
            && !self.authority.erp_authority
            && !self.authority.connected
            && !self.authority.native_provider
            && !self.authority.receipt
            && !self.authority.independent_readback
            && !self.authority.work_product_adoption
            && !self.authority.outcome
            && !self.honesty.fixture_native
            && !self.honesty.recording_native
            && !self.honesty.loopback_native
            && !self.honesty.blocked_env_native
            && !self.honesty.fixture_connected
            && !self.honesty.recording_connected
            && !self.honesty.loopback_connected
            && !self.honesty.blocked_env_connected
            && !self.honesty.absence_of_record_is_financial_truth
            && !self.honesty.absence_of_payment_is_settlement
            && self.honesty.blocked_environment_status == NETSUITE_BLOCKED_ENV
            && self.distinctions.not_this_plugin_issues == vec!["407", "436", "430", "374"]
            && self.distinctions.not_this_plugin_providers
                == vec!["xero", "sap", "paddle", "aws_cost_explorer"]
            && !self.layer2_gaps.is_empty();
        if valid {
            Ok(())
        } else {
            Err(ContractValidationError::Invalid)
        }
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_is_valid_and_non_native() {
        let contract = NetSuiteContract::baseline().expect("contract baseline");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!contract.provider.native);
        assert!(!contract.provider.connected);
        assert!(!contract.service.writes);
        assert_eq!(NETSUITE_BLOCKED_ENV, "BLOCKED_ENV");
    }
}
