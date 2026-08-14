//! Layer-1 governed Salesforce CRM result plugin.
//!
//! The crate owns a typed, read-only proposal/record/verify seam for bounded
//! Account, Opportunity, and Case evidence.  It can consume deterministic
//! fixture, recording, fake, and loopback responses, or fail closed as
//! `BLOCKED_ENV`.  It never resolves OAuth material, performs native HTTPS,
//! mutates Salesforce, retains raw payloads, becomes Inbox/Truth authority, or
//! adopts a Work Product outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionSalesforceCrmConsumer, MissionSalesforceCrmResult, MissionSalesforceResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, CollectedSalesforceResponses, FakeSalesforceTransport,
    FixtureSalesforceTransport, LoopbackSalesforceTransport, ProviderDefinitionError,
    RecordingSalesforceTransport, SalesforceHttpRequest, SalesforceHttpResponse, SalesforcePage,
    SalesforceProvider, SalesforceProviderDefinition, SalesforceTransport,
    SalesforceTransportError,
};
pub use service::{
    SalesforceCapability, SalesforceCrmResultService, SalesforceEvidence, SalesforceOperation,
    SalesforceReadProposal, SalesforceReadResult, SalesforceServiceDefinition,
    SalesforceVerification,
};

pub const SALESFORCE_CRM_RESULT_SCHEMA_VERSION: &str = "hartevo-salesforce-crm-result-contract/v1";
pub const SALESFORCE_CRM_RESULT_CONTRACT_VERSION: &str = "salesforce-crm-result-e1/v1";
pub const SALESFORCE_CRM_RESULT_PLUGIN_ID: &str = "salesforce-crm-result";
pub const SALESFORCE_CRM_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const SALESFORCE_CRM_RESULT_SERVICE_ID: &str = "salesforce.crm.result";
pub const SALESFORCE_CRM_RESULT_SERVICE_NAME: &str = "SalesforceCrmResultService";
pub const SALESFORCE_PROVIDER_ID: &str = "salesforce.crm.rest-graphql";
pub const SALESFORCE_PROVIDER_NAME: &str = "SalesforceProvider";
pub const MISSION_SALESFORCE_CRM_CONSUMER_ID: &str = "mission.salesforce.crm.result.consumer";
pub const MISSION_SALESFORCE_CRM_CONSUMER_NAME: &str = "MissionSalesforceCrmConsumer";
pub const SALESFORCE_CRM_RESULT_SERVICE_SCHEMA: &str = "hartevo.salesforce-crm-result-service/v1";
pub const SALESFORCE_PROVIDER_SCHEMA: &str = "hartevo.salesforce-provider/v1";
pub const MISSION_SALESFORCE_CRM_CONSUMER_SCHEMA: &str =
    "hartevo.mission-salesforce-crm-consumer/v1";
pub const SALESFORCE_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const SALESFORCE_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const SALESFORCE_API_ORIGIN: &str = "https://INSTANCE.my.salesforce.com";
pub const SALESFORCE_REST_QUERY_DOCS: &str =
    "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query.htm";
pub const SALESFORCE_REST_SOBJECT_DOCS: &str = "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_basic_info.htm";
pub const SALESFORCE_GRAPHQL_RECORD_OBJECTS_DOCS: &str =
    "https://developer.salesforce.com/docs/platform/graphql/guide/query-record-objects.html";
pub const SALESFORCE_MAX_FIELDS: usize = 32;
pub const SALESFORCE_MAX_RECORDS: usize = 8;
pub const SALESFORCE_MAX_PAGES: u8 = 4;
pub const SALESFORCE_MAX_APPROVAL_STEPS: u16 = 16;
pub const SALESFORCE_MAX_HISTORY_ENTRIES: u16 = 32;

pub const SALESFORCE_CRM_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/salesforce-crm-result/salesforce-crm-result.v1.json");

/// A digest of the exact checked-in contract document.
pub fn contract_digest() -> Digest {
    Digest::from_bytes(SALESFORCE_CRM_RESULT_CONTRACT_JSON.as_bytes())
}

/// The version bound into every proposal, registration, and evidence record.
pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// The Layer-1 authority boundary is intentionally all-false.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn independent_readback() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }

    pub const fn inbox_authority() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SalesforceCrmResultError {
    #[error("Salesforce CRM result contract is invalid: {0}")]
    Contract(String),
    #[error("Salesforce CRM result input is invalid: {0}")]
    InvalidInput(String),
    #[error("Salesforce CRM result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Salesforce CRM result provider mismatch: {0}")]
    ProviderMismatch(String),
    #[error("Salesforce CRM result version mismatch")]
    VersionMismatch,
    #[error("Salesforce CRM result contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Salesforce CRM result provider digest mismatch")]
    ProviderDigestMismatch,
    #[error("Salesforce CRM result proposal digest mismatch")]
    ProposalDigestMismatch,
    #[error("Salesforce CRM result evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("Salesforce CRM result registration is revoked")]
    RegistrationRevoked,
    #[error("Salesforce CRM result registration drifted: {0}")]
    RegistrationDrift(String),
    #[error("Salesforce CRM result OAuth reference is revoked")]
    SecretRevoked,
    #[error("Salesforce CRM result object is outside the registered allowlist")]
    ObjectOutOfScope,
    #[error("Salesforce CRM result field is outside the registered allowlist")]
    FieldOutOfScope,
    #[error("Salesforce CRM result field is not valid for the requested object")]
    FieldObjectMismatch,
    #[error("Salesforce CRM result record revision fence mismatch")]
    RecordRevisionMismatch,
    #[error("Salesforce CRM result response object or record drifted")]
    RecordDrift,
    #[error("Salesforce CRM result response contains an invalid or unsafe projection")]
    UnsafeProjection,
    #[error("Salesforce CRM result pagination loop detected")]
    PaginationLoop,
    #[error("Salesforce CRM result pagination bound exceeded")]
    PaginationBoundExceeded,
    #[error("Salesforce CRM result evidence was tampered")]
    TamperedEvidence,
    #[error("Salesforce CRM result provider transport failed: {0}")]
    Transport(String),
    #[error("Salesforce CRM result Mission consumer rejected evidence: {0}")]
    Consumer(String),
}

impl From<model::ModelError> for SalesforceCrmResultError {
    fn from(error: model::ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

impl From<provider::ProviderDefinitionError> for SalesforceCrmResultError {
    fn from(error: provider::ProviderDefinitionError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceCrmResultContract {
    #[serde(rename = "$schema")]
    pub json_schema: String,
    #[serde(rename = "$id")]
    pub document_id: String,
    pub schema_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub layer: u8,
    pub service: SalesforceServiceContract,
    pub provider: SalesforceProviderContract,
    pub consumer: SalesforceConsumerContract,
    pub official_api_basis: SalesforceOfficialApiBasis,
    pub scope: SalesforceScopeContract,
    pub allowlist: SalesforceAllowlistContract,
    pub evidence: SalesforceEvidenceContract,
    pub registration: SalesforceRegistrationContract,
    pub authority: SalesforceAuthorityContract,
    pub native_claims: SalesforceNativeClaimsContract,
    pub layer2_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceServiceContract {
    pub id: String,
    pub name: String,
    pub version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub live_execution: bool,
    pub mutations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceProviderContract {
    pub id: String,
    pub name: String,
    pub version: String,
    pub operations: Vec<String>,
    pub objects: Vec<String>,
    pub accepted_provenance: Vec<String>,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceConsumerContract {
    pub id: String,
    pub name: String,
    pub mission_bound: bool,
    pub project_bound: bool,
    pub work_product_bound: bool,
    pub adopts_outcome: bool,
    pub truth_authority: bool,
    pub inbox_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceOfficialApiBasis {
    pub rest_query: String,
    pub rest_s_object: String,
    pub graphql_record_objects: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceScopeContract {
    pub required: Vec<String>,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceAllowlistContract {
    pub objects: Vec<String>,
    pub field_policy: String,
    pub approval: Vec<String>,
    pub history: Vec<String>,
    pub redacted: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceEvidenceContract {
    pub digests: Vec<String>,
    pub bounded: Vec<String>,
    pub next_records_url: String,
    pub raw_payload_retained: bool,
    pub retries: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceRegistrationContract {
    pub version_bound: bool,
    pub provider_bound: bool,
    pub contract_bound: bool,
    pub scope_bound: bool,
    pub permission_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceAuthorityContract {
    pub external_writes: bool,
    pub composite_writes: bool,
    pub email_send: bool,
    pub case_comments: bool,
    pub approval_mutation: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub work_product_adoption: bool,
    pub inbox_authority: bool,
    pub truth_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceNativeClaimsContract {
    pub connected: bool,
    pub native_provider: bool,
    pub durable_receipt: bool,
    pub adopted_outcome: bool,
    pub blocked_environment_is_native: bool,
}

impl SalesforceCrmResultContract {
    pub fn baseline() -> Result<Self, SalesforceCrmResultError> {
        let contract = serde_json::from_str::<Self>(SALESFORCE_CRM_RESULT_CONTRACT_JSON)
            .map_err(|error| SalesforceCrmResultError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), SalesforceCrmResultError> {
        let expected_operations = [
            "describe", "register", "revoke", "restore", "propose", "record", "verify",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_provider_operations = ["rest_query", "graphql_query"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let expected_objects = ["Account", "Opportunity", "Case"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let required_scope = [
            "organization",
            "instance",
            "apiVersion",
            "allowlistedObjects",
            "allowlistedFields",
            "record",
            "recordRevision",
            "mission",
            "missionRevision",
            "project",
            "projectRevision",
            "workProduct",
            "workProductRevision",
            "permissionDigest",
            "consentDigest",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_redacted = ["contacts", "emails", "addresses", "notes", "rawPayload"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let authority_is_false = [
            self.authority.external_writes,
            self.authority.composite_writes,
            self.authority.email_send,
            self.authority.case_comments,
            self.authority.approval_mutation,
            self.authority.connected,
            self.authority.native_provider,
            self.authority.durable_receipt,
            self.authority.independent_readback,
            self.authority.work_product_adoption,
            self.authority.inbox_authority,
            self.authority.truth_authority,
            self.native_claims.connected,
            self.native_claims.native_provider,
            self.native_claims.durable_receipt,
            self.native_claims.adopted_outcome,
            self.native_claims.blocked_environment_is_native,
        ]
        .into_iter()
        .any(std::convert::identity);
        if self.schema_version != SALESFORCE_CRM_RESULT_SCHEMA_VERSION
            || self.contract_version != SALESFORCE_CRM_RESULT_CONTRACT_VERSION
            || self.evidence_level != "E1"
            || self.layer != 1
            || self.service.id != SALESFORCE_CRM_RESULT_SERVICE_ID
            || self.service.name != SALESFORCE_CRM_RESULT_SERVICE_NAME
            || self.service.version != SALESFORCE_CRM_RESULT_PLUGIN_VERSION_TEXT
            || self.service.operations != expected_operations
            || !self.service.read_only
            || self.service.live_execution
            || !self.service.mutations.is_empty()
            || self.provider.id != SALESFORCE_PROVIDER_ID
            || self.provider.name != SALESFORCE_PROVIDER_NAME
            || self.provider.version != SALESFORCE_PROVIDER_VERSION_TEXT
            || self.provider.operations != expected_provider_operations
            || self.provider.objects != expected_objects
            || self.provider.native
            || self.consumer.id != MISSION_SALESFORCE_CRM_CONSUMER_ID
            || self.consumer.name != MISSION_SALESFORCE_CRM_CONSUMER_NAME
            || !self.consumer.mission_bound
            || !self.consumer.project_bound
            || !self.consumer.work_product_bound
            || self.consumer.adopts_outcome
            || self.consumer.truth_authority
            || self.consumer.inbox_authority
            || self.official_api_basis.rest_query != SALESFORCE_REST_QUERY_DOCS
            || self.official_api_basis.rest_s_object != SALESFORCE_REST_SOBJECT_DOCS
            || self.official_api_basis.graphql_record_objects
                != SALESFORCE_GRAPHQL_RECORD_OBJECTS_DOCS
            || self.scope.required != required_scope
            || self.scope.secret != "opaque_non_serializing_oauth_secret_reference"
            || self.allowlist.objects != expected_objects
            || self.allowlist.field_policy != "typed_enum_only"
            || self.allowlist.redacted != expected_redacted
            || !self.evidence.digests.iter().any(|value| value == "scope")
            || !self
                .evidence
                .digests
                .iter()
                .any(|value| value == "evidence")
            || self.evidence.next_records_url != "digest_only"
            || self.evidence.raw_payload_retained
            || !self.registration.version_bound
            || !self.registration.provider_bound
            || !self.registration.contract_bound
            || !self.registration.scope_bound
            || !self.registration.permission_bound
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || authority_is_false
            || self.layer2_gaps.is_empty()
        {
            return Err(SalesforceCrmResultError::Contract(
                "checked-in Salesforce CRM result contract drifted from the Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn contract_document_and_authority_boundary_are_exact() {
        let contract = SalesforceCrmResultContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(contract.provider.accepted_provenance.len(), 5);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::independent_readback());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::inbox_authority());
        assert!(!Layer1Authority::truth_authority());
        assert_eq!(SALESFORCE_BLOCKED_ENV, "BLOCKED_ENV");
    }
}
