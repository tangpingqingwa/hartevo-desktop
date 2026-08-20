//! Standalone Layer-1 governed Azure Policy Insights result plugin.
//!
//! This crate exposes a typed read/proposal/record/verify seam for bounded
//! Policy Insights queryResults evidence at resource, resource-group and
//! subscription scope. It never resolves Microsoft Entra credentials, sends
//! native HTTPS, mutates assignments or exemptions, triggers remediation,
//! retains raw policy/resource payloads, creates a kernel receipt, adopts an
//! Outcome, or claims compliance certification.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod consumer;
mod model;
mod provider;
mod query;
mod service;

pub use consumer::{
    MissionAzurePolicyConsumer, MissionAzurePolicyConsumerError, MissionAzurePolicyResult,
    MissionAzurePolicyResultState, MissionResultState,
};
pub use model::{
    AzurePolicyRegistration, AzurePolicyScope, ComplianceState, Digest, EntraAuthKind,
    EvidenceStatus, Layer1PolicyAuthority, MAX_FILTER_NODES, MAX_IDENTIFIER_BYTES,
    MAX_NEXT_LINK_BYTES, MAX_PAGES, MAX_RECORDS, MAX_RECORDS_PER_PAGE, MAX_RESOURCE_ID_BYTES,
    MAX_RESPONSE_BYTES, MAX_TIMESTAMP_BYTES, MissionBinding, MissionId, ModelError, ODataFilter,
    OpaqueNextLink, PermissionFence, PermissionFenceReceipt, PolicyFingerprints, PolicyQueryScope,
    PolicyStateRecord, PolicyStateView, ProjectBinding, ProjectId, ProviderErrorEvidence,
    ProviderErrorKind, ProviderProvenance, QueryBounds, QueryWindow, RegistrationRevocation,
    RegistrationState, ResourceGroupName, ResourceId, Revision, SecretReference, SubscriptionId,
    TenantId, Timestamp, WorkProductBinding, WorkProductId,
};
pub use provider::{
    AzurePolicyHttpRequest, AzurePolicyHttpResponse, AzurePolicyInsightsProvider, AzurePolicyPage,
    AzurePolicyProviderDefinition, AzurePolicyProviderError, AzurePolicyTransport,
    AzurePolicyTransportError, BlockedEnvAzurePolicyTransport, FakeAzurePolicyTransport,
    FixtureAzurePolicyTransport, LoopbackAzurePolicyTransport, ProviderDefinitionError,
    RecordingAzurePolicyTransport,
};
pub use query::{AzurePolicyQuery, AzurePolicyQueryProposal, AzurePolicyReadRequest, QueryError};
pub use service::{
    AzurePolicyComplianceProposal, AzurePolicyComplianceService,
    AzurePolicyComplianceServiceDefinition, AzurePolicyComplianceServiceError, AzurePolicyEvidence,
    AzurePolicyObservationReceipt, AzurePolicyResultService, ComplianceSummary,
};

pub const AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION: &str =
    "hartevo.azure-policy-compliance-result-contract/v1";
pub const AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION: &str =
    "azure-policy-compliance-result-e1/v1";
pub const AZURE_POLICY_COMPLIANCE_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID: &str = "azure.policy.compliance.result";
pub const AZURE_POLICY_INSIGHTS_PROVIDER_ID: &str = "azure.policy-insights.query-results";
pub const AZURE_POLICY_INSIGHTS_PROVIDER_VERSION: &str = "1.0.0";
pub const MISSION_AZURE_POLICY_CONSUMER_ID: &str = "mission.azure.policy.compliance.result";
pub const AZURE_POLICY_API_VERSION: &str = "2024-10-01";
pub const AZURE_POLICY_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/azure-policy-compliance-result/azure-policy-compliance-result.v1.json";
pub const AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-policy-compliance-result/azure-policy-compliance-result.v1.json"
);

pub type Layer1Authority = Layer1PolicyAuthority;
pub type AzurePolicyStateEvidence = PolicyStateRecord;
pub type AzurePolicyComplianceResult = AzurePolicyComplianceProposal;
pub type AzurePolicyComplianceState = ComplianceState;
pub type AzurePolicyResultStatus = EvidenceStatus;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn validate_contract() -> Result<(), String> {
    let document: serde_json::Value =
        serde_json::from_str(AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_JSON)
            .map_err(|error| error.to_string())?;
    let matches = document["schemaVersion"] == AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION
        && document["contractVersion"] == AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION
        && document["layer"] == 1
        && document["service"]["id"] == AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID
        && document["provider"]["id"] == AZURE_POLICY_INSIGHTS_PROVIDER_ID
        && document["provider"]["apiVersion"] == AZURE_POLICY_API_VERSION
        && document["consumer"]["id"] == MISSION_AZURE_POLICY_CONSUMER_ID
        && document["authority"]["connected"] == false
        && document["authority"]["nativeProvider"] == false
        && document["authority"]["externalWrites"] == false
        && document["authority"]["certification"] == false
        && document["authority"]["outcomeAuthority"] == false
        && document["queryPolicy"]["writes"]
            .as_array()
            .is_some_and(Vec::is_empty);
    if matches {
        Ok(())
    } else {
        Err("Azure Policy Layer-1 contract does not match its typed boundary".to_owned())
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        AZURE_POLICY_API_VERSION, AZURE_POLICY_BLOCKED_ENV,
        AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_JSON,
        AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION,
        AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION, AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID,
        AZURE_POLICY_INSIGHTS_PROVIDER_ID, AzurePolicyComplianceServiceDefinition,
        AzurePolicyProviderDefinition, MISSION_AZURE_POLICY_CONSUMER_ID, ProviderProvenance,
        contract_digest, validate_contract,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        validate_contract().expect("contract");
        let document: serde_json::Value =
            serde_json::from_str(AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_JSON)
                .expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document["service"]["id"],
            AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID
        );
        assert_eq!(
            document["provider"]["id"],
            AZURE_POLICY_INSIGHTS_PROVIDER_ID
        );
        assert_eq!(document["provider"]["apiVersion"], AZURE_POLICY_API_VERSION);
        assert_eq!(document["consumer"]["id"], MISSION_AZURE_POLICY_CONSUMER_ID);
        assert!(!contract_digest().as_str().is_empty());
        assert_eq!(AZURE_POLICY_BLOCKED_ENV, "BLOCKED_ENV");
        let provider = AzurePolicyProviderDefinition::new("1.0.0", ProviderProvenance::Recording)
            .expect("provider");
        assert!(!provider.native);
        assert!(!provider.https_transport);
        assert!(!provider.live_execution);
        let service = AzurePolicyComplianceServiceDefinition::default();
        assert!(service.read_only);
        assert!(!service.live_execution);
        assert!(!service.external_writes);
        assert!(!service.certification);
        assert!(!service.outcome_authority);
    }
}

#[cfg(test)]
mod adversarial_tests;
