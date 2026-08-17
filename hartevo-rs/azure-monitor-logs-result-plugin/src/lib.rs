//! Layer-1 governed Azure Monitor Logs aggregate-result plugin.
//!
//! This crate is intentionally standalone. It defines a versioned contract,
//! an allowlisted aggregate KQL AST, an exact Azure/provider and
//! Project/Mission/Work Product scope, a fixture/recording/loopback provider
//! seam, and a bounded Mission consumer. It never resolves Entra credentials,
//! performs native HTTPS, stores raw logs, or claims Hartevo Truth, Consent,
//! Effect, Receipt, Verification, Outcome, or Work Product authority.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod query;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, MissionAzureMonitorLogsConsumer, MissionAzureMonitorLogsObservation,
};
pub use model::{
    AggregateCell, AggregateColumn, AggregateColumnType, AggregateRow, AggregateSchema,
    AzureMonitorLogsScope, ColumnName, ConsumerId, Digest, Layer1Authority, MAX_AGGREGATES,
    MAX_CELL_TEXT_BYTES, MAX_COST_MICROUNITS, MAX_DURATION_MS, MAX_GROUP_BY_COLUMNS,
    MAX_PARAMETERS, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES, MAX_RESPONSE_ROWS, MAX_WINDOW_DAYS,
    MissionId, ModelError, ParameterName, ProjectId, ProviderId, QueryBounds, QueryTemplateId,
    RegistrationState, RegistrationTransition, ResultStatus, Revision, SecretReference, ServiceId,
    SubscriptionId, TableName, TenantId, TimeWindow, Timestamp, WorkProductId, WorkspaceId,
};
pub use provider::{
    AzureMonitorLogsProvider, AzureMonitorLogsProviderDefinition, AzureMonitorLogsProviderPort,
    AzureMonitorLogsRequest, AzureMonitorLogsResponse, AzureMonitorLogsTransport,
    BlockedEnvAzureMonitorLogsTransport, BlockedEnvTransport, FixtureAzureMonitorLogsTransport,
    LoopbackAzureMonitorLogsTransport, ProviderDefinitionError, ProviderError, ProviderErrorKind,
    ProviderProvenance, ProviderResultStatus, RecordingAzureMonitorLogsTransport,
    empty_response_for_request, has_only_bounded_aggregate_cells, provenance_flags,
    response_contains_duplicate_rows, row_count,
};
pub use query::{
    AggregateFunction, AggregateSpec, FilterClause, ParameterValue, QueryError, QueryParameter,
    QueryPlan, QueryTemplate,
};
pub use service::{
    AzureMonitorLogsOutcomeService, AzureMonitorLogsRegistration, AzureMonitorLogsResult,
    AzureMonitorLogsResultService, AzureMonitorLogsServiceDefinition, ProviderErrorSummary,
    ServiceError,
};

pub const AZURE_MONITOR_LOGS_SCHEMA_VERSION: &str = "hartevo.azure-monitor-logs-result-contract/v1";
pub const AZURE_MONITOR_LOGS_CONTRACT_VERSION: &str = "EXT-AZURE-MONITOR-LOGS-01-L1/v1";
pub const AZURE_MONITOR_LOGS_SERVICE_ID: &str = "azure.monitor.logs.result";
pub const AZURE_MONITOR_LOGS_PROVIDER_ID: &str = "azure.monitor.logs.query";
pub const MISSION_AZURE_MONITOR_LOGS_CONSUMER_ID: &str = "mission.azure-monitor-logs.result";
pub const AZURE_MONITOR_LOGS_SERVICE_VERSION: &str = "1.0.0";
pub const AZURE_MONITOR_LOGS_PROVIDER_VERSION: &str = "1.0.0";
pub const AZURE_MONITOR_LOGS_API_REVISION: &str = "logs-query-v1";
pub const AZURE_MONITOR_LOGS_QUERY_PATH: &str = "/v1/workspaces/{workspaceId}/query";
pub const AZURE_MONITOR_LOGS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-monitor-logs-result/azure-monitor-logs-result.v1.json"
);

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract metadata field {0} is missing or invalid")]
    Field(&'static str),
}

pub fn contract_digest() -> Digest {
    Digest::from_text(AZURE_MONITOR_LOGS_CONTRACT_JSON)
}

pub fn validate_contract_document() -> Result<(), ContractValidationError> {
    use serde_json::Value;

    let document = serde_json::from_str::<Value>(AZURE_MONITOR_LOGS_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let identity = model::contract_identity_fields();
    let expected = [
        ("schemaVersion", identity[0].as_str()),
        ("contractVersion", identity[1].as_str()),
    ];
    for (field, value) in expected {
        if document.get(field).and_then(Value::as_str) != Some(value) {
            return Err(ContractValidationError::Field(field));
        }
    }
    if document.get("layer").and_then(Value::as_u64) != Some(1)
        || document.get("pluginId").and_then(Value::as_str) != Some("azure.monitor.logs.result")
        || document.get("evidenceLevel").and_then(Value::as_str) != Some("L1_PROVIDER_CONTRACT")
    {
        return Err(ContractValidationError::Field(
            "layer/pluginId/evidenceLevel",
        ));
    }
    let service = document
        .get("service")
        .ok_or(ContractValidationError::Field("service"))?;
    if service.get("id").and_then(Value::as_str) != Some(AZURE_MONITOR_LOGS_SERVICE_ID)
        || service.get("readOnly").and_then(Value::as_bool) != Some(true)
        || service.get("liveExecution").and_then(Value::as_bool) != Some(false)
        || service.get("externalWrites").and_then(Value::as_bool) != Some(false)
        || service.get("truthAuthority").and_then(Value::as_bool) != Some(false)
        || service.get("consentAuthority").and_then(Value::as_bool) != Some(false)
        || service.get("effectAuthority").and_then(Value::as_bool) != Some(false)
        || service.get("receiptAuthority").and_then(Value::as_bool) != Some(false)
        || service
            .get("verificationAuthority")
            .and_then(Value::as_bool)
            != Some(false)
        || service.get("outcomeAuthority").and_then(Value::as_bool) != Some(false)
    {
        return Err(ContractValidationError::Field("service"));
    }
    let provider = document
        .get("provider")
        .ok_or(ContractValidationError::Field("provider"))?;
    if provider.get("id").and_then(Value::as_str) != Some(AZURE_MONITOR_LOGS_PROVIDER_ID)
        || provider.get("endpoint").and_then(Value::as_str)
            != Some("https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query")
        || provider.get("connectedEvidence").and_then(Value::as_bool) != Some(false)
        || provider.get("nativeEvidence").and_then(Value::as_bool) != Some(false)
        || provider.get("firstPartyEvidence").and_then(Value::as_bool) != Some(false)
        || provider.get("providerReceipt").and_then(Value::as_bool) != Some(false)
    {
        return Err(ContractValidationError::Field("provider"));
    }
    let consumer = document
        .get("consumer")
        .ok_or(ContractValidationError::Field("consumer"))?;
    if consumer.get("id").and_then(Value::as_str) != Some(MISSION_AZURE_MONITOR_LOGS_CONSUMER_ID)
        || consumer.get("projectBound").and_then(Value::as_bool) != Some(true)
        || consumer.get("missionBound").and_then(Value::as_bool) != Some(true)
        || consumer.get("workProductBound").and_then(Value::as_bool) != Some(true)
        || consumer.get("adoptsOutcome").and_then(Value::as_bool) != Some(false)
        || consumer.get("adoptsWorkProduct").and_then(Value::as_bool) != Some(false)
        || consumer.get("truthAuthority").and_then(Value::as_bool) != Some(false)
        || consumer.get("consentAuthority").and_then(Value::as_bool) != Some(false)
    {
        return Err(ContractValidationError::Field("consumer"));
    }
    let statuses = document
        .get("statuses")
        .and_then(Value::as_array)
        .ok_or(ContractValidationError::Field("statuses"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if statuses
        != [
            "COMPLETE",
            "EMPTY",
            "PARTIAL",
            "TRUNCATED",
            "TIMEOUT",
            "ACCESS_LOST",
            "PROVIDER_UNKNOWN",
            "TAMPERED",
            "REVOKED",
        ]
    {
        return Err(ContractValidationError::Field("statuses"));
    }
    let provenance = document
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or(ContractValidationError::Field("provenance"))?;
    for name in ["fixture", "recording", "loopback", "blocked_env"] {
        let entry = provenance
            .get(name)
            .and_then(Value::as_object)
            .ok_or(ContractValidationError::Field("provenance entry"))?;
        if entry.get("connected").and_then(Value::as_bool) != Some(false)
            || entry.get("native").and_then(Value::as_bool) != Some(false)
            || entry.get("firstParty").and_then(Value::as_bool) != Some(false)
        {
            return Err(ContractValidationError::Field("provenance flags"));
        }
    }
    Ok(())
}

/// Layer 1's authority is intentionally all-false for every provider mode.
pub const fn layer1_connected() -> bool {
    false
}

pub const fn layer1_native() -> bool {
    false
}

pub const fn layer1_first_party() -> bool {
    false
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn contract_metadata_is_versioned_and_honest() {
        validate_contract_document().expect("contract metadata must validate");
        assert_eq!(
            AZURE_MONITOR_LOGS_SCHEMA_VERSION,
            "hartevo.azure-monitor-logs-result-contract/v1"
        );
        assert_eq!(
            AZURE_MONITOR_LOGS_CONTRACT_VERSION,
            "EXT-AZURE-MONITOR-LOGS-01-L1/v1"
        );
        assert!(!layer1_connected());
        assert!(!layer1_native());
        assert!(!layer1_first_party());
    }

    #[test]
    fn contract_digest_is_deterministic() {
        assert_eq!(contract_digest(), contract_digest());
    }
}
