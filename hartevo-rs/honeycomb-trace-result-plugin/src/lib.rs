//! Standalone Layer-1 Honeycomb trace-query aggregate-result plugin.
//!
//! This root freezes a typed region/team/environment/dataset/query scope,
//! bounded query AST, query/query-result request seams, redacted aggregate
//! evidence, and a Mission consumer. It deliberately has no native Honeycomb
//! credential resolution, HTTP transport, raw telemetry retention, provider
//! mutation, Connected claim, or Outcome/Work Product authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AdoptionAvailability, ConsumerError, ConsumerRegistration, MissionHoneycombTraceConsumer,
    MissionHoneycombTraceResult, MissionResultState, MissionTraceConsumer, MissionTraceResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvHoneycombTransport, BlockedEnvTransport, FakeHoneycombTransport,
    FixtureHoneycombTransport, HoneycombProviderDefinition, HoneycombQueryProvider,
    HoneycombQueryTransport, LoopbackHoneycombTransport, ProviderDefinitionError,
    ProviderProvenance, QueryCreateRequest, QueryCreateResponse, QueryResultCreateRequest,
    QueryResultCreateResponse, QueryResultGetRequest, QueryResultGetResponse,
    RecordingHoneycombTransport, TransportCall, TransportError,
};
pub use service::{
    HoneycombQueryProposal, HoneycombQueryResultProposal, HoneycombResultEvidence,
    HoneycombResultProposal, HoneycombResultReceipt, HoneycombService, HoneycombServiceError,
    HoneycombTraceResultService, ResultEvidence, ResultProposal, ResultReceipt, RetryEvidence,
    RetryPolicy,
};

pub const HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION: &str =
    "hartevo.honeycomb-trace-result.contract/v1";
pub const HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION: &str = "honeycomb-trace-result/v1";
pub const HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const HONEYCOMB_TRACE_RESULT_SERVICE_ID: &str = "honeycomb.trace-result";
pub const HONEYCOMB_TRACE_RESULT_PROVIDER_ID: &str = "honeycomb.query-result";
pub const HONEYCOMB_TRACE_RESULT_PROVIDER_VERSION: &str = "honeycomb-api-v1-r1";
pub const HONEYCOMB_TRACE_RESULT_CONSUMER_ID: &str = "mission.honeycomb-trace-result";
pub const HONEYCOMB_TRACE_RESULT_API_VERSION: &str = "1";
pub const HONEYCOMB_TRACE_RESULT_QUERY_CREATE_PATH: &str = "/1/queries/{datasetSlug}";
pub const HONEYCOMB_TRACE_RESULT_QUERY_RESULT_CREATE_PATH: &str = "/1/query_results/{datasetSlug}";
pub const HONEYCOMB_TRACE_RESULT_QUERY_RESULT_GET_PATH: &str =
    "/1/query_results/{datasetSlug}/{queryResultId}";
pub const HONEYCOMB_TRACE_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/honeycomb-trace-result/honeycomb-trace-result.v1.json"
);

pub fn plugin_version() -> &'static str {
    HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(HONEYCOMB_TRACE_RESULT_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract document and its Layer-1 honesty pins.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(HONEYCOMB_TRACE_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let is = |path: &'static str, actual: bool| {
        if actual {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    is(
        "schemaVersion",
        contract["schemaVersion"] == HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == HONEYCOMB_TRACE_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == "Layer-1")?;
    is(
        "service.id",
        contract["service"]["id"] == HONEYCOMB_TRACE_RESULT_SERVICE_ID,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == HONEYCOMB_TRACE_RESULT_PROVIDER_ID,
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == HONEYCOMB_TRACE_RESULT_CONSUMER_ID,
    )?;
    is(
        "service.nativePostExecution",
        contract["service"]["nativePostExecution"] == false,
    )?;
    is(
        "service.nativeGetReadback",
        contract["service"]["nativeGetReadback"] == false,
    )?;
    is("provider.native", contract["provider"]["native"] == false)?;
    is(
        "provider.permissions",
        contract["provider"]["permissions"] == serde_json::json!(["Run Queries", "Manage Queries"]),
    )?;
    is(
        "queryAst.maxTimeRangeSeconds",
        contract["queryAst"]["maxTimeRangeSeconds"] == MAX_QUERY_RANGE_SECONDS,
    )?;
    is(
        "queryAst.arbitraryDsl",
        contract["queryAst"]["arbitraryDsl"] == false,
    )?;
    is(
        "queryAst.arbitraryField",
        contract["queryAst"]["arbitraryField"] == false,
    )?;
    is(
        "authority.connected",
        contract["authority"]["connected"] == false,
    )?;
    is(
        "authority.externalWrites",
        contract["authority"]["externalWrites"] == false,
    )?;
    is(
        "authority.eventIngestion",
        contract["authority"]["eventIngestion"] == false,
    )?;
    is(
        "authority.boardMutation",
        contract["authority"]["boardMutation"] == false,
    )?;
    is(
        "authority.markerMutation",
        contract["authority"]["markerMutation"] == false,
    )?;
    is(
        "authority.sloMutation",
        contract["authority"]["sloMutation"] == false,
    )?;
    is(
        "authority.triggerMutation",
        contract["authority"]["triggerMutation"] == false,
    )?;
    is(
        "authority.dashboardAuthority",
        contract["authority"]["dashboardAuthority"] == false,
    )?;
    is(
        "authority.kernelOutcomeAdoption",
        contract["authority"]["kernelOutcomeAdoption"] == false,
    )?;
    is(
        "authority.workProductAdoption",
        contract["authority"]["workProductAdoption"] == false,
    )?;
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_digest_is_stable() {
        validate_contract().expect("contract validates");
        assert_eq!(contract_digest(), contract_digest());
        assert_eq!(plugin_version(), "0.1.0");
        assert!(!HONEYCOMB_TRACE_RESULT_CONTRACT_JSON.is_empty());
    }
}

#[cfg(test)]
mod adversarial_tests;
