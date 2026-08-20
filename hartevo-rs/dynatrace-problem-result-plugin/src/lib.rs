//! Standalone Layer-1 Dynatrace Problems API evidence-result plugin.
//!
//! The crate freezes a typed environment/account/management-zone/entity/
//! problem/time/Project/Mission/Work Product scope, bounded GET-only list and
//! detail request seams, digest-only problem projections, and a Mission
//! consumer. It deliberately has no native token resolution, HTTPS transport,
//! provider mutation, topology/log retention, Connected claim, kernel Truth,
//! Consent, Effect, Receipt, Verification, Outcome, root-cause, or Work
//! Product adoption authority.

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

pub use consumer::{ConsumerError, MissionDynatraceProblemConsumer, MissionDynatraceProblemResult};
pub use model::{
    AccountId, AffectedEntityProjection, Digest, DynatraceImpact, DynatraceProblemEvidence,
    DynatraceProblemScope, DynatraceProblemScopeInput, DynatraceProblemStatus,
    DynatraceRegistration, DynatraceSeverity, EntitySelector, EnvironmentId, EvidenceState,
    ManagementZoneId, MissionId, ProblemId, ProblemObservationState, ProblemProjection, ProjectId,
    ProviderProvenance, ProviderRevision, Revision, SecretReference, TimeWindow, WorkProductId,
};
pub use provider::{
    BlockedEnvDynatraceTransport, DynatraceApiRequestKind, DynatraceDetailRequest,
    DynatraceHttpMethod, DynatraceListRequest, DynatraceProblemDetail, DynatraceProblemPage,
    DynatraceProblemPayload, DynatraceProblemTransport, DynatraceProvider,
    DynatraceProviderDefinition, DynatraceProviderDefinitionError, DynatraceRawEntity,
    FakeDynatraceTransport, FixtureDynatraceTransport, LoopbackDynatraceTransport,
    ProblemTransportCall, RecordingDynatraceTransport, TransportError,
};
pub use service::{DynatraceProblemResultService, DynatraceProblemResultServiceError};

pub const DYNATRACE_PROBLEM_RESULT_SCHEMA_VERSION: &str =
    "hartevo.dynatrace-problem-result-contract/v1";
pub const DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION: &str = "dynatrace-problem-result/v1";
pub const DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const DYNATRACE_PROBLEM_RESULT_SERVICE_ID: &str = "dynatrace.problem-result";
pub const DYNATRACE_PROBLEM_RESULT_PROVIDER_ID: &str = "dynatrace.problems-v2";
pub const DYNATRACE_PROBLEM_RESULT_PROVIDER_VERSION: &str = "dynatrace-problems-api-v2-r1";
pub const DYNATRACE_PROBLEM_RESULT_CONSUMER_ID: &str = "mission.dynatrace-problem-result";
pub const DYNATRACE_PROBLEM_RESULT_API_VERSION: &str = "v2";
pub const DYNATRACE_PROBLEM_RESULT_LIST_PATH: &str = "/api/v2/problems";
pub const DYNATRACE_PROBLEM_RESULT_DETAIL_PATH: &str = "/api/v2/problems/{problemId}";
pub const DYNATRACE_PROBLEM_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/dynatrace-problem-result/dynatrace-problem-result.v1.json"
);

pub fn plugin_version() -> &'static str {
    DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(DYNATRACE_PROBLEM_RESULT_CONTRACT_JSON.as_bytes())
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
    let contract: serde_json::Value = serde_json::from_str(DYNATRACE_PROBLEM_RESULT_CONTRACT_JSON)
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
        contract["schemaVersion"] == DYNATRACE_PROBLEM_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == 1)?;
    is(
        "service.id",
        contract["service"]["id"] == DYNATRACE_PROBLEM_RESULT_SERVICE_ID,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == DYNATRACE_PROBLEM_RESULT_PROVIDER_ID,
    )?;
    is(
        "provider.apiVersion",
        contract["provider"]["apiVersion"] == DYNATRACE_PROBLEM_RESULT_API_VERSION,
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == DYNATRACE_PROBLEM_RESULT_CONSUMER_ID,
    )?;
    is(
        "service.nativePostExecution",
        contract["service"]["nativePostExecution"] == false,
    )?;
    is(
        "service.nativeGetReadback",
        contract["service"]["nativeGetReadback"] == false,
    )?;
    for field in ["native", "connected", "firstParty"] {
        is(
            match field {
                "native" => "provider.native",
                "connected" => "provider.connected",
                _ => "provider.firstParty",
            },
            contract["provider"][field] == false,
        )?;
    }
    is(
        "provider.permissions",
        contract["provider"]["permissions"] == serde_json::json!(["problems.read"]),
    )?;
    is(
        "provider.transportProvenance",
        contract["provider"]["transportProvenance"]
            == serde_json::json!(["fixture", "recording", "loopback", "blocked_env"]),
    )?;
    is(
        "provider.operations",
        contract["provider"]["operations"]
            == serde_json::json!(["GET /api/v2/problems", "GET /api/v2/problems/{problemId}"]),
    )?;
    is(
        "readOnly",
        contract["readOnly"] == true
            && contract["mutatingProviderOperations"] == serde_json::json!([]),
    )?;
    is(
        "projection.optionalApiFieldsRequested",
        contract["projection"]["optionalApiFieldsRequested"] == serde_json::json!([]),
    )?;
    is(
        "bounds.maxTimeWindowSeconds",
        contract["bounds"]["maxTimeWindowSeconds"] == (model::MAX_TIME_WINDOW_MS / 1_000),
    )?;
    is(
        "bounds.maxPageSize",
        contract["bounds"]["maxPageSize"] == model::MAX_PAGE_SIZE,
    )?;
    is(
        "bounds.maxPages",
        contract["bounds"]["maxPages"] == model::MAX_PAGES,
    )?;
    is(
        "bounds.maxProblemsPerPage",
        contract["bounds"]["maxProblemsPerPage"] == model::MAX_PROBLEMS_PER_PAGE,
    )?;
    is(
        "bounds.maxAffectedEntityTypes",
        contract["bounds"]["maxAffectedEntityTypes"] == model::MAX_AFFECTED_ENTITY_TYPES,
    )?;
    is(
        "bounds.maxAffectedEntitiesPerProblem",
        contract["bounds"]["maxAffectedEntitiesPerProblem"]
            == model::MAX_AFFECTED_ENTITIES_PER_PROBLEM,
    )?;
    is(
        "bounds.maxResponseBytes",
        contract["bounds"]["maxResponseBytes"] == model::MAX_RESPONSE_BYTES,
    )?;
    is(
        "bounds.maxEntitySelectorBytes",
        contract["bounds"]["maxEntitySelectorBytes"] == model::MAX_ENTITY_SELECTOR_BYTES,
    )?;
    is(
        "bounds.maxNextPageKeyBytes",
        contract["bounds"]["maxNextPageKeyBytes"] == model::MAX_NEXT_PAGE_KEY_BYTES,
    )?;
    for field in [
        "connected",
        "native",
        "firstParty",
        "truth",
        "consent",
        "effect",
        "receipt",
        "verification",
        "outcome",
        "rootCause",
        "workProductAdoption",
    ] {
        is("authority", contract["authority"][field] == false)?;
    }
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    is(
        "registration.failClosedOnDrift",
        contract["registration"]["failClosedOnDrift"] == true,
    )?;
    Ok(())
}

pub fn validate_plugin_metadata(
    plugin_version: &str,
    contract_version: &str,
) -> Result<(), ContractValidationError> {
    if plugin_version != DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION {
        return Err(ContractValidationError::FrozenField("pluginVersion"));
    }
    if contract_version != DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION {
        return Err(ContractValidationError::FrozenField("contractVersion"));
    }
    validate_contract()
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_digest_is_stable() {
        validate_contract().expect("contract validates");
        validate_plugin_metadata(plugin_version(), DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION)
            .expect("metadata validates");
        assert_eq!(contract_digest(), contract_digest());
        assert_eq!(plugin_version(), "0.1.0");
        assert!(!DYNATRACE_PROBLEM_RESULT_CONTRACT_JSON.is_empty());
    }
}

#[cfg(test)]
mod adversarial_tests;
