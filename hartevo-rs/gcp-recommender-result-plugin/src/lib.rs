//! Standalone Layer-1 Google Cloud Recommender and Insight result plugin.
//!
//! The crate owns a bounded typed service definition, a provider seam for
//! fixture/recording/loopback/BLOCKED_ENV responses, and a Mission consumer.
//! It never resolves a live credential, opens native HTTPS, retains raw GCP
//! descriptions or Struct payloads, marks a recommendation, executes an
//! operation group, mutates a resource, claims projected savings, or adopts a
//! kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::fn_params_excessive_bools)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionGcpRecommendationConsumer, MissionGcpRecommendationConsumerError,
    MissionGcpRecommendationEvidence, MissionGcpRecommendationResult,
    MissionGcpRecommendationState, MissionResultState,
};
pub use model::{
    BillingAccountId, CloudProjectId, ConsentScope, ConsumerId, Digest, FolderId,
    GcpImpactCategory, GcpParent, GcpProjectId, GcpRecommenderQuery, GcpRecommenderRecord,
    GcpRecommenderRegistration, GcpRecommenderScope, GcpRecommenderScopeSpec, GcpResultKind,
    GcpScope, GoogleAuthKind, ImpactCategory, ImpactClass, InsightId, InsightRecord, InsightTypeId,
    Layer1Authority, Location, MissionBinding, MissionId, ModelError, OpaquePageToken,
    OrganizationId, PageTokenBinding, PartialReason, PermissionFence, PermissionScope,
    ProjectBinding, ProjectId, ProviderId, ReadOperation, RecommendationId, RecommendationPriority,
    RecommendationRecord, RecommendationState, RecommendationSubtype, RecommenderId,
    RecommenderScope, Registration, RegistrationRevocationReceipt, RegistrationState,
    ResultFilters, ResultId, ResultProjection, ResultState, ResultVersionFence, Revision,
    SecretReference, ServiceId, Timestamp, WorkProductBinding, WorkProductId,
};
pub use provider::{
    BlockedEnvGcpRecommenderTransport, BlockedEnvTransport, FakeGcpRecommenderTransport,
    FixtureGcpRecommenderTransport, FixtureTransport, GcpProviderDefinition,
    GcpRecommendationGetResponse, GcpRecommendationListResponse, GcpRecommenderGetRequest,
    GcpRecommenderGetResponse, GcpRecommenderListPage, GcpRecommenderListRequest,
    GcpRecommenderListResponse, GcpRecommenderProvider, GcpRecommenderProviderAdapter,
    GcpRecommenderProviderApi, GcpRecommenderProviderDefinition, GcpRecommenderTransport,
    GetRequest, ListRequest, LoopbackGcpRecommenderTransport, LoopbackTransport,
    ProviderDefinitionError, ProviderProvenance, RecordingGcpRecommenderTransport,
    RecordingTransport, TransportError,
};
pub use service::{
    EVIDENCE_POLICY_VERSION, GcpRecommenderEvidence, GcpRecommenderObservationReceipt,
    GcpRecommenderProposal, GcpRecommenderReadbackReceipt, GcpRecommenderResultProposal,
    GcpRecommenderResultReceipt, GcpRecommenderResultService, GcpRecommenderService,
    GcpRecommenderServiceDefinition, GcpRecommenderServiceError, ReadTarget,
    RecommendationResultProposal, RetryEvidence, RetryPolicy, evidence_policy_digest,
};

pub const GCP_RECOMMENDER_RESULT_SCHEMA_VERSION: &str =
    "hartevo.gcp-recommender-result.contract/v1";
pub const GCP_RECOMMENDER_RESULT_CONTRACT_VERSION: &str = "gcp-recommender-result/v1";
pub const GCP_RECOMMENDER_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const GCP_RECOMMENDER_RESULT_SERVICE_ID: &str = "gcp.recommender-result";
pub const GCP_RECOMMENDER_RESULT_PROVIDER_ID: &str = "gcp.recommender.result";
pub const GCP_RECOMMENDER_RESULT_PROVIDER_VERSION: &str = "google-recommender-v1-r1";
pub const GCP_RECOMMENDER_RESULT_CONSUMER_ID: &str = "mission.gcp-recommender-result";
pub const GCP_RECOMMENDER_RESULT_API_VERSION: &str = "v1";
pub const GCP_RECOMMENDER_RESULT_RECOMMENDATIONS_LIST_PATH: &str =
    "/v1/{parent}/locations/{location}/recommenders/{recommender}/recommendations";
pub const GCP_RECOMMENDER_RESULT_RECOMMENDATIONS_GET_PATH: &str =
    "/v1/{parent}/locations/{location}/recommenders/{recommender}/recommendations/{recommendation}";
pub const GCP_RECOMMENDER_RESULT_INSIGHTS_LIST_PATH: &str =
    "/v1/{parent}/locations/{location}/insightTypes/{insightType}/insights";
pub const GCP_RECOMMENDER_RESULT_INSIGHTS_GET_PATH: &str =
    "/v1/{parent}/locations/{location}/insightTypes/{insightType}/insights/{insight}";
pub const GCP_RECOMMENDER_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-recommender-result/gcp-recommender-result.v1.json"
);

pub fn plugin_version() -> &'static str {
    GCP_RECOMMENDER_RESULT_PLUGIN_VERSION
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_RECOMMENDER_RESULT_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract document and its non-native authority
/// pins. This is intentionally strict so contract drift fails closed.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(GCP_RECOMMENDER_RESULT_CONTRACT_JSON)
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
        contract["schemaVersion"] == GCP_RECOMMENDER_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == GCP_RECOMMENDER_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == GCP_RECOMMENDER_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == "Layer-1")?;
    is(
        "service.id",
        contract["service"]["id"] == GCP_RECOMMENDER_RESULT_SERVICE_ID,
    )?;
    is("service.readOnly", contract["service"]["readOnly"] == true)?;
    is(
        "service.liveExecution",
        contract["service"]["liveExecution"] == false,
    )?;
    is(
        "service.nativePostExecution",
        contract["service"]["nativePostExecution"] == false,
    )?;
    is(
        "service.nativeGetReadback",
        contract["service"]["nativeGetReadback"] == false,
    )?;
    is(
        "service.marksRecommendation",
        contract["service"]["marksRecommendation"] == false,
    )?;
    is(
        "service.executesOperationGroup",
        contract["service"]["executesOperationGroup"] == false,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == GCP_RECOMMENDER_RESULT_PROVIDER_ID,
    )?;
    is(
        "provider.apiVersion",
        contract["provider"]["apiVersion"] == "v1",
    )?;
    is("provider.native", contract["provider"]["native"] == false)?;
    is(
        "provider.connected",
        contract["provider"]["connected"] == false,
    )?;
    is(
        "provider.firstParty",
        contract["provider"]["firstParty"] == false,
    )?;
    is(
        "provider.liveCredentialResolution",
        contract["provider"]["liveCredentialResolution"] == false,
    )?;
    is(
        "provider.operations",
        contract["provider"]["operations"]
            == serde_json::json!([
                "recommendations.list",
                "recommendations.get",
                "insights.list",
                "insights.get"
            ]),
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == GCP_RECOMMENDER_RESULT_CONSUMER_ID,
    )?;
    is(
        "consumer.adoptsOutcome",
        contract["consumer"]["adoptsOutcome"] == false,
    )?;
    is(
        "consumer.truthAuthority",
        contract["consumer"]["truthAuthority"] == false,
    )?;
    is(
        "filters.arbitraryExpression",
        contract["filters"]["arbitraryExpression"] == false,
    )?;
    is(
        "evidence.rawDescriptions",
        contract["evidence"]["rawDescriptions"] == false,
    )?;
    is(
        "evidence.customStructPayloads",
        contract["evidence"]["customStructPayloads"] == false,
    )?;
    is(
        "evidence.principals",
        contract["evidence"]["principals"] == false,
    )?;
    is(
        "evidence.operationPlans",
        contract["evidence"]["operationPlans"] == false,
    )?;
    is(
        "evidence.projectedSavings",
        contract["evidence"]["projectedSavings"] == false,
    )?;
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
    is(
        "transport.connected",
        contract["transport"]["connected"] == false,
    )?;
    is("transport.native", contract["transport"]["native"] == false)?;
    is(
        "transport.firstParty",
        contract["transport"]["firstParty"] == false,
    )?;
    is(
        "authority.recommendationMutation",
        contract["authority"]["recommendationMutation"] == false,
    )?;
    is(
        "authority.operationGroupExecution",
        contract["authority"]["operationGroupExecution"] == false,
    )?;
    is(
        "authority.resourceMutation",
        contract["authority"]["resourceMutation"] == false,
    )?;
    is(
        "authority.connected",
        contract["authority"]["connected"] == false,
    )?;
    is(
        "authority.nativeProvider",
        contract["authority"]["nativeProvider"] == false,
    )?;
    is(
        "authority.kernelOutcomeAdoption",
        contract["authority"]["kernelOutcomeAdoption"] == false,
    )?;
    is(
        "authority.projectedSavingsAuthority",
        contract["authority"]["projectedSavingsAuthority"] == false,
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_authority_is_false() {
        validate_contract().expect("contract validates");
        assert_eq!(contract_digest(), contract_digest());
        assert_eq!(plugin_version(), "0.1.0");
        assert!(!GCP_RECOMMENDER_RESULT_CONTRACT_JSON.is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::operation_group_execution());
    }
}

#[cfg(test)]
mod adversarial_tests;
