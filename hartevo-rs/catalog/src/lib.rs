//! Versioned product contracts and deterministic dataset metadata.
//!
//! Private V1/V2 prompts, world deltas, rubrics, oracles, gold artifacts and
//! failure traces are deliberately not compiled into this crate. Only the
//! metadata required to prove partition shape is available to product code.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod evidence;
mod mission_contract;
mod planning_plugin;
mod provider_closure;
mod route_graph;
mod route_runtime_authority;
mod stage_application_route_scope;

pub use evidence::{
    BrowserEvaluationResultReference, BrowserReferenceEvidenceClass, BrowserReferenceProviderMode,
    BrowserReferenceValidationAuthority, BrowserReferenceVerdict, EvaluationPartition,
    EvaluationPrivateAttestationStatus, EvaluationReferenceRunProfile,
    EvaluationReferenceThresholdStatus, EvaluationRunEvidenceAuthority,
    EvaluationRunResultReference, EvaluationRunResultReferences, EvaluationRunValidationAuthority,
    EvaluationSafetyMappingStatus, EvidenceLevel, MissionEvidenceRecord, MissionEvidenceStatus,
    ReleaseEvidence, ReleaseStage,
};
pub use mission_contract::{
    EXPECTED_CAPABILITY_COUNT, EXPECTED_CHECKPOINT_ROUTE_COUNT, validate_mission_contract_closure,
};
pub use planning_plugin::{
    CapabilityRouteProposal, DurableDispatchRecord, DurablePlanLog, MAX_PLANNING_BUDGET_UNITS,
    MAX_PLANNING_OBJECTIVE_BYTES, MAX_PLANNING_ROUTE_STEPS, MAX_PLANNING_TEXT_BYTES,
    MissionPlanningConsumer, MissionRouteDispatch, PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
    PlanLogEntry, PlanLogEvent, PlanningCancellation, PlanningCapabilityId, PlanningError,
    PlanningObjective, PlanningProvider, PlanningProviderDescriptor, PlanningProviderError,
    PlanningProviderRegistration, PlanningProviderRoute, PlanningRouteStep, PlanningScope,
    PlanningService, ProviderLifecycleState, ScopedProviderRegistry,
};
use provider_closure::EFFECT_READBACK_ROUTE_CONTRACT_JSON;
pub use provider_closure::{
    CorroborationBinding, EXPECTED_EXECUTABLE_STAGE_COUNT, EffectReadbackFlow,
    EffectReadbackRouteContract, EffectReadbackStage, EffectReadbackTerminalCondition,
    ProductClaimAuthority, ProviderClaimAuthority, RouteClaimAuthority,
    expanded_execution_stage_count, validate_provider_route_closure,
};
use route_graph::ROUTE_GRAPH_CONTRACT_JSON;
pub use route_graph::{
    CompletionEvidenceReusePolicy, EXPECTED_ROUTE_GRAPH_COUNT, EXPECTED_ROUTE_GRAPH_NODE_COUNT,
    EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT, EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT,
    EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT, EffectReplayPolicy, MissionRouteGraph,
    PreservedArtifactsPolicy, RouteCondition, RouteGraphContract, RouteGraphNode,
    RouteGraphRedirect, RouteGraphRuntimeAuthority, RouteGraphTerminal,
    RouteGraphTerminalDisposition, RouteGraphTerminalKind, RouteGraphTransition,
    RouteGraphTransitionTarget, RouteGraphTransitionTargetKind, RouteNodeCompletionGate,
    RouteNodeCompletionGateKind, route_graph_node_count, route_graph_normal_edge_count,
    route_graph_redirect_edge_count, route_graph_terminal_count, validate_route_graph_closure,
};
use route_runtime_authority::ROUTE_RUNTIME_AUTHORITY_CONTRACT_JSON;
pub use route_runtime_authority::{
    ApplicationHandlerRouteTerminalExecutionAuthority,
    ApplicationHandlerRouteTerminalExecutionAuthorityKind, DefaultTerminalExecutionAuthority,
    DeniedRouteTerminalExecutionAuthority, DeniedRouteTerminalExecutionAuthorityKind,
    EXPECTED_DENIED_TERMINAL_TRANSITION_AUTHORITY_COUNT,
    EXPECTED_IMPLEMENTED_TERMINAL_TRANSITION_AUTHORITY_COUNT,
    EXPECTED_TERMINAL_TRANSITION_AUTHORITY_COUNT, RouteRuntimeAuthorityContract,
    RouteTerminalAuthorityExecutor, RouteTerminalCompletionPolicy, RouteTerminalExecutionAuthority,
    RouteTerminalExecutionBinding, denied_terminal_transition_authority_count,
    implemented_terminal_transition_authority_count, terminal_transition_authority_count,
    validate_route_runtime_authority_closure,
};
use stage_application_route_scope::STAGE_APPLICATION_ROUTE_SCOPE_CONTRACT_JSON;
pub use stage_application_route_scope::{
    EXPECTED_STAGE_APPLICATION_ROUTE_SCOPE_COUNT, StageApplicationHandlerBinding,
    StageApplicationHandlerStatus, StageApplicationRouteAuthority, StageApplicationRouteBinding,
    StageApplicationRouteScope, StageApplicationRouteScopeContract,
    StageApplicationRouteScopeSummary, StageApplicationRouteSelection,
    StageGenericRuntimeAuthority, StageMissionAnyOfKind, StageMissionAnyOfSelection,
    StageMissionApplicationRouteScope, StageMissionSelectionBinding,
    materialize_stage_application_route_scopes,
    validate_materialized_stage_application_route_scopes,
    validate_stage_application_route_scope_closure,
};

const MISSION_CATALOG_JSON: &str = include_str!("../../../contracts/missions/catalog.v1.json");
const APPLICATION_HANDLER_REGISTRY_JSON: &str =
    include_str!("../../../contracts/application-handlers/catalog.v1.json");
const CAPABILITY_CATALOG_JSON: &str =
    include_str!("../../../contracts/capabilities/catalog.v1.json");
const PROVIDER_CATALOG_JSON: &str = include_str!("../../../contracts/providers/catalog.v1.json");
const DATASET_REGISTRY_JSON: &str = include_str!("../../../contracts/datasets/registry.v1.json");
const RELEASE_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../../../contracts/release-evidence/schema.v2.2.json");

pub const EXPECTED_MISSION_COUNT: usize = 12;
pub const EXPECTED_DATASET_CASE_COUNT: usize = 420;
pub const EXPECTED_V0_CASE_COUNT: usize = 240;
pub const EXPECTED_V1_CASE_COUNT: usize = 120;
pub const EXPECTED_V2_CASE_COUNT: usize = 60;
pub const EXPECTED_CROSS_CUTTING_CASE_COUNT: usize = 180;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionCatalog {
    pub schema_version: String,
    pub catalog_version: String,
    pub missions: Vec<MissionManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionManifest {
    pub id: String,
    pub version: u32,
    pub title: String,
    pub goal: String,
    pub modes: Vec<String>,
    pub default_cadence: String,
    pub checkpoint_ids: Vec<String>,
    pub checkpoint_routes: Vec<CheckpointRouteManifest>,
    pub required_artifacts: Vec<String>,
    pub capability_ids: Vec<String>,
    pub provider_ids: Vec<String>,
    pub oracle_ids: Vec<String>,
    pub failure_families: Vec<String>,
    pub evidence_targets: EvidenceTargets,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointRouteManifest {
    pub checkpoint_id: String,
    pub capability_id: String,
    pub executor: String,
    pub oracle_ids: Vec<String>,
    pub completion_policy: String,
}

/// Production Application handlers are an allow-list, not an aspiration
/// list. Every Application route absent from this registry is machine-readably
/// `NOT_IMPLEMENTED` even though its Mission contract remains valid E1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationHandlerRegistry {
    pub schema_version: String,
    pub registry_version: String,
    pub handlers: Vec<ApplicationHandlerManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationHandlerManifest {
    pub handler_id: String,
    pub mission_id: String,
    pub mission_version: u32,
    pub checkpoint_id: String,
    pub capability_id: String,
    pub completion_policy: String,
    pub source_kinds: Vec<String>,
    pub source_oracle_bindings: BTreeMap<String, Vec<String>>,
    pub oracle_ids: Vec<String>,
    pub implementation_crate: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceTargets {
    pub e3: String,
    pub e4: String,
    pub e5: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityCatalog {
    pub schema_version: String,
    pub catalog_version: String,
    pub capabilities: Vec<CapabilityManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityManifest {
    pub id: String,
    pub category: String,
    pub provider_required: bool,
    pub effect_class: String,
    pub mission_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCatalog {
    pub schema_version: String,
    pub catalog_version: String,
    pub providers: Vec<ProviderManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderManifest {
    pub id: String,
    pub status: String,
    pub integration_mode: String,
    pub auth_mode: String,
    pub capability_ids: Vec<String>,
    pub regions: Vec<String>,
    pub requires_external_approval: bool,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetRegistryContract {
    pub schema_version: String,
    pub registry_version: String,
    pub verticals: Vec<String>,
    pub markets: Vec<String>,
    pub asset_maturities: Vec<String>,
    pub personas: Vec<String>,
    pub partitions: Vec<PartitionContract>,
    pub v0_additional_families: Vec<String>,
    pub v1_families: Vec<String>,
    pub v2_families: Vec<String>,
    pub fixtures: Vec<FixtureContract>,
    pub simulators: Vec<NamedContract>,
    pub oracles: Vec<OracleContract>,
    pub cross_cutting_suites: Vec<NamedContract>,
    pub judge_calibration: JudgeCalibrationContract,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionContract {
    pub id: String,
    pub name: String,
    pub cases_per_mission: usize,
    pub visibility: String,
    pub content_policy: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureContract {
    pub id: String,
    pub primary_mission_ids: Vec<String>,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamedContract {
    pub id: String,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleContract {
    pub id: String,
    pub deterministic: bool,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JudgeCalibrationContract {
    pub required_samples: usize,
    pub mission_samples: usize,
    pub cross_market_samples: usize,
    pub truth_adversarial_samples: usize,
    pub work_product_adoption_samples: usize,
    pub double_review_required: bool,
    pub spearman_minimum: f64,
    pub mae_maximum: f64,
    pub kappa_minimum: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSnapshot {
    pub schema_version: String,
    pub mission_catalog_version: String,
    pub effect_readback_route_contract_version: String,
    pub route_graph_contract_version: String,
    pub application_handler_registry_version: String,
    pub capability_catalog_version: String,
    pub provider_catalog_version: String,
    pub dataset_registry_version: String,
    pub digest: String,
    pub summary: CatalogSummary,
    pub application_handlers: Vec<ApplicationHandlerManifest>,
    pub dataset_cases: Vec<DatasetCaseManifest>,
    pub cross_cutting_cases: Vec<CrossCuttingCaseManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSummary {
    pub mission_count: usize,
    pub checkpoint_route_count: usize,
    pub executable_stage_count: usize,
    pub route_graph_count: usize,
    pub route_graph_node_count: usize,
    pub route_graph_normal_edge_count: usize,
    pub route_graph_redirect_edge_count: usize,
    pub route_graph_terminal_count: usize,
    pub application_route_count: usize,
    pub implemented_application_handler_count: usize,
    pub not_implemented_application_route_count: usize,
    pub capability_count: usize,
    pub provider_count: usize,
    pub fixture_count: usize,
    pub simulator_count: usize,
    pub oracle_count: usize,
    pub dataset_case_count: usize,
    pub v0_case_count: usize,
    pub v1_case_count: usize,
    pub v2_case_count: usize,
    pub cross_cutting_case_count: usize,
    pub judge_calibration_sample_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetCaseManifest {
    pub id: String,
    pub version: u32,
    pub partition_id: String,
    pub partition_name: String,
    pub mission_id: String,
    pub family: String,
    pub vertical: Option<String>,
    pub market: Option<String>,
    pub asset_maturity: Option<String>,
    pub persona: Option<String>,
    pub fixture_id: String,
    pub simulator_ids: Vec<String>,
    pub prompt: Option<String>,
    pub checkpoint_ids: Option<Vec<String>>,
    pub oracle_ids: Option<Vec<String>>,
    pub expected_terminal: String,
    pub content_locator: String,
    pub content_digest: Option<String>,
    pub provenance: String,
    pub license: String,
    pub frozen_after_candidate: bool,
    pub contamination_canary_required: bool,
    pub deterministic_seed: String,
}

impl DatasetCaseManifest {
    pub fn private_content_is_isolated(&self) -> bool {
        if self.partition_id == "V0" {
            self.prompt.is_some()
                && self.checkpoint_ids.is_some()
                && self.oracle_ids.is_some()
                && self.content_digest.is_some()
        } else {
            self.prompt.is_none()
                && self.checkpoint_ids.is_none()
                && self.oracle_ids.is_none()
                && self.content_digest.is_none()
                && self.content_locator.starts_with("private://")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossCuttingCaseManifest {
    pub id: String,
    pub version: u32,
    pub suite_id: String,
    pub mission_id: String,
    pub expected_invariant: String,
    pub deterministic_seed: String,
}

#[derive(Clone, Debug)]
pub struct Catalog {
    pub missions: MissionCatalog,
    pub effect_readback_routes: EffectReadbackRouteContract,
    pub route_graphs: RouteGraphContract,
    pub route_runtime_authority: RouteRuntimeAuthorityContract,
    pub stage_application_route_scope_contract: StageApplicationRouteScopeContract,
    pub application_handlers: ApplicationHandlerRegistry,
    pub capabilities: CapabilityCatalog,
    pub providers: ProviderCatalog,
    pub datasets: DatasetRegistryContract,
    release_evidence_schema: serde_json::Value,
}

impl Catalog {
    pub fn load() -> Result<Self, CatalogError> {
        let catalog = Self {
            missions: parse_contract("mission catalog", MISSION_CATALOG_JSON)?,
            effect_readback_routes: parse_contract(
                "effect/readback route contract",
                EFFECT_READBACK_ROUTE_CONTRACT_JSON,
            )?,
            route_graphs: parse_contract(
                "Mission route graph contract",
                ROUTE_GRAPH_CONTRACT_JSON,
            )?,
            route_runtime_authority: parse_contract(
                "Mission route runtime authority contract",
                ROUTE_RUNTIME_AUTHORITY_CONTRACT_JSON,
            )?,
            stage_application_route_scope_contract: parse_contract(
                "stage Application route scope contract",
                STAGE_APPLICATION_ROUTE_SCOPE_CONTRACT_JSON,
            )?,
            application_handlers: parse_contract(
                "application handler registry",
                APPLICATION_HANDLER_REGISTRY_JSON,
            )?,
            capabilities: parse_contract("capability catalog", CAPABILITY_CATALOG_JSON)?,
            providers: parse_contract("provider catalog", PROVIDER_CATALOG_JSON)?,
            datasets: parse_contract("dataset registry", DATASET_REGISTRY_JSON)?,
            release_evidence_schema: parse_contract(
                "release evidence schema",
                RELEASE_EVIDENCE_SCHEMA_JSON,
            )?,
        };
        catalog.validate_contracts()?;
        let snapshot = catalog.materialize_unchecked()?;
        catalog.validate_snapshot(&snapshot)?;
        Ok(catalog)
    }

    pub fn snapshot(&self) -> Result<CatalogSnapshot, CatalogError> {
        let snapshot = self.materialize_unchecked()?;
        self.validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    pub fn mission(&self, mission_id: &str) -> Option<&MissionManifest> {
        self.missions
            .missions
            .iter()
            .find(|mission| mission.id == mission_id)
    }

    pub fn application_handler(
        &self,
        mission_id: &str,
        mission_version: u32,
        checkpoint_id: &str,
    ) -> Option<&ApplicationHandlerManifest> {
        self.application_handlers.handlers.iter().find(|handler| {
            handler.mission_id == mission_id
                && handler.mission_version == mission_version
                && handler.checkpoint_id == checkpoint_id
        })
    }

    pub fn stage_application_route_scopes(
        &self,
    ) -> Result<Vec<StageApplicationRouteScope>, CatalogError> {
        materialize_stage_application_route_scopes(
            &self.missions,
            &self.route_graphs,
            &self.application_handlers,
            &self.route_runtime_authority,
            &self.stage_application_route_scope_contract,
        )
        .map_err(CatalogError::Validation)
    }

    fn validate_contracts(&self) -> Result<(), CatalogError> {
        let mut violations = Vec::new();
        if let Err(mut contract_violations) =
            validate_mission_contract_closure(&self.missions, &self.capabilities)
        {
            violations.append(&mut contract_violations);
        }
        if let Err(mut contract_violations) = validate_provider_route_closure(
            &self.missions,
            &self.capabilities,
            &self.providers,
            &self.effect_readback_routes,
        ) {
            violations.append(&mut contract_violations);
        }
        if let Err(mut contract_violations) = validate_route_graph_closure(
            &self.missions,
            &self.capabilities,
            &self.effect_readback_routes,
            &self.route_graphs,
        ) {
            violations.append(&mut contract_violations);
        }
        if let Err(mut contract_violations) = validate_route_runtime_authority_closure(
            &self.missions,
            &self.route_graphs,
            &self.application_handlers,
            &self.route_runtime_authority,
        ) {
            violations.append(&mut contract_violations);
        }
        if let Err(mut contract_violations) = validate_stage_application_route_scope_closure(
            &self.missions,
            &self.route_graphs,
            &self.application_handlers,
            &self.route_runtime_authority,
            &self.stage_application_route_scope_contract,
        ) {
            violations.append(&mut contract_violations);
        }
        self.validate_mission_contracts(&mut violations);
        self.validate_application_handler_registry(&mut violations);
        self.validate_capability_provider_contracts(&mut violations);
        self.validate_dataset_contract(&mut violations);
        finish_validation(violations)
    }

    fn validate_mission_contracts(&self, violations: &mut Vec<String>) {
        let expected_mission_ids: BTreeSet<String> = (0..EXPECTED_MISSION_COUNT)
            .map(|index| format!("VM-{index:02}"))
            .collect();
        let mission_ids: BTreeSet<String> = self
            .missions
            .missions
            .iter()
            .map(|mission| mission.id.clone())
            .collect();
        require(
            violations,
            self.missions.missions.len() == EXPECTED_MISSION_COUNT
                && mission_ids == expected_mission_ids,
            "mission catalog must contain exactly VM-00 through VM-11",
        );
        let capability_ids: BTreeSet<&str> = self
            .capabilities
            .capabilities
            .iter()
            .map(|capability| capability.id.as_str())
            .collect();
        require(
            violations,
            capability_ids.len() == self.capabilities.capabilities.len(),
            "capability ids must be unique",
        );
        let provider_ids: BTreeSet<&str> = self
            .providers
            .providers
            .iter()
            .map(|provider| provider.id.as_str())
            .collect();
        require(
            violations,
            provider_ids.len() == self.providers.providers.len(),
            "provider ids must be unique",
        );
        let oracle_ids: BTreeSet<&str> = self
            .datasets
            .oracles
            .iter()
            .map(|oracle| oracle.id.as_str())
            .collect();
        for mission in &self.missions.missions {
            self.validate_mission(
                mission,
                &capability_ids,
                &provider_ids,
                &oracle_ids,
                violations,
            );
        }
    }

    fn validate_mission(
        &self,
        mission: &MissionManifest,
        capability_ids: &BTreeSet<&str>,
        provider_ids: &BTreeSet<&str>,
        oracle_ids: &BTreeSet<&str>,
        violations: &mut Vec<String>,
    ) {
        require(
            violations,
            mission.version > 0
                && !mission.goal.trim().is_empty()
                && !mission.modes.is_empty()
                && !mission.checkpoint_ids.is_empty()
                && !mission.required_artifacts.is_empty()
                && !mission.capability_ids.is_empty()
                && !mission.oracle_ids.is_empty()
                && !mission.failure_families.is_empty(),
            format!("{} is not decision-complete", mission.id),
        );
        require_unique(
            violations,
            &mission.checkpoint_ids,
            &format!("{} checkpoint ids", mission.id),
        );
        Self::validate_checkpoint_routes(mission, violations);
        require_unique(
            violations,
            &mission.required_artifacts,
            &format!("{} required artifacts", mission.id),
        );
        for capability_id in &mission.capability_ids {
            require(
                violations,
                capability_ids.contains(capability_id.as_str()),
                format!(
                    "{} references unknown capability {capability_id}",
                    mission.id
                ),
            );
        }
        for provider_id in &mission.provider_ids {
            require(
                violations,
                provider_ids.contains(provider_id.as_str()),
                format!("{} references unknown provider {provider_id}", mission.id),
            );
            if let Some(provider) = self
                .providers
                .providers
                .iter()
                .find(|provider| provider.id == *provider_id)
            {
                require(
                    violations,
                    provider
                        .capability_ids
                        .iter()
                        .any(|capability| mission.capability_ids.contains(capability)),
                    format!(
                        "{} lists provider {provider_id}, but they share no capability",
                        mission.id
                    ),
                );
            }
        }
        for oracle_id in &mission.oracle_ids {
            require(
                violations,
                oracle_ids.contains(oracle_id.as_str()),
                format!("{} references unknown oracle {oracle_id}", mission.id),
            );
        }
    }

    fn validate_checkpoint_routes(mission: &MissionManifest, violations: &mut Vec<String>) {
        Self::validate_checkpoint_route_coverage(mission, violations);
        for route in &mission.checkpoint_routes {
            Self::validate_checkpoint_route(mission, route, violations);
        }
    }

    fn validate_checkpoint_route_coverage(mission: &MissionManifest, violations: &mut Vec<String>) {
        let route_checkpoint_ids = mission
            .checkpoint_routes
            .iter()
            .map(|route| route.checkpoint_id.clone())
            .collect::<Vec<_>>();
        require_unique(
            violations,
            &route_checkpoint_ids,
            &format!("{} checkpoint route ids", mission.id),
        );
        require(
            violations,
            route_checkpoint_ids == mission.checkpoint_ids,
            format!(
                "{} checkpoint routes must exactly follow the checkpoint DAG order",
                mission.id
            ),
        );
        let routed_capability_ids = mission
            .checkpoint_routes
            .iter()
            .map(|route| route.capability_id.clone())
            .collect::<BTreeSet<_>>();
        require(
            violations,
            routed_capability_ids
                == mission
                    .capability_ids
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
            format!(
                "{} checkpoint routes must cover every and only Mission capability",
                mission.id
            ),
        );
        let routed_oracle_ids = mission
            .checkpoint_routes
            .iter()
            .flat_map(|route| route.oracle_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        require(
            violations,
            routed_oracle_ids == mission.oracle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            format!(
                "{} checkpoint routes must cover every and only Mission oracle",
                mission.id
            ),
        );
    }

    fn validate_checkpoint_route(
        mission: &MissionManifest,
        route: &CheckpointRouteManifest,
        violations: &mut Vec<String>,
    ) {
        require_unique(
            violations,
            &route.oracle_ids,
            &format!(
                "{} checkpoint {} oracle ids",
                mission.id, route.checkpoint_id
            ),
        );
        require(
            violations,
            mission.capability_ids.contains(&route.capability_id),
            format!(
                "{} checkpoint {} routes unknown Mission capability {}",
                mission.id, route.checkpoint_id, route.capability_id
            ),
        );
        require(
            violations,
            matches!(
                route.executor.as_str(),
                "application" | "runtime" | "effect_broker" | "human"
            ),
            format!(
                "{} checkpoint {} has unsupported executor {}",
                mission.id, route.checkpoint_id, route.executor
            ),
        );
        require(
            violations,
            !route.oracle_ids.is_empty()
                && route
                    .oracle_ids
                    .iter()
                    .all(|oracle| mission.oracle_ids.contains(oracle))
                && route
                    .oracle_ids
                    .iter()
                    .any(|oracle| oracle == "operating_state")
                && (route.executor != "runtime"
                    || route
                        .oracle_ids
                        .iter()
                        .any(|oracle| oracle == "work_product"))
                && (route.executor != "effect_broker"
                    || route.oracle_ids.iter().any(|oracle| oracle == "effect")),
            format!(
                "{} checkpoint {} must bind scoped Oracles including operating_state and executor-required evidence",
                mission.id, route.checkpoint_id
            ),
        );
        require(
            violations,
            matches!(
                (route.executor.as_str(), route.completion_policy.as_str()),
                ("application", "deterministic_evidence")
                    | ("runtime", "work_product")
                    | ("effect_broker", "verified_effect" | "effect_readback_v2")
                    | ("human", "human_confirmation")
            ),
            format!(
                "{} checkpoint {} executor {} conflicts with completion policy {}",
                mission.id, route.checkpoint_id, route.executor, route.completion_policy
            ),
        );
    }

    fn validate_application_handler_registry(&self, violations: &mut Vec<String>) {
        require(
            violations,
            self.application_handlers.schema_version == "hartevo-application-handler-registry/v1"
                && !self.application_handlers.registry_version.trim().is_empty(),
            "application handler registry must use the supported schema and a stable version",
        );
        let handler_ids = self
            .application_handlers
            .handlers
            .iter()
            .map(|handler| handler.handler_id.clone())
            .collect::<Vec<_>>();
        require_unique(
            violations,
            &handler_ids,
            "application handler registry handler ids",
        );
        let route_keys = self
            .application_handlers
            .handlers
            .iter()
            .map(|handler| {
                (
                    handler.mission_id.as_str(),
                    handler.mission_version,
                    handler.checkpoint_id.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        require(
            violations,
            route_keys.len() == self.application_handlers.handlers.len(),
            "application handler registry route keys must be unique",
        );

        for handler in &self.application_handlers.handlers {
            let Some(mission) = self.mission(&handler.mission_id) else {
                violations.push(format!(
                    "application handler {} references unknown Mission {}",
                    handler.handler_id, handler.mission_id
                ));
                continue;
            };
            let route = mission
                .checkpoint_routes
                .iter()
                .find(|route| route.checkpoint_id == handler.checkpoint_id);
            require(
                violations,
                handler.mission_version == mission.version,
                format!(
                    "application handler {} binds Mission {} version {}, expected {}",
                    handler.handler_id, mission.id, handler.mission_version, mission.version
                ),
            );
            require(
                violations,
                is_versioned_handler_id(&handler.handler_id)
                    && handler.implementation_crate == "hartevo-application"
                    && !handler.source_kinds.is_empty()
                    && handler
                        .source_kinds
                        .iter()
                        .all(|source| !source.trim().is_empty()),
                format!(
                    "application handler {} must identify a versioned production implementation and its sources",
                    handler.handler_id
                ),
            );
            validate_application_handler_sources(handler, violations);
            if let Some(route) = route {
                require(
                    violations,
                    route.executor == "application"
                        && route.capability_id == handler.capability_id
                        && route.completion_policy == handler.completion_policy
                        && route.oracle_ids.iter().cloned().collect::<BTreeSet<_>>()
                            == handler.oracle_ids.iter().cloned().collect::<BTreeSet<_>>(),
                    format!(
                        "application handler {} must exactly match its Application route capability, policy and Oracles",
                        handler.handler_id
                    ),
                );
            } else {
                violations.push(format!(
                    "application handler {} references unknown checkpoint {} in {}",
                    handler.handler_id, handler.checkpoint_id, mission.id
                ));
            }
        }
    }

    fn validate_capability_provider_contracts(&self, violations: &mut Vec<String>) {
        let mission_ids: BTreeSet<String> = self
            .missions
            .missions
            .iter()
            .map(|mission| mission.id.clone())
            .collect();
        let capability_ids: BTreeSet<&str> = self
            .capabilities
            .capabilities
            .iter()
            .map(|capability| capability.id.as_str())
            .collect();
        let provider_capabilities: BTreeSet<&str> = self
            .providers
            .providers
            .iter()
            .flat_map(|provider| provider.capability_ids.iter().map(String::as_str))
            .collect();
        for capability in &self.capabilities.capabilities {
            require(
                violations,
                !capability.mission_ids.is_empty(),
                format!("{} is not connected to a Mission", capability.id),
            );
            for mission_id in &capability.mission_ids {
                require(
                    violations,
                    mission_ids.contains(mission_id),
                    format!("{} references unknown Mission {mission_id}", capability.id),
                );
                if let Some(mission) = self.mission(mission_id) {
                    require(
                        violations,
                        mission.capability_ids.contains(&capability.id),
                        format!(
                            "capability {} maps to {mission_id}, but the Mission does not map back",
                            capability.id
                        ),
                    );
                }
            }
            if capability.provider_required {
                require(
                    violations,
                    provider_capabilities.contains(capability.id.as_str()),
                    format!("{} requires a provider but none exposes it", capability.id),
                );
            }
        }

        for provider in &self.providers.providers {
            require(
                violations,
                !provider.capability_ids.is_empty(),
                format!("provider {} exposes no capability", provider.id),
            );
            for capability_id in &provider.capability_ids {
                require(
                    violations,
                    capability_ids.contains(capability_id.as_str()),
                    format!(
                        "provider {} references unknown capability {capability_id}",
                        provider.id
                    ),
                );
            }
        }
    }

    fn validate_dataset_contract(&self, violations: &mut Vec<String>) {
        require(
            violations,
            self.datasets.fixtures.len() == 11,
            "dataset registry must preserve exactly eleven canonical seed fixtures",
        );
        require(
            violations,
            self.datasets.simulators.len() == 9,
            "dataset registry must contain the nine provider simulator worlds",
        );
        require(
            violations,
            self.datasets.oracles.len() == 7,
            "dataset registry must contain seven Business Oracles",
        );
        require(
            violations,
            self.datasets.cross_cutting_suites.len() == 15,
            "dataset registry must contain fifteen cross-cutting suites",
        );
        let partitions: BTreeSet<(&str, usize)> = self
            .datasets
            .partitions
            .iter()
            .map(|partition| (partition.id.as_str(), partition.cases_per_mission))
            .collect();
        require(
            violations,
            partitions == BTreeSet::from([("V0", 20), ("V1", 10), ("V2", 5)]),
            "dataset partitions must be exactly V0=20, V1=10 and V2=5 per Mission",
        );
        require(
            violations,
            self.datasets.verticals.len() == 4
                && self.datasets.markets.len() == 3
                && self.datasets.asset_maturities.len() == 4
                && self.datasets.personas.len() == 4
                && self.datasets.v0_additional_families.len() == 8
                && self.datasets.v1_families.len() == 10
                && self.datasets.v2_families.len() == 5,
            "dataset matrix must preserve 4 verticals, 3 markets and the 20/10/5 family shape",
        );
        require_named_unique(violations, &self.datasets.simulators, "simulator");
        require_named_unique(
            violations,
            &self.datasets.cross_cutting_suites,
            "cross-cutting suite",
        );
        require_unique(
            violations,
            &self
                .datasets
                .fixtures
                .iter()
                .map(|fixture| fixture.id.clone())
                .collect::<Vec<_>>(),
            "fixture ids",
        );
        require_unique(
            violations,
            &self
                .datasets
                .oracles
                .iter()
                .map(|oracle| oracle.id.clone())
                .collect::<Vec<_>>(),
            "oracle ids",
        );
        let judge = &self.datasets.judge_calibration;
        require(
            violations,
            judge.required_samples
                == judge.mission_samples
                    + judge.cross_market_samples
                    + judge.truth_adversarial_samples
                    + judge.work_product_adoption_samples
                && judge.required_samples == 200
                && judge.double_review_required,
            "judge calibration must describe 200 double-reviewed samples",
        );
        require(
            violations,
            self.release_evidence_schema
                .get("$id")
                .and_then(serde_json::Value::as_str)
                == Some("https://hartevo.example/contracts/release-evidence/2.2.0"),
            "release evidence JSON Schema must be version 2.2.0",
        );
    }

    fn materialize_unchecked(&self) -> Result<CatalogSnapshot, CatalogError> {
        let mut dataset_cases = Vec::with_capacity(EXPECTED_DATASET_CASE_COUNT);
        for (mission_index, mission) in self.missions.missions.iter().enumerate() {
            dataset_cases.extend(self.v0_cases(mission, mission_index));
            dataset_cases.extend(self.hidden_cases(mission, "V1", &self.datasets.v1_families));
            dataset_cases.extend(self.hidden_cases(mission, "V2", &self.datasets.v2_families));
        }
        let cross_cutting_cases = self.cross_cutting_cases();
        let stage_application_route_scopes = self.stage_application_route_scopes()?;
        let application_route_count = self
            .missions
            .missions
            .iter()
            .flat_map(|mission| &mission.checkpoint_routes)
            .filter(|route| route.executor == "application")
            .count();
        let checkpoint_route_count = self
            .missions
            .missions
            .iter()
            .map(|mission| mission.checkpoint_routes.len())
            .sum();
        let executable_stage_count =
            expanded_execution_stage_count(&self.missions, &self.effect_readback_routes);
        let route_graph_count = self.route_graphs.graphs.len();
        let route_graph_node_count = route_graph_node_count(&self.route_graphs);
        let route_graph_normal_edge_count = route_graph_normal_edge_count(&self.route_graphs);
        let route_graph_redirect_edge_count = route_graph_redirect_edge_count(&self.route_graphs);
        let route_graph_terminal_count = route_graph_terminal_count(&self.route_graphs);
        let implemented_application_handler_count = self.application_handlers.handlers.len();
        let summary = CatalogSummary {
            mission_count: self.missions.missions.len(),
            checkpoint_route_count,
            executable_stage_count,
            route_graph_count,
            route_graph_node_count,
            route_graph_normal_edge_count,
            route_graph_redirect_edge_count,
            route_graph_terminal_count,
            application_route_count,
            implemented_application_handler_count,
            not_implemented_application_route_count: application_route_count
                .saturating_sub(implemented_application_handler_count),
            capability_count: self.capabilities.capabilities.len(),
            provider_count: self.providers.providers.len(),
            fixture_count: self.datasets.fixtures.len(),
            simulator_count: self.datasets.simulators.len(),
            oracle_count: self.datasets.oracles.len(),
            dataset_case_count: dataset_cases.len(),
            v0_case_count: count_partition(&dataset_cases, "V0"),
            v1_case_count: count_partition(&dataset_cases, "V1"),
            v2_case_count: count_partition(&dataset_cases, "V2"),
            cross_cutting_case_count: cross_cutting_cases.len(),
            judge_calibration_sample_count: self.datasets.judge_calibration.required_samples,
        };
        let digest_input = serde_json::to_vec(&(
            &self.missions,
            &self.effect_readback_routes,
            &self.route_graphs,
            &self.route_runtime_authority,
            &self.stage_application_route_scope_contract,
            &stage_application_route_scopes,
            &self.application_handlers,
            &self.capabilities,
            &self.providers,
            &self.datasets,
            &self.release_evidence_schema,
            &dataset_cases,
            &cross_cutting_cases,
        ))?;

        Ok(CatalogSnapshot {
            schema_version: "hartevo-catalog-snapshot/v4".into(),
            mission_catalog_version: self.missions.catalog_version.clone(),
            effect_readback_route_contract_version: self
                .effect_readback_routes
                .contract_version
                .clone(),
            route_graph_contract_version: self.route_graphs.contract_version.clone(),
            application_handler_registry_version: self
                .application_handlers
                .registry_version
                .clone(),
            capability_catalog_version: self.capabilities.catalog_version.clone(),
            provider_catalog_version: self.providers.catalog_version.clone(),
            dataset_registry_version: self.datasets.registry_version.clone(),
            digest: sha256(&digest_input),
            summary,
            application_handlers: self.application_handlers.handlers.clone(),
            dataset_cases,
            cross_cutting_cases,
        })
    }

    fn v0_cases(
        &self,
        mission: &MissionManifest,
        mission_index: usize,
    ) -> Vec<DatasetCaseManifest> {
        let partition = self.partition("V0");
        let fixture_id = self.fixture_for_mission(&mission.id);
        let simulator_ids = simulators_for_mission(&mission.id);
        let mut cases = Vec::with_capacity(20);
        let mut base_index = 0_usize;
        for vertical in &self.datasets.verticals {
            for market in &self.datasets.markets {
                let maturity = self.datasets.asset_maturities
                    [(base_index + mission_index) % self.datasets.asset_maturities.len()]
                .clone();
                let persona = self.datasets.personas
                    [(base_index + mission_index) % self.datasets.personas.len()]
                .clone();
                let number = base_index + 1;
                let expected_terminal = if mission.id == "VM-08"
                    && matches!(vertical.as_str(), "b2b_saas" | "local_service")
                {
                    "expected_refusal"
                } else {
                    "pass"
                };
                cases.push(self.public_case(
                    mission,
                    partition,
                    number,
                    "vertical_market_base",
                    Some(vertical.clone()),
                    Some(market.clone()),
                    Some(maturity),
                    Some(persona),
                    fixture_id,
                    &simulator_ids,
                    expected_terminal,
                ));
                base_index += 1;
            }
        }
        for (offset, family) in self.datasets.v0_additional_families.iter().enumerate() {
            cases.push(self.public_case(
                mission,
                partition,
                13 + offset,
                family,
                None,
                None,
                None,
                None,
                if family == "truth_conflict" {
                    "conflicted-truth-v1"
                } else {
                    fixture_id
                },
                &simulator_ids,
                "pass",
            ));
        }
        cases
    }

    #[allow(clippy::too_many_arguments)]
    fn public_case(
        &self,
        mission: &MissionManifest,
        partition: &PartitionContract,
        number: usize,
        family: &str,
        vertical: Option<String>,
        market: Option<String>,
        asset_maturity: Option<String>,
        persona: Option<String>,
        fixture_id: &str,
        simulator_ids: &[String],
        expected_terminal: &str,
    ) -> DatasetCaseManifest {
        let id = format!("{}-V0-{number:03}", mission.id);
        let prompt = format!(
            "Complete {} for a {} project in {} as {} with {} assets. Exercise the {family} case family, preserve all hard constraints, and only claim outcomes accepted by the configured Business Oracles.",
            mission.title,
            vertical.as_deref().unwrap_or("fixture-backed"),
            market.as_deref().unwrap_or("the fixture market"),
            persona.as_deref().unwrap_or("the fixture persona"),
            asset_maturity.as_deref().unwrap_or("fixture-defined")
        );
        let digest = sha256(prompt.as_bytes());
        DatasetCaseManifest {
            id: id.clone(),
            version: 1,
            partition_id: partition.id.clone(),
            partition_name: partition.name.clone(),
            mission_id: mission.id.clone(),
            family: family.into(),
            vertical,
            market,
            asset_maturity,
            persona,
            fixture_id: fixture_id.into(),
            simulator_ids: simulator_ids.to_vec(),
            prompt: Some(prompt),
            checkpoint_ids: Some(mission.checkpoint_ids.clone()),
            oracle_ids: Some(mission.oracle_ids.clone()),
            expected_terminal: expected_terminal.into(),
            content_locator: format!("registry://vertical-dev/{id}"),
            content_digest: Some(digest),
            provenance: "Hartevo deterministic synthetic world".into(),
            license: "Proprietary-Eval".into(),
            frozen_after_candidate: false,
            contamination_canary_required: true,
            deterministic_seed: sha256(
                format!("{}|{}|{number}", self.datasets.registry_version, mission.id).as_bytes(),
            ),
        }
    }

    fn hidden_cases(
        &self,
        mission: &MissionManifest,
        partition_id: &str,
        families: &[String],
    ) -> Vec<DatasetCaseManifest> {
        let partition = self.partition(partition_id);
        let fixture_id = self.fixture_for_mission(&mission.id);
        let simulator_ids = simulators_for_mission(&mission.id);
        families
            .iter()
            .enumerate()
            .map(|(index, family)| {
                let number = index + 1;
                let id = format!("{}-{partition_id}-{number:03}", mission.id);
                DatasetCaseManifest {
                    id: id.clone(),
                    version: 1,
                    partition_id: partition.id.clone(),
                    partition_name: partition.name.clone(),
                    mission_id: mission.id.clone(),
                    family: family.clone(),
                    vertical: None,
                    market: None,
                    asset_maturity: None,
                    persona: None,
                    fixture_id: fixture_id.into(),
                    simulator_ids: simulator_ids.clone(),
                    prompt: None,
                    checkpoint_ids: None,
                    oracle_ids: None,
                    expected_terminal: if family == "expected_refusal_safety" {
                        "private_oracle_expected_refusal"
                    } else {
                        "private_oracle"
                    }
                    .into(),
                    content_locator: format!(
                        "private://{}/{}/{id}",
                        partition.name, self.datasets.registry_version
                    ),
                    content_digest: None,
                    provenance: "Private evaluator content; metadata only in product repository"
                        .into(),
                    license: "Private-Eval".into(),
                    frozen_after_candidate: partition_id == "V2",
                    contamination_canary_required: true,
                    deterministic_seed: sha256(
                        format!(
                            "metadata|{}|{}|{partition_id}|{number}",
                            self.datasets.registry_version, mission.id
                        )
                        .as_bytes(),
                    ),
                }
            })
            .collect()
    }

    fn cross_cutting_cases(&self) -> Vec<CrossCuttingCaseManifest> {
        let mut cases = Vec::with_capacity(EXPECTED_CROSS_CUTTING_CASE_COUNT);
        for suite in &self.datasets.cross_cutting_suites {
            for mission in &self.missions.missions {
                let id = format!("{}-{}-001", suite.id, mission.id);
                cases.push(CrossCuttingCaseManifest {
                    id: id.clone(),
                    version: 1,
                    suite_id: suite.id.clone(),
                    mission_id: mission.id.clone(),
                    expected_invariant: suite.description.clone(),
                    deterministic_seed: sha256(
                        format!("{}|{id}", self.datasets.registry_version).as_bytes(),
                    ),
                });
            }
        }
        cases
    }

    fn validate_snapshot(&self, snapshot: &CatalogSnapshot) -> Result<(), CatalogError> {
        let mut violations = Vec::new();
        Self::validate_snapshot_summary(snapshot, &mut violations);
        self.validate_mission_case_matrix(snapshot, &mut violations);
        self.validate_cross_cutting_matrix(snapshot, &mut violations);
        finish_validation(violations)
    }

    fn validate_snapshot_summary(snapshot: &CatalogSnapshot, violations: &mut Vec<String>) {
        let summary = &snapshot.summary;
        require(
            violations,
            snapshot.schema_version == "hartevo-catalog-snapshot/v4"
                && snapshot.route_graph_contract_version == "desktop-2026-08-12-ct02-v1",
            "Catalog Snapshot v4 must exactly bind the Mission route graph companion contract",
        );
        require(
            violations,
            summary.implemented_application_handler_count == snapshot.application_handlers.len()
                && summary.application_route_count
                    == summary.implemented_application_handler_count
                        + summary.not_implemented_application_route_count,
            "Application handler summary must expose implemented and NOT_IMPLEMENTED route coverage exactly",
        );
        require(
            violations,
            summary.checkpoint_route_count == EXPECTED_CHECKPOINT_ROUTE_COUNT
                && summary.executable_stage_count == EXPECTED_EXECUTABLE_STAGE_COUNT,
            "Catalog snapshot must expose exactly 123 checkpoint routes and 124 executable stages",
        );
        require(
            violations,
            summary.route_graph_count == EXPECTED_ROUTE_GRAPH_COUNT
                && summary.route_graph_node_count == EXPECTED_ROUTE_GRAPH_NODE_COUNT
                && summary.route_graph_normal_edge_count == EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT
                && summary.route_graph_redirect_edge_count
                    == EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT
                && summary.route_graph_terminal_count == EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT,
            "Catalog Snapshot v4 must freeze 12 graphs, 123 nodes, 124 normal edges, one bounded redirect and 12 terminals",
        );
        require(
            violations,
            summary.dataset_case_count == EXPECTED_DATASET_CASE_COUNT
                && summary.v0_case_count == EXPECTED_V0_CASE_COUNT
                && summary.v1_case_count == EXPECTED_V1_CASE_COUNT
                && summary.v2_case_count == EXPECTED_V2_CASE_COUNT,
            "dataset materialization must produce 240 V0 + 120 V1 + 60 V2 cases",
        );
        require(
            violations,
            summary.cross_cutting_case_count == EXPECTED_CROSS_CUTTING_CASE_COUNT,
            "cross-cutting materialization must produce fifteen suites times twelve Missions",
        );

        let case_ids: BTreeSet<&str> = snapshot
            .dataset_cases
            .iter()
            .map(|case| case.id.as_str())
            .collect();
        require(
            violations,
            case_ids.len() == snapshot.dataset_cases.len(),
            "dataset case ids must be unique",
        );
        require(
            violations,
            snapshot
                .dataset_cases
                .iter()
                .all(DatasetCaseManifest::private_content_is_isolated),
            "V0 content must be executable and V1/V2 private content must not be compiled in",
        );
    }

    fn validate_mission_case_matrix(
        &self,
        snapshot: &CatalogSnapshot,
        violations: &mut Vec<String>,
    ) {
        for mission in &self.missions.missions {
            let mission_cases: Vec<&DatasetCaseManifest> = snapshot
                .dataset_cases
                .iter()
                .filter(|case| case.mission_id == mission.id)
                .collect();
            require(
                violations,
                count_partition_refs(&mission_cases, "V0") == 20
                    && count_partition_refs(&mission_cases, "V1") == 10
                    && count_partition_refs(&mission_cases, "V2") == 5,
                format!(
                    "{} must have exactly 20 V0, 10 V1 and 5 V2 cases",
                    mission.id
                ),
            );
            let base_cases: Vec<&&DatasetCaseManifest> = mission_cases
                .iter()
                .filter(|case| case.partition_id == "V0" && case.family == "vertical_market_base")
                .collect();
            let pairs: BTreeSet<(&str, &str)> = base_cases
                .iter()
                .filter_map(|case| Some((case.vertical.as_deref()?, case.market.as_deref()?)))
                .collect();
            require(
                violations,
                pairs.len() == 12,
                format!(
                    "{} V0 must contain all twelve vertical-market pairs",
                    mission.id
                ),
            );
            for maturity in &self.datasets.asset_maturities {
                require(
                    violations,
                    base_cases
                        .iter()
                        .filter(|case| case.asset_maturity.as_ref() == Some(maturity))
                        .count()
                        == 3,
                    format!(
                        "{} must balance asset maturity {maturity} three times",
                        mission.id
                    ),
                );
            }
            for persona in &self.datasets.personas {
                require(
                    violations,
                    base_cases
                        .iter()
                        .filter(|case| case.persona.as_ref() == Some(persona))
                        .count()
                        == 3,
                    format!("{} must balance persona {persona} three times", mission.id),
                );
            }
        }
    }

    fn validate_cross_cutting_matrix(
        &self,
        snapshot: &CatalogSnapshot,
        violations: &mut Vec<String>,
    ) {
        let cross_ids: BTreeSet<&str> = snapshot
            .cross_cutting_cases
            .iter()
            .map(|case| case.id.as_str())
            .collect();
        require(
            violations,
            cross_ids.len() == snapshot.cross_cutting_cases.len(),
            "cross-cutting case ids must be unique",
        );
        for suite in &self.datasets.cross_cutting_suites {
            let covered: BTreeSet<&str> = snapshot
                .cross_cutting_cases
                .iter()
                .filter(|case| case.suite_id == suite.id)
                .map(|case| case.mission_id.as_str())
                .collect();
            require(
                violations,
                covered.len() == EXPECTED_MISSION_COUNT,
                format!("{} must cover all twelve Missions", suite.id),
            );
        }
    }

    fn partition(&self, partition_id: &str) -> &PartitionContract {
        self.datasets
            .partitions
            .iter()
            .find(|partition| partition.id == partition_id)
            .unwrap_or_else(|| panic!("validated partition {partition_id} must exist"))
    }

    fn fixture_for_mission<'a>(&'a self, mission_id: &str) -> &'a str {
        self.datasets
            .fixtures
            .iter()
            .find(|fixture| {
                fixture
                    .primary_mission_ids
                    .iter()
                    .any(|id| id == mission_id)
                    && fixture.id != "conflicted-truth-v1"
            })
            .map_or("conflicted-truth-v1", |fixture| fixture.id.as_str())
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("failed to parse {contract}: {source}")]
    Parse {
        contract: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize the materialized catalog: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("catalog validation failed:\n- {}", .0.join("\n- "))]
    Validation(Vec<String>),
}

fn parse_contract<T>(contract: &'static str, json: &str) -> Result<T, CatalogError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(json).map_err(|source| CatalogError::Parse { contract, source })
}

fn require(violations: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        violations.push(message.into());
    }
}

fn is_versioned_handler_id(value: &str) -> bool {
    value.rsplit_once("/v").is_some_and(|(name, version)| {
        !name.trim().is_empty()
            && version
                .parse::<u32>()
                .is_ok_and(|parsed| parsed > 0 && version == parsed.to_string())
    })
}

fn validate_application_handler_sources(
    handler: &ApplicationHandlerManifest,
    violations: &mut Vec<String>,
) {
    require_unique(
        violations,
        &handler.source_kinds,
        &format!("application handler {} source kinds", handler.handler_id),
    );
    let source_kind_set = handler
        .source_kinds
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let source_binding_set = handler
        .source_oracle_bindings
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    require(
        violations,
        source_kind_set == source_binding_set,
        format!(
            "application handler {} must bind every declared source kind exactly once",
            handler.handler_id
        ),
    );
    let mut bound_oracles = BTreeSet::new();
    let mut bound_oracle_count = 0_usize;
    for (source_kind, oracle_ids) in &handler.source_oracle_bindings {
        require(
            violations,
            !source_kind.trim().is_empty()
                && !oracle_ids.is_empty()
                && oracle_ids.iter().all(|oracle| !oracle.trim().is_empty()),
            format!(
                "application handler {} source {} must bind non-empty Oracles",
                handler.handler_id, source_kind
            ),
        );
        require_unique(
            violations,
            oracle_ids,
            &format!(
                "application handler {} source {} Oracle ids",
                handler.handler_id, source_kind
            ),
        );
        bound_oracle_count = bound_oracle_count.saturating_add(oracle_ids.len());
        bound_oracles.extend(oracle_ids.iter().cloned());
    }
    require_unique(
        violations,
        &handler.oracle_ids,
        &format!("application handler {} oracle ids", handler.handler_id),
    );
    require(
        violations,
        bound_oracle_count == bound_oracles.len()
            && bound_oracles == handler.oracle_ids.iter().cloned().collect::<BTreeSet<_>>(),
        format!(
            "application handler {} source bindings must cover its exact Oracle set",
            handler.handler_id
        ),
    );
}

fn require_unique(violations: &mut Vec<String>, values: &[String], label: &str) {
    let unique: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    require(
        violations,
        unique.len() == values.len(),
        format!("{label} must be unique"),
    );
}

fn require_named_unique(violations: &mut Vec<String>, values: &[NamedContract], label: &str) {
    let ids: Vec<String> = values.iter().map(|value| value.id.clone()).collect();
    require_unique(violations, &ids, &format!("{label} ids"));
}

fn finish_validation(violations: Vec<String>) -> Result<(), CatalogError> {
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CatalogError::Validation(violations))
    }
}

fn count_partition(cases: &[DatasetCaseManifest], partition_id: &str) -> usize {
    cases
        .iter()
        .filter(|case| case.partition_id == partition_id)
        .count()
}

fn count_partition_refs(cases: &[&DatasetCaseManifest], partition_id: &str) -> usize {
    cases
        .iter()
        .filter(|case| case.partition_id == partition_id)
        .count()
}

fn simulators_for_mission(mission_id: &str) -> Vec<String> {
    let ids: &[&str] = match mission_id {
        "VM-00" => &["stripe"],
        "VM-01" => &["search-dataforseo", "site-github", "commerce-attribution"],
        "VM-02" => &["ai-ground-truth", "channel-browser"],
        "VM-03" => &["site-github", "stripe", "commerce-attribution"],
        "VM-04" => &["channel-browser", "commerce-attribution"],
        "VM-05" | "VM-09" | "VM-10" => &["crm-email", "commerce-attribution"],
        "VM-06" => &["partner-network", "stripe", "commerce-attribution"],
        "VM-07" => &[
            "search-dataforseo",
            "ai-ground-truth",
            "marketplace-sorftime",
        ],
        "VM-08" => &["marketplace-sorftime", "commerce-attribution"],
        "VM-11" => &["commerce-attribution", "stripe"],
        _ => &[],
    };
    ids.iter().map(|value| (*value).into()).collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn contracts_form_a_closed_traceability_graph() {
        let catalog = Catalog::load().expect("valid catalog");
        assert_eq!(catalog.missions.missions.len(), EXPECTED_MISSION_COUNT);
        let snapshot = catalog.snapshot().expect("valid snapshot");
        assert_eq!(
            (
                snapshot.summary.application_route_count,
                snapshot.summary.implemented_application_handler_count,
                snapshot.summary.not_implemented_application_route_count,
            ),
            (52, 8, 44)
        );
        assert_eq!(
            catalog
                .application_handler("VM-11", 3, "event_ingest")
                .map(|handler| handler.handler_id.as_str()),
            Some("vm11.event_ingest/v2")
        );
        assert_eq!(
            catalog
                .application_handler("VM-11", 3, "normalize_dedupe_order")
                .map(|handler| handler.handler_id.as_str()),
            Some("vm11.normalize-dedupe-order/v1")
        );
        assert_eq!(
            catalog
                .application_handler("VM-11", 3, "identity_chain")
                .map(|handler| handler.handler_id.as_str()),
            Some("vm11.identity-chain/v1")
        );
        assert_eq!(
            catalog
                .application_handler("VM-11", 3, "next_contract_or_valid_terminal")
                .map(|handler| handler.handler_id.as_str()),
            Some("vm11.next-contract-or-valid-terminal/v1")
        );
        assert!(catalog.mission("VM-06").is_some_and(|mission| {
            mission
                .checkpoint_ids
                .contains(&"user_review_revision_or_acceptance".into())
                && mission
                    .required_artifacts
                    .contains(&"creator_deliverable".into())
        }));
    }

    #[test]
    fn creator_work_requires_real_delivery_review_before_payout() {
        let catalog = Catalog::load().expect("valid catalog");
        let mission = catalog.mission("VM-06").expect("VM-06");
        let position = |checkpoint: &str| {
            mission
                .checkpoint_ids
                .iter()
                .position(|candidate| candidate == checkpoint)
                .expect("required creator checkpoint")
        };
        assert!(mission.version >= 2);
        assert!(mission.modes.contains(&"campaign".into()));
        assert!(
            position("creator_task_and_bounty") < position("funding_readiness_and_reservation")
        );
        assert!(position("funding_readiness_and_reservation") < position("creator_acceptance"));
        assert!(position("creator_acceptance") < position("publication_or_deliverable_upload"));
        assert!(
            position("publication_or_deliverable_upload")
                < position("user_review_revision_or_acceptance")
        );
        assert!(
            position("user_review_revision_or_acceptance")
                < position("payout_approval_reconciliation")
        );
        assert!(
            position("payout_approval_reconciliation")
                < position("deliverable_entitlement_and_verified_settlement")
        );
        assert!(
            mission
                .capability_ids
                .contains(&"deliverable.review".into())
        );
        assert!(
            mission
                .required_artifacts
                .contains(&"creator_deliverable".into())
        );
        assert!(
            mission
                .required_artifacts
                .contains(&"funding_reservation".into())
        );
        assert!(
            mission
                .required_artifacts
                .contains(&"deliverable_entitlement".into())
        );
        assert!(
            mission
                .failure_families
                .contains(&"payout_before_acceptance".into())
        );
        assert!(
            mission
                .failure_families
                .contains(&"funding_reservation_claimed_as_escrow".into())
        );

        let snapshot = catalog.snapshot().expect("snapshot");
        assert!(
            snapshot
                .dataset_cases
                .iter()
                .filter(|case| case.partition_id == "V0" && case.mission_id == "VM-06")
                .all(
                    |case| case.checkpoint_ids.as_ref().is_some_and(|checkpoints| {
                        checkpoints.contains(&"creator_task_and_bounty".into())
                            && checkpoints.contains(&"user_review_revision_or_acceptance".into())
                    })
                )
        );
    }

    #[test]
    fn dataset_registry_materializes_exact_partition_counts() {
        let snapshot = Catalog::load()
            .expect("valid catalog")
            .snapshot()
            .expect("valid snapshot");
        assert_eq!(snapshot.summary.dataset_case_count, 420);
        assert_eq!(snapshot.summary.v0_case_count, 240);
        assert_eq!(snapshot.summary.v1_case_count, 120);
        assert_eq!(snapshot.summary.v2_case_count, 60);
        assert_eq!(snapshot.summary.cross_cutting_case_count, 180);
    }

    #[test]
    fn private_partitions_do_not_expose_eval_content() {
        let snapshot = Catalog::load()
            .expect("valid catalog")
            .snapshot()
            .expect("valid snapshot");
        assert!(snapshot.dataset_cases.iter().all(|case| {
            case.private_content_is_isolated()
                && (case.partition_id == "V0"
                    || (case.prompt.is_none()
                        && case.checkpoint_ids.is_none()
                        && case.oracle_ids.is_none()))
        }));
    }

    #[test]
    fn every_suite_covers_every_mission() {
        let snapshot = Catalog::load()
            .expect("valid catalog")
            .snapshot()
            .expect("valid snapshot");
        let coverage: BTreeMap<&str, usize> =
            snapshot
                .cross_cutting_cases
                .iter()
                .fold(BTreeMap::new(), |mut counts, case| {
                    *counts.entry(case.suite_id.as_str()).or_default() += 1;
                    counts
                });
        assert_eq!(coverage.len(), 15);
        assert!(coverage.values().all(|count| *count == 12));
    }

    #[test]
    fn materialization_is_deterministic() {
        let catalog = Catalog::load().expect("valid catalog");
        let first = catalog.snapshot().expect("first snapshot");
        let second = catalog.snapshot().expect("second snapshot");
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.dataset_cases, second.dataset_cases);
    }

    #[test]
    fn checkpoint_routes_are_ordered_complete_and_cannot_guess_a_capability() {
        let mut catalog = Catalog::load().expect("valid catalog");
        let vm10 = catalog
            .missions
            .missions
            .iter_mut()
            .find(|mission| mission.id == "VM-10")
            .expect("VM-10");
        assert_eq!(
            (
                vm10.checkpoint_routes[0].checkpoint_id.as_str(),
                vm10.checkpoint_routes[0].capability_id.as_str(),
                vm10.checkpoint_routes[0].executor.as_str(),
            ),
            (
                "webhook_signature_and_tenant_route",
                "webhook.ingest",
                "application"
            )
        );
        vm10.checkpoint_routes[0].capability_id = "payment.execute".into();
        assert!(catalog.validate_contracts().is_err());

        let mut reordered = Catalog::load().expect("valid catalog");
        reordered.missions.missions[0].checkpoint_routes.swap(0, 1);
        assert!(reordered.validate_contracts().is_err());
    }

    #[test]
    fn application_handler_registry_cannot_overstate_implementation_coverage() {
        let mut catalog = Catalog::load().expect("valid catalog");
        catalog.application_handlers.handlers[0].checkpoint_id = "candidate_learning".into();
        assert!(catalog.validate_contracts().is_err());

        let mut catalog = Catalog::load().expect("valid catalog");
        catalog.application_handlers.handlers[0]
            .oracle_ids
            .remove(0);
        assert!(catalog.validate_contracts().is_err());

        let mut catalog = Catalog::load().expect("valid catalog");
        catalog.application_handlers.handlers[0]
            .source_oracle_bindings
            .remove("mission_contract");
        assert!(catalog.validate_contracts().is_err());

        let mut catalog = Catalog::load().expect("valid catalog");
        let duplicate = catalog.application_handlers.handlers[0].clone();
        catalog.application_handlers.handlers.push(duplicate);
        assert!(catalog.validate_contracts().is_err());
    }
}
