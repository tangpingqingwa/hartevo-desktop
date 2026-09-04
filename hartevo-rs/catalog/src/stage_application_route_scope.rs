use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ApplicationHandlerManifest, ApplicationHandlerRegistry, CheckpointRouteManifest,
    MissionCatalog, MissionManifest, MissionRouteGraph, ReleaseStage, RouteGraphContract,
    RouteGraphNode, RouteGraphTerminal, RouteRuntimeAuthorityContract,
    RouteTerminalExecutionAuthority, RouteTerminalExecutionBinding,
    validate_route_runtime_authority_closure,
};

pub(crate) const STAGE_APPLICATION_ROUTE_SCOPE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/missions/stage-application-route-scope.v1.json");

pub const EXPECTED_STAGE_APPLICATION_ROUTE_SCOPE_COUNT: usize = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StageApplicationRouteScopeContract {
    pub schema_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub release_evidence_schema_version: String,
    pub mission_catalog_version: String,
    pub route_graph_contract_version: String,
    pub application_handler_registry_version: String,
    pub route_runtime_authority_contract_version: String,
    pub default_missing_handler_status: StageApplicationHandlerStatus,
    pub generic_runtime_authority: StageGenericRuntimeAuthority,
    pub stages: Vec<StageApplicationRouteSelection>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageGenericRuntimeAuthority {
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StageApplicationHandlerStatus {
    #[serde(rename = "IMPLEMENTED")]
    Implemented,
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StageApplicationRouteSelection {
    pub stage: ReleaseStage,
    pub required_mission_ids: Vec<String>,
    pub required_any_of_mission_sets: Vec<StageMissionAnyOfSelection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StageMissionAnyOfSelection {
    pub kind: StageMissionAnyOfKind,
    pub mission_ids: Vec<String>,
    pub minimum_selected: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageMissionAnyOfKind {
    WritingMission,
}

/// Deterministic upstream truth for one Release stage. This is Catalog
/// projection data, not Release evidence and not a runtime graph executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageApplicationRouteScope {
    pub contract_version: String,
    pub stage: ReleaseStage,
    pub generic_runtime_authority: StageGenericRuntimeAuthority,
    pub selection: StageApplicationRouteSelection,
    pub mission_scopes: Vec<StageMissionApplicationRouteScope>,
    pub summary: StageApplicationRouteScopeSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageMissionApplicationRouteScope {
    pub mission_id: String,
    pub mission_version: u32,
    pub route_graph_id: String,
    pub selection: StageMissionSelectionBinding,
    pub application_routes: Vec<StageApplicationRouteBinding>,
    pub terminals: Vec<RouteGraphTerminal>,
    pub non_application_terminal_transition_authorities: Vec<RouteTerminalExecutionBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageMissionSelectionBinding {
    pub required: bool,
    pub any_of_memberships: Vec<StageMissionAnyOfKind>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageApplicationRouteBinding {
    pub route: CheckpointRouteManifest,
    pub route_node: RouteGraphNode,
    pub handler: StageApplicationHandlerBinding,
    pub authority: StageApplicationRouteAuthority,
    pub terminal_transition_authorities: Vec<RouteTerminalExecutionBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageApplicationHandlerBinding {
    pub status: StageApplicationHandlerStatus,
    pub manifest: Option<ApplicationHandlerManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StageApplicationRouteAuthority {
    DeniedNotImplemented,
    RegisteredApplicationHandler {
        handler_id: String,
        implementation_crate: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageApplicationRouteScopeSummary {
    pub eligible_mission_count: usize,
    pub application_route_count: usize,
    pub implemented_handler_count: usize,
    pub not_implemented_handler_count: usize,
    pub terminal_count: usize,
    pub terminal_transition_count: usize,
    pub application_terminal_transition_count: usize,
    pub non_application_terminal_transition_count: usize,
    pub implemented_terminal_transition_authority_count: usize,
}

pub fn validate_stage_application_route_scope_closure(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    contract: &StageApplicationRouteScopeContract,
) -> Result<(), Vec<String>> {
    materialize_stage_application_route_scopes(
        missions,
        route_graphs,
        application_handlers,
        route_runtime_authority,
        contract,
    )
    .map(|_| ())
}

pub fn materialize_stage_application_route_scopes(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    contract: &StageApplicationRouteScopeContract,
) -> Result<Vec<StageApplicationRouteScope>, Vec<String>> {
    let mut violations = Vec::new();
    validate_contract_header(
        missions,
        route_graphs,
        application_handlers,
        route_runtime_authority,
        contract,
        &mut violations,
    );
    validate_stage_selections(contract, &mut violations);
    if let Err(mut authority_violations) = validate_route_runtime_authority_closure(
        missions,
        route_graphs,
        application_handlers,
        route_runtime_authority,
    ) {
        violations.append(&mut authority_violations);
    }
    validate_generic_runtime_authority(route_graphs, contract, &mut violations);

    let scopes = build_stage_application_route_scopes(
        missions,
        route_graphs,
        application_handlers,
        route_runtime_authority,
        contract,
        &mut violations,
    );
    validate_materialized_scope_shape(&scopes, &mut violations);

    if violations.is_empty() {
        Ok(scopes)
    } else {
        Err(violations)
    }
}

pub fn validate_materialized_stage_application_route_scopes(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    contract: &StageApplicationRouteScopeContract,
    scopes: &[StageApplicationRouteScope],
) -> Result<(), Vec<String>> {
    let expected = materialize_stage_application_route_scopes(
        missions,
        route_graphs,
        application_handlers,
        route_runtime_authority,
        contract,
    )?;
    if scopes == expected {
        Ok(())
    } else {
        Err(vec![
            "materialized stage Application route scopes must exactly match Catalog-derived truth"
                .into(),
        ])
    }
}

fn validate_contract_header(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    contract: &StageApplicationRouteScopeContract,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        contract.schema_version == "hartevo-stage-application-route-scope-contract/v1"
            && contract.contract_version == "desktop-2026-08-13-ct04-v1"
            && contract.evidence_level == "E1"
            && contract.release_evidence_schema_version == "2.3.0"
            && contract.default_missing_handler_status
                == StageApplicationHandlerStatus::NotImplemented
            && contract.generic_runtime_authority == StageGenericRuntimeAuthority::Denied,
        "stage Application route scope must use the frozen deny-by-default CT-04 E1 contract",
    );
    require(
        violations,
        contract.mission_catalog_version == missions.catalog_version,
        "stage Application route scope must bind the exact Mission Catalog version",
    );
    require(
        violations,
        contract.route_graph_contract_version == route_graphs.contract_version,
        "stage Application route scope must bind the exact route graph contract version",
    );
    require(
        violations,
        contract.application_handler_registry_version == application_handlers.registry_version,
        "stage Application route scope must bind the exact Application handler registry version",
    );
    require(
        violations,
        contract.route_runtime_authority_contract_version
            == route_runtime_authority.contract_version,
        "stage Application route scope must bind the exact route runtime authority contract version",
    );
}

fn validate_stage_selections(
    contract: &StageApplicationRouteScopeContract,
    violations: &mut Vec<String>,
) {
    let expected = expected_stage_selections();
    let stages = contract
        .stages
        .iter()
        .map(|selection| selection.stage)
        .collect::<BTreeSet<_>>();
    require(
        violations,
        contract.stages == expected
            && contract.stages.len() == EXPECTED_STAGE_APPLICATION_ROUTE_SCOPE_COUNT
            && stages.len() == contract.stages.len(),
        "stage Application route scope must freeze the exact five Release-stage Mission selections",
    );

    for selection in &contract.stages {
        let required = selection
            .required_mission_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let any_of = selection
            .required_any_of_mission_sets
            .iter()
            .flat_map(|group| group.mission_ids.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        require(
            violations,
            required.len() == selection.required_mission_ids.len()
                && selection.required_any_of_mission_sets.iter().all(|group| {
                    group.minimum_selected > 0
                        && group.minimum_selected <= group.mission_ids.len()
                        && group.mission_ids.iter().collect::<BTreeSet<_>>().len()
                            == group.mission_ids.len()
                })
                && required.is_disjoint(&any_of),
            format!(
                "{:?} Mission selection must be unique, non-overlapping and satisfiable",
                selection.stage
            ),
        );
    }
}

fn validate_generic_runtime_authority(
    route_graphs: &RouteGraphContract,
    contract: &StageApplicationRouteScopeContract,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        contract.generic_runtime_authority == StageGenericRuntimeAuthority::Denied
            && !route_graphs.runtime_authority.branch_execution()
            && !route_graphs.runtime_authority.redirect_execution()
            && !route_graphs.runtime_authority.optional_skip_execution()
            && !route_graphs.runtime_authority.terminal_execution(),
        "stage scopes cannot infer generic branch, redirect, optional-skip or terminal runtime authority",
    );
}

fn build_stage_application_route_scopes(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    contract: &StageApplicationRouteScopeContract,
    violations: &mut Vec<String>,
) -> Vec<StageApplicationRouteScope> {
    contract
        .stages
        .iter()
        .map(|selection| {
            build_stage_scope(
                missions,
                route_graphs,
                application_handlers,
                route_runtime_authority,
                contract,
                selection,
                violations,
            )
        })
        .collect()
}

fn build_stage_scope(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    contract: &StageApplicationRouteScopeContract,
    selection: &StageApplicationRouteSelection,
    violations: &mut Vec<String>,
) -> StageApplicationRouteScope {
    let eligible_ids = eligible_mission_ids(selection);
    let mission_scopes = missions
        .missions
        .iter()
        .filter(|mission| eligible_ids.contains(mission.id.as_str()))
        .filter_map(|mission| {
            build_mission_scope(
                route_graphs,
                application_handlers,
                route_runtime_authority,
                selection,
                mission,
                violations,
            )
        })
        .collect::<Vec<_>>();
    let summary = summarize_scope(&mission_scopes);
    StageApplicationRouteScope {
        contract_version: contract.contract_version.clone(),
        stage: selection.stage,
        generic_runtime_authority: contract.generic_runtime_authority,
        selection: selection.clone(),
        mission_scopes,
        summary,
    }
}

fn build_mission_scope(
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    selection: &StageApplicationRouteSelection,
    mission: &MissionManifest,
    violations: &mut Vec<String>,
) -> Option<StageMissionApplicationRouteScope> {
    let graph = route_graphs
        .graphs
        .iter()
        .find(|graph| graph.mission_id == mission.id);
    let Some(graph) = graph else {
        violations.push(format!(
            "{:?} Mission {} has no exact route graph",
            selection.stage, mission.id
        ));
        return None;
    };
    let application_routes = mission
        .checkpoint_routes
        .iter()
        .filter(|route| route.executor == "application")
        .filter_map(|route| {
            build_application_route_binding(
                selection.stage,
                mission,
                graph,
                route,
                application_handlers,
                route_runtime_authority,
                violations,
            )
        })
        .collect::<Vec<_>>();
    let application_checkpoint_ids = application_routes
        .iter()
        .map(|route| route.route.checkpoint_id.as_str())
        .collect::<BTreeSet<_>>();
    let non_application_terminal_transition_authorities = route_runtime_authority
        .terminal_transitions
        .iter()
        .filter(|binding| {
            binding.mission_id == mission.id
                && binding.mission_version == mission.version
                && !application_checkpoint_ids.contains(binding.source_checkpoint_id.as_str())
        })
        .cloned()
        .collect();
    Some(StageMissionApplicationRouteScope {
        mission_id: mission.id.clone(),
        mission_version: mission.version,
        route_graph_id: graph.id.clone(),
        selection: StageMissionSelectionBinding {
            required: selection.required_mission_ids.contains(&mission.id),
            any_of_memberships: selection
                .required_any_of_mission_sets
                .iter()
                .filter(|group| group.mission_ids.contains(&mission.id))
                .map(|group| group.kind)
                .collect(),
        },
        application_routes,
        terminals: graph.terminals.clone(),
        non_application_terminal_transition_authorities,
    })
}

fn build_application_route_binding(
    stage: ReleaseStage,
    mission: &MissionManifest,
    graph: &MissionRouteGraph,
    route: &CheckpointRouteManifest,
    application_handlers: &ApplicationHandlerRegistry,
    route_runtime_authority: &RouteRuntimeAuthorityContract,
    violations: &mut Vec<String>,
) -> Option<StageApplicationRouteBinding> {
    let node = graph
        .nodes
        .iter()
        .find(|node| node.checkpoint_id == route.checkpoint_id);
    let Some(node) = node else {
        violations.push(format!(
            "{stage:?} {}/{} Application route has no exact graph node",
            mission.id, route.checkpoint_id
        ));
        return None;
    };
    let handler = application_handlers.handlers.iter().find(|handler| {
        handler.mission_id == mission.id
            && handler.mission_version == mission.version
            && handler.checkpoint_id == route.checkpoint_id
    });
    let (handler, authority) = application_route_authority(handler);
    let terminal_transition_authorities = route_runtime_authority
        .terminal_transitions
        .iter()
        .filter(|binding| {
            binding.mission_id == mission.id
                && binding.mission_version == mission.version
                && binding.source_checkpoint_id == route.checkpoint_id
        })
        .cloned()
        .collect();
    Some(StageApplicationRouteBinding {
        route: route.clone(),
        route_node: node.clone(),
        handler,
        authority,
        terminal_transition_authorities,
    })
}

fn application_route_authority(
    handler: Option<&ApplicationHandlerManifest>,
) -> (
    StageApplicationHandlerBinding,
    StageApplicationRouteAuthority,
) {
    handler.map_or_else(
        || {
            (
                StageApplicationHandlerBinding {
                    status: StageApplicationHandlerStatus::NotImplemented,
                    manifest: None,
                },
                StageApplicationRouteAuthority::DeniedNotImplemented,
            )
        },
        |handler| {
            (
                StageApplicationHandlerBinding {
                    status: StageApplicationHandlerStatus::Implemented,
                    manifest: Some(handler.clone()),
                },
                StageApplicationRouteAuthority::RegisteredApplicationHandler {
                    handler_id: handler.handler_id.clone(),
                    implementation_crate: handler.implementation_crate.clone(),
                },
            )
        },
    )
}

fn validate_materialized_scope_shape(
    scopes: &[StageApplicationRouteScope],
    violations: &mut Vec<String>,
) {
    require(
        violations,
        scopes.len() == EXPECTED_STAGE_APPLICATION_ROUTE_SCOPE_COUNT,
        "Catalog must materialize exactly five stage Application route scopes",
    );
    for scope in scopes {
        validate_stage_scope_shape(scope, violations);
    }
}

fn validate_stage_scope_shape(scope: &StageApplicationRouteScope, violations: &mut Vec<String>) {
    let expected_summary = expected_scope_summary(scope.stage);
    require(
        violations,
        scope.summary == expected_summary,
        format!(
            "{:?} stage Application route scope must preserve its frozen Mission/route/handler/terminal counts: actual={:?}, expected={expected_summary:?}",
            scope.stage, scope.summary
        ),
    );
    for mission in &scope.mission_scopes {
        validate_mission_scope_shape(scope.stage, mission, violations);
    }
}

fn validate_mission_scope_shape(
    stage: ReleaseStage,
    mission: &StageMissionApplicationRouteScope,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        mission.selection.required || !mission.selection.any_of_memberships.is_empty(),
        format!(
            "{stage:?} Mission {} must be selected by a typed stage rule",
            mission.mission_id
        ),
    );
    for route in &mission.application_routes {
        validate_application_route_shape(stage, mission, route, violations);
    }
    let application_checkpoint_ids = mission
        .application_routes
        .iter()
        .map(|route| route.route.checkpoint_id.as_str())
        .collect::<BTreeSet<_>>();
    for terminal in &mission.non_application_terminal_transition_authorities {
        let exact = terminal.mission_id == mission.mission_id
            && terminal.mission_version == mission.mission_version
            && !application_checkpoint_ids.contains(terminal.source_checkpoint_id.as_str())
            && terminal_exists(mission, terminal)
            && matches!(
                terminal.authority,
                RouteTerminalExecutionAuthority::Denied(_)
            );
        require(
            violations,
            exact,
            format!(
                "{stage:?} {}/{} is outside Application scope and must retain explicit denied terminal authority",
                mission.mission_id, terminal.source_checkpoint_id
            ),
        );
    }
}

fn validate_application_route_shape(
    stage: ReleaseStage,
    mission: &StageMissionApplicationRouteScope,
    route: &StageApplicationRouteBinding,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        route.route.executor == "application"
            && route.route_node.checkpoint_id == route.route.checkpoint_id
            && application_handler_binding_is_exact(mission, route),
        format!(
            "{stage:?} {}/{} must bind one exact graph node, handler status and fail-closed authority",
            mission.mission_id, route.route.checkpoint_id
        ),
    );
    for terminal in &route.terminal_transition_authorities {
        require(
            violations,
            terminal.mission_id == mission.mission_id
                && terminal.mission_version == mission.mission_version
                && terminal.source_checkpoint_id == route.route.checkpoint_id
                && terminal_exists(mission, terminal),
            format!(
                "{stage:?} {}/{} terminal authority must bind its exact Mission terminal set",
                mission.mission_id, route.route.checkpoint_id
            ),
        );
    }
}

fn application_handler_binding_is_exact(
    mission: &StageMissionApplicationRouteScope,
    route: &StageApplicationRouteBinding,
) -> bool {
    let implemented = route.handler.status == StageApplicationHandlerStatus::Implemented;
    match (&route.handler.manifest, &route.authority) {
        (
            Some(handler),
            StageApplicationRouteAuthority::RegisteredApplicationHandler {
                handler_id,
                implementation_crate,
            },
        ) => {
            implemented
                && handler.handler_id == *handler_id
                && handler.implementation_crate == *implementation_crate
                && handler.mission_id == mission.mission_id
                && handler.mission_version == mission.mission_version
                && handler.checkpoint_id == route.route.checkpoint_id
                && handler.capability_id == route.route.capability_id
                && handler.completion_policy == route.route.completion_policy
                && handler.oracle_ids.iter().collect::<BTreeSet<_>>()
                    == route.route.oracle_ids.iter().collect::<BTreeSet<_>>()
        }
        (None, StageApplicationRouteAuthority::DeniedNotImplemented) => !implemented,
        _ => false,
    }
}

fn terminal_exists(
    mission: &StageMissionApplicationRouteScope,
    terminal: &RouteTerminalExecutionBinding,
) -> bool {
    mission
        .terminals
        .iter()
        .any(|candidate| candidate.id == terminal.terminal_id)
}

fn summarize_scope(
    mission_scopes: &[StageMissionApplicationRouteScope],
) -> StageApplicationRouteScopeSummary {
    let application_route_count = mission_scopes
        .iter()
        .map(|mission| mission.application_routes.len())
        .sum();
    let implemented_handler_count = mission_scopes
        .iter()
        .flat_map(|mission| &mission.application_routes)
        .filter(|route| route.handler.status == StageApplicationHandlerStatus::Implemented)
        .count();
    let application_terminal_transition_count = mission_scopes
        .iter()
        .flat_map(|mission| &mission.application_routes)
        .map(|route| route.terminal_transition_authorities.len())
        .sum();
    let non_application_terminal_transition_count = mission_scopes
        .iter()
        .map(|mission| {
            mission
                .non_application_terminal_transition_authorities
                .len()
        })
        .sum();
    let implemented_application_terminal_transition_authority_count = mission_scopes
        .iter()
        .flat_map(|mission| &mission.application_routes)
        .flat_map(|route| &route.terminal_transition_authorities)
        .filter(|binding| {
            matches!(
                binding.authority,
                RouteTerminalExecutionAuthority::ApplicationHandler(_)
            )
        })
        .count();
    let implemented_non_application_terminal_transition_authority_count = mission_scopes
        .iter()
        .flat_map(|mission| &mission.non_application_terminal_transition_authorities)
        .filter(|binding| {
            matches!(
                binding.authority,
                RouteTerminalExecutionAuthority::ApplicationHandler(_)
            )
        })
        .count();
    StageApplicationRouteScopeSummary {
        eligible_mission_count: mission_scopes.len(),
        application_route_count,
        implemented_handler_count,
        not_implemented_handler_count: application_route_count
            .saturating_sub(implemented_handler_count),
        terminal_count: mission_scopes
            .iter()
            .map(|mission| mission.terminals.len())
            .sum(),
        terminal_transition_count: application_terminal_transition_count
            + non_application_terminal_transition_count,
        application_terminal_transition_count,
        non_application_terminal_transition_count,
        implemented_terminal_transition_authority_count:
            implemented_application_terminal_transition_authority_count
                + implemented_non_application_terminal_transition_authority_count,
    }
}

fn expected_scope_summary(stage: ReleaseStage) -> StageApplicationRouteScopeSummary {
    let values = match stage {
        ReleaseStage::EngineeringFoundation | ReleaseStage::InternalAlpha => {
            (7, 29, 11, 18, 7, 8, 7, 1, 1)
        }
        ReleaseStage::ControlledBeta => (6, 22, 0, 22, 6, 6, 5, 1, 0),
        ReleaseStage::GeneralAvailability | ReleaseStage::MatureE5 => {
            (12, 52, 11, 41, 12, 13, 12, 1, 1)
        }
    };
    StageApplicationRouteScopeSummary {
        eligible_mission_count: values.0,
        application_route_count: values.1,
        implemented_handler_count: values.2,
        not_implemented_handler_count: values.3,
        terminal_count: values.4,
        terminal_transition_count: values.5,
        application_terminal_transition_count: values.6,
        non_application_terminal_transition_count: values.7,
        implemented_terminal_transition_authority_count: values.8,
    }
}

fn eligible_mission_ids(selection: &StageApplicationRouteSelection) -> BTreeSet<&str> {
    selection
        .required_mission_ids
        .iter()
        .chain(
            selection
                .required_any_of_mission_sets
                .iter()
                .flat_map(|group| &group.mission_ids),
        )
        .map(String::as_str)
        .collect()
}

fn expected_stage_selections() -> Vec<StageApplicationRouteSelection> {
    let all_missions = (0..12)
        .map(|index| format!("VM-{index:02}"))
        .collect::<Vec<String>>();
    let foundation = || StageApplicationRouteSelection {
        stage: ReleaseStage::EngineeringFoundation,
        required_mission_ids: vec!["VM-00".into(), "VM-07".into(), "VM-11".into()],
        required_any_of_mission_sets: vec![StageMissionAnyOfSelection {
            kind: StageMissionAnyOfKind::WritingMission,
            mission_ids: vec![
                "VM-01".into(),
                "VM-03".into(),
                "VM-04".into(),
                "VM-05".into(),
            ],
            minimum_selected: 1,
        }],
    };
    let mut engineering_foundation = foundation();
    let mut internal_alpha = foundation();
    internal_alpha.stage = ReleaseStage::InternalAlpha;
    engineering_foundation.stage = ReleaseStage::EngineeringFoundation;
    vec![
        engineering_foundation,
        internal_alpha,
        StageApplicationRouteSelection {
            stage: ReleaseStage::ControlledBeta,
            required_mission_ids: (1..=6).map(|index| format!("VM-{index:02}")).collect(),
            required_any_of_mission_sets: Vec::new(),
        },
        StageApplicationRouteSelection {
            stage: ReleaseStage::GeneralAvailability,
            required_mission_ids: all_missions.clone(),
            required_any_of_mission_sets: Vec::new(),
        },
        StageApplicationRouteSelection {
            stage: ReleaseStage::MatureE5,
            required_mission_ids: all_missions,
            required_any_of_mission_sets: Vec::new(),
        },
    ]
}

fn require(violations: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        violations.push(message.into());
    }
}
