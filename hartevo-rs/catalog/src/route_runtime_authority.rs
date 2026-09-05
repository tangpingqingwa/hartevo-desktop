use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ApplicationHandlerRegistry, MissionCatalog, RouteCondition, RouteGraphContract,
    RouteGraphTerminalDisposition, RouteGraphTransitionTargetKind,
};

pub(crate) const ROUTE_RUNTIME_AUTHORITY_CONTRACT_JSON: &str =
    include_str!("../../../contracts/missions/route-runtime-authority.v1.json");

pub const EXPECTED_TERMINAL_TRANSITION_AUTHORITY_COUNT: usize = 13;
pub const EXPECTED_IMPLEMENTED_TERMINAL_TRANSITION_AUTHORITY_COUNT: usize = 3;
pub const EXPECTED_DENIED_TERMINAL_TRANSITION_AUTHORITY_COUNT: usize = 10;

const VM04_CHANNEL_REBALANCE_TRANSITION_ID: &str = "vm04.channel_rebalance.to.valid-terminal/v2";
const VM04_CHANNEL_REBALANCE_HANDLER_ID: &str = "vm04.channel-rebalance/v1";
const VM11_STOP_TRANSITION_ID: &str =
    "vm11.next_contract_or_valid_terminal.to.valid-terminal.stop/v2";
const VM11_STOP_HANDLER_ID: &str = "vm11.next-contract-or-valid-terminal/v1";
const VM11_CANDIDATE_LEARNING_TRANSITION_ID: &str = "vm11.candidate_learning.to.valid-terminal/v2";
const VM11_CANDIDATE_LEARNING_HANDLER_ID: &str = "vm11.candidate-learning/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteRuntimeAuthorityContract {
    pub schema_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub route_graph_contract_version: String,
    pub application_handler_registry_version: String,
    pub default_terminal_execution_authority: DefaultTerminalExecutionAuthority,
    pub terminal_transitions: Vec<RouteTerminalExecutionBinding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultTerminalExecutionAuthority {
    Denied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteTerminalExecutionBinding {
    pub transition_id: String,
    pub mission_id: String,
    pub mission_version: u32,
    pub source_checkpoint_id: String,
    pub condition: RouteCondition,
    pub terminal_id: String,
    pub authority: RouteTerminalExecutionAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RouteTerminalExecutionAuthority {
    Denied(DeniedRouteTerminalExecutionAuthority),
    ApplicationHandler(ApplicationHandlerRouteTerminalExecutionAuthority),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeniedRouteTerminalExecutionAuthority {
    pub kind: DeniedRouteTerminalExecutionAuthorityKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedRouteTerminalExecutionAuthorityKind {
    Denied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplicationHandlerRouteTerminalExecutionAuthority {
    pub kind: ApplicationHandlerRouteTerminalExecutionAuthorityKind,
    pub executor: RouteTerminalAuthorityExecutor,
    pub handler_id: String,
    pub implementation_crate: String,
    pub completion_policy: RouteTerminalCompletionPolicy,
    pub mission_disposition: RouteGraphTerminalDisposition,
    pub skipped_checkpoint_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationHandlerRouteTerminalExecutionAuthorityKind {
    ApplicationHandler,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTerminalAuthorityExecutor {
    Application,
    Runtime,
    EffectBroker,
    Human,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTerminalCompletionPolicy {
    DeterministicEvidence,
    WorkProduct,
    VerifiedEffect,
    EffectReadbackV2,
    HumanConfirmation,
}

impl RouteTerminalCompletionPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicEvidence => "deterministic_evidence",
            Self::WorkProduct => "work_product",
            Self::VerifiedEffect => "verified_effect",
            Self::EffectReadbackV2 => "effect_readback_v2",
            Self::HumanConfirmation => "human_confirmation",
        }
    }
}

pub fn terminal_transition_authority_count(contract: &RouteRuntimeAuthorityContract) -> usize {
    contract.terminal_transitions.len()
}

pub fn implemented_terminal_transition_authority_count(
    contract: &RouteRuntimeAuthorityContract,
) -> usize {
    contract
        .terminal_transitions
        .iter()
        .filter(|binding| {
            matches!(
                binding.authority,
                RouteTerminalExecutionAuthority::ApplicationHandler(_)
            )
        })
        .count()
}

pub fn denied_terminal_transition_authority_count(
    contract: &RouteRuntimeAuthorityContract,
) -> usize {
    contract
        .terminal_transitions
        .iter()
        .filter(|binding| {
            matches!(
                binding.authority,
                RouteTerminalExecutionAuthority::Denied(_)
            )
        })
        .count()
}

pub fn validate_route_runtime_authority_closure(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    contract: &RouteRuntimeAuthorityContract,
) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    validate_header(
        route_graphs,
        application_handlers,
        contract,
        &mut violations,
    );
    validate_generic_authority_remains_denied(route_graphs, &mut violations);
    validate_terminal_transition_coverage(route_graphs, contract, &mut violations);
    validate_terminal_transition_authorities(
        missions,
        route_graphs,
        application_handlers,
        contract,
        &mut violations,
    );

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn validate_header(
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    contract: &RouteRuntimeAuthorityContract,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        contract.schema_version == "hartevo-mission-route-runtime-authority-contract/v1"
            && contract.contract_version == "desktop-2026-09-05-ct03-v7"
            && contract.evidence_level == "E1"
            && contract.default_terminal_execution_authority
                == DefaultTerminalExecutionAuthority::Denied,
        "Mission route runtime authority must use the frozen deny-by-default CT-03 E1 contract",
    );
    require(
        violations,
        contract.route_graph_contract_version == route_graphs.contract_version,
        "Mission route runtime authority must bind the exact route graph contract version",
    );
    require(
        violations,
        contract.application_handler_registry_version == application_handlers.registry_version,
        "Mission route runtime authority must bind the exact Application handler registry version",
    );
}

fn validate_generic_authority_remains_denied(
    route_graphs: &RouteGraphContract,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        !route_graphs.runtime_authority.branch_execution()
            && !route_graphs.runtime_authority.redirect_execution()
            && !route_graphs.runtime_authority.optional_skip_execution()
            && !route_graphs.runtime_authority.terminal_execution(),
        "generic route graph branch, redirect, optional-skip and terminal authority must remain denied",
    );
}

type TerminalTransitionKey = (String, u32, String, String, RouteCondition, String);

fn validate_terminal_transition_coverage(
    route_graphs: &RouteGraphContract,
    contract: &RouteRuntimeAuthorityContract,
    violations: &mut Vec<String>,
) {
    let expected = route_graphs
        .graphs
        .iter()
        .flat_map(|graph| {
            graph
                .transitions
                .iter()
                .filter(|transition| {
                    transition.target.kind == RouteGraphTransitionTargetKind::Terminal
                })
                .map(|transition| {
                    (
                        graph.mission_id.clone(),
                        graph.mission_version,
                        transition.id.clone(),
                        transition.source_checkpoint_id.clone(),
                        transition.condition,
                        transition.target.terminal_id.clone().unwrap_or_default(),
                    )
                })
        })
        .collect::<Vec<TerminalTransitionKey>>();
    let actual = contract
        .terminal_transitions
        .iter()
        .map(|binding| {
            (
                binding.mission_id.clone(),
                binding.mission_version,
                binding.transition_id.clone(),
                binding.source_checkpoint_id.clone(),
                binding.condition,
                binding.terminal_id.clone(),
            )
        })
        .collect::<Vec<TerminalTransitionKey>>();
    let transition_ids = contract
        .terminal_transitions
        .iter()
        .map(|binding| binding.transition_id.as_str())
        .collect::<BTreeSet<_>>();

    require(
        violations,
        actual == expected
            && actual.len() == EXPECTED_TERMINAL_TRANSITION_AUTHORITY_COUNT
            && transition_ids.len() == actual.len(),
        "runtime authority must cover every terminal transition exactly once in frozen graph order",
    );
}

fn validate_terminal_transition_authorities(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    contract: &RouteRuntimeAuthorityContract,
    violations: &mut Vec<String>,
) {
    for binding in &contract.terminal_transitions {
        if binding.transition_id == VM04_CHANNEL_REBALANCE_TRANSITION_ID {
            validate_vm04_channel_rebalance_authority(
                missions,
                route_graphs,
                application_handlers,
                binding,
                violations,
            );
        } else if binding.transition_id == VM11_STOP_TRANSITION_ID {
            validate_vm11_stop_authority(
                missions,
                route_graphs,
                application_handlers,
                binding,
                violations,
            );
        } else if binding.transition_id == VM11_CANDIDATE_LEARNING_TRANSITION_ID {
            validate_vm11_candidate_learning_authority(
                missions,
                route_graphs,
                application_handlers,
                binding,
                violations,
            );
        } else {
            require(
                violations,
                matches!(
                    binding.authority,
                    RouteTerminalExecutionAuthority::Denied(_)
                ),
                format!(
                    "terminal transition {} is not implemented and must remain denied",
                    binding.transition_id
                ),
            );
        }
    }

    require(
        violations,
        terminal_transition_authority_count(contract)
            == EXPECTED_TERMINAL_TRANSITION_AUTHORITY_COUNT
            && implemented_terminal_transition_authority_count(contract)
                == EXPECTED_IMPLEMENTED_TERMINAL_TRANSITION_AUTHORITY_COUNT
            && denied_terminal_transition_authority_count(contract)
                == EXPECTED_DENIED_TERMINAL_TRANSITION_AUTHORITY_COUNT,
        "runtime authority must expose exactly three implemented and ten denied terminal transitions",
    );
}

fn validate_vm04_channel_rebalance_authority(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    binding: &RouteTerminalExecutionBinding,
    violations: &mut Vec<String>,
) {
    let RouteTerminalExecutionAuthority::ApplicationHandler(authority) = &binding.authority else {
        violations.push(
            "VM-04 channel rebalance must bind its exact implemented Application terminal authority"
                .into(),
        );
        return;
    };
    require(
        violations,
        authority.kind == ApplicationHandlerRouteTerminalExecutionAuthorityKind::ApplicationHandler
            && authority.executor == RouteTerminalAuthorityExecutor::Application
            && authority.handler_id == VM04_CHANNEL_REBALANCE_HANDLER_ID
            && authority.implementation_crate == "hartevo-application"
            && authority.completion_policy == RouteTerminalCompletionPolicy::DeterministicEvidence
            && authority.mission_disposition == RouteGraphTerminalDisposition::Completed
            && authority.skipped_checkpoint_ids.is_empty(),
        "VM-04 channel-rebalance terminal authority must bind Completed with no skipped checkpoints",
    );

    validate_application_handler_terminal_binding(
        missions,
        route_graphs,
        application_handlers,
        binding,
        authority,
        "VM-04 channel rebalance",
        violations,
    );
}

fn validate_vm11_stop_authority(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    binding: &RouteTerminalExecutionBinding,
    violations: &mut Vec<String>,
) {
    let RouteTerminalExecutionAuthority::ApplicationHandler(authority) = &binding.authority else {
        violations.push(
            "VM-11 Stop must bind its exact implemented Application terminal authority".into(),
        );
        return;
    };
    require(
        violations,
        authority.kind == ApplicationHandlerRouteTerminalExecutionAuthorityKind::ApplicationHandler
            && authority.executor == RouteTerminalAuthorityExecutor::Application
            && authority.handler_id == VM11_STOP_HANDLER_ID
            && authority.implementation_crate == "hartevo-application"
            && authority.completion_policy == RouteTerminalCompletionPolicy::DeterministicEvidence
            && authority.mission_disposition == RouteGraphTerminalDisposition::Completed
            && authority.skipped_checkpoint_ids == ["candidate_learning"],
        "VM-11 Stop terminal authority must bind Completed plus the exact candidate-learning bypass",
    );

    validate_application_handler_terminal_binding(
        missions,
        route_graphs,
        application_handlers,
        binding,
        authority,
        "VM-11 Stop",
        violations,
    );
}

fn validate_vm11_candidate_learning_authority(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    binding: &RouteTerminalExecutionBinding,
    violations: &mut Vec<String>,
) {
    let RouteTerminalExecutionAuthority::ApplicationHandler(authority) = &binding.authority else {
        violations.push(
            "VM-11 candidate learning must bind its exact implemented Application terminal authority"
                .into(),
        );
        return;
    };
    require(
        violations,
        authority.kind == ApplicationHandlerRouteTerminalExecutionAuthorityKind::ApplicationHandler
            && authority.executor == RouteTerminalAuthorityExecutor::Application
            && authority.handler_id == VM11_CANDIDATE_LEARNING_HANDLER_ID
            && authority.implementation_crate == "hartevo-application"
            && authority.completion_policy == RouteTerminalCompletionPolicy::DeterministicEvidence
            && authority.mission_disposition == RouteGraphTerminalDisposition::Completed
            && authority.skipped_checkpoint_ids.is_empty(),
        "VM-11 candidate-learning terminal authority must bind Completed with no skipped checkpoints",
    );

    validate_application_handler_terminal_binding(
        missions,
        route_graphs,
        application_handlers,
        binding,
        authority,
        "VM-11 candidate learning",
        violations,
    );
}

fn validate_application_handler_terminal_binding(
    missions: &MissionCatalog,
    route_graphs: &RouteGraphContract,
    application_handlers: &ApplicationHandlerRegistry,
    binding: &RouteTerminalExecutionBinding,
    authority: &ApplicationHandlerRouteTerminalExecutionAuthority,
    label: &str,
    violations: &mut Vec<String>,
) {
    let mission = missions
        .missions
        .iter()
        .find(|mission| mission.id == binding.mission_id);
    let route = mission.and_then(|mission| {
        mission
            .checkpoint_routes
            .iter()
            .find(|route| route.checkpoint_id == binding.source_checkpoint_id)
    });
    let handler = application_handlers
        .handlers
        .iter()
        .find(|handler| handler.handler_id == authority.handler_id);
    require(
        violations,
        mission.is_some_and(|mission| mission.version == binding.mission_version)
            && route.is_some_and(|route| {
                route.executor == "application"
                    && route.completion_policy == authority.completion_policy.as_str()
            })
            && handler.is_some_and(|handler| {
                handler.mission_id == binding.mission_id
                    && handler.mission_version == binding.mission_version
                    && handler.checkpoint_id == binding.source_checkpoint_id
                    && handler.implementation_crate == authority.implementation_crate
                    && handler.completion_policy == authority.completion_policy.as_str()
                    && route.is_some_and(|route| {
                        handler.capability_id == route.capability_id
                            && handler.oracle_ids.iter().collect::<BTreeSet<_>>()
                                == route.oracle_ids.iter().collect::<BTreeSet<_>>()
                    })
            }),
        format!(
            "{label} authority must close against the exact Mission route and registered production handler"
        ),
    );

    let terminal = route_graphs
        .graphs
        .iter()
        .find(|graph| graph.mission_id == binding.mission_id)
        .and_then(|graph| {
            graph
                .terminals
                .iter()
                .find(|terminal| terminal.id == binding.terminal_id)
        });
    require(
        violations,
        terminal.is_some_and(|terminal| {
            terminal.mission_disposition == Some(authority.mission_disposition)
        }),
        format!("{label} authority must target the typed Completed Mission terminal"),
    );
}

fn require(violations: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        violations.push(message.into());
    }
}
