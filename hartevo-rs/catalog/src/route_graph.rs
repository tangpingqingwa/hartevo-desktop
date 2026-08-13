use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{CapabilityCatalog, EffectReadbackRouteContract, MissionCatalog, MissionManifest};

pub(crate) const ROUTE_GRAPH_CONTRACT_JSON: &str =
    include_str!("../../../contracts/missions/route-graph.v2.json");

pub const EXPECTED_ROUTE_GRAPH_COUNT: usize = 12;
pub const EXPECTED_ROUTE_GRAPH_NODE_COUNT: usize = 124;
pub const EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT: usize = 125;
pub const EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT: usize = 1;
pub const EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT: usize = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphContract {
    pub schema_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub runtime_authority: RouteGraphRuntimeAuthority,
    pub graphs: Vec<MissionRouteGraph>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphRuntimeAuthority {
    #[serde(rename = "branchExecution")]
    branch: DeniedRuntimeAuthority,
    #[serde(rename = "redirectExecution")]
    redirect: DeniedRuntimeAuthority,
    #[serde(rename = "optionalSkipExecution")]
    optional_skip: DeniedRuntimeAuthority,
    #[serde(rename = "terminalExecution")]
    terminal: DeniedRuntimeAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "bool", into = "bool")]
struct DeniedRuntimeAuthority;

impl RouteGraphRuntimeAuthority {
    pub fn branch_execution(&self) -> bool {
        self.branch.into()
    }

    pub fn redirect_execution(&self) -> bool {
        self.redirect.into()
    }

    pub fn optional_skip_execution(&self) -> bool {
        self.optional_skip.into()
    }

    pub fn terminal_execution(&self) -> bool {
        self.terminal.into()
    }
}

impl TryFrom<bool> for DeniedRuntimeAuthority {
    type Error = &'static str;

    fn try_from(claimed: bool) -> Result<Self, Self::Error> {
        if claimed {
            Err("Mission route graph runtime authority must be false")
        } else {
            Ok(Self)
        }
    }
}

impl From<DeniedRuntimeAuthority> for bool {
    fn from(_claim: DeniedRuntimeAuthority) -> Self {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionRouteGraph {
    pub id: String,
    pub mission_id: String,
    pub mission_version: u32,
    pub entry_checkpoint_id: String,
    pub nodes: Vec<RouteGraphNode>,
    pub transitions: Vec<RouteGraphTransition>,
    pub redirects: Vec<RouteGraphRedirect>,
    pub terminals: Vec<RouteGraphTerminal>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphNode {
    pub checkpoint_id: String,
    pub depends_on: Vec<String>,
    pub optional: bool,
    pub completion_gate: RouteNodeCompletionGate,
    pub waiting_user_conditions: Vec<RouteCondition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteNodeCompletionGateKind {
    CheckpointRoutePolicy,
    EffectReadbackV2TerminalVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteNodeCompletionGate {
    pub kind: RouteNodeCompletionGateKind,
    pub flow_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RouteCondition {
    #[serde(rename = "checkpoint.completed")]
    CheckpointCompleted,
    #[serde(rename = "effect_readback_v2.terminal_verification_satisfied")]
    EffectReadbackV2TerminalVerificationSatisfied,
    #[serde(rename = "vm07_replan_resolution.replan")]
    Vm07Replan,
    #[serde(rename = "vm07_replan_resolution.valid_terminal")]
    Vm07ValidTerminal,
    #[serde(rename = "outcome_review_next_contract_resolution.stop_valid_terminal")]
    OutcomeReviewStopValidTerminal,
    #[serde(rename = "outcome_review_next_contract_resolution.continue_current_contract")]
    OutcomeReviewContinueCurrentContract,
    #[serde(
        rename = "outcome_review_next_contract_resolution.scale_with_revised_contract_waiting_user"
    )]
    OutcomeReviewScaleWithRevisedContractWaitingUser,
    #[serde(
        rename = "outcome_review_next_contract_resolution.test_with_new_experiment_waiting_user"
    )]
    OutcomeReviewTestWithNewExperimentWaitingUser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphTransition {
    pub id: String,
    pub source_checkpoint_id: String,
    pub condition: RouteCondition,
    pub target: RouteGraphTransitionTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteGraphTransitionTargetKind {
    Checkpoint,
    Terminal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphTransitionTarget {
    pub kind: RouteGraphTransitionTargetKind,
    pub checkpoint_id: Option<String>,
    pub terminal_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectReplayPolicy {
    Forbidden,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservedArtifactsPolicy {
    AuditOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionEvidenceReusePolicy {
    Forbidden,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphRedirect {
    pub id: String,
    pub source_checkpoint_id: String,
    pub condition: RouteCondition,
    pub target_checkpoint_id: String,
    pub reset_region_checkpoint_ids: Vec<String>,
    pub max_traversals_per_cycle: u32,
    pub effect_replay_policy: EffectReplayPolicy,
    pub preserve_completed_artifacts: PreservedArtifactsPolicy,
    pub completion_evidence_reuse_policy: CompletionEvidenceReusePolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteGraphTerminalKind {
    ValidMissionTerminal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteGraphTerminalDisposition {
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteGraphTerminal {
    pub id: String,
    pub kind: RouteGraphTerminalKind,
    pub mission_disposition: Option<RouteGraphTerminalDisposition>,
}

pub fn route_graph_node_count(contract: &RouteGraphContract) -> usize {
    contract.graphs.iter().map(|graph| graph.nodes.len()).sum()
}

pub fn route_graph_normal_edge_count(contract: &RouteGraphContract) -> usize {
    contract
        .graphs
        .iter()
        .map(|graph| graph.transitions.len())
        .sum()
}

pub fn route_graph_redirect_edge_count(contract: &RouteGraphContract) -> usize {
    contract
        .graphs
        .iter()
        .map(|graph| graph.redirects.len())
        .sum()
}

pub fn route_graph_terminal_count(contract: &RouteGraphContract) -> usize {
    contract
        .graphs
        .iter()
        .map(|graph| graph.terminals.len())
        .sum()
}

pub fn validate_route_graph_closure(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    effect_readback: &EffectReadbackRouteContract,
    contract: &RouteGraphContract,
) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    validate_contract_header(contract, &mut violations);
    validate_graph_identity_closure(missions, contract, &mut violations);
    for graph in &contract.graphs {
        let Some(mission) = missions
            .missions
            .iter()
            .find(|mission| mission.id == graph.mission_id)
        else {
            continue;
        };
        validate_graph_shape(graph, mission, &mut violations);
        validate_completion_gates(graph, mission, effect_readback, &mut violations);
        validate_transition_closure(graph, mission, &mut violations);
        validate_redirect_closure(graph, mission, capabilities, &mut violations);
        validate_reachability(graph, &mut violations);
    }
    validate_frozen_counts(contract, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn validate_contract_header(contract: &RouteGraphContract, violations: &mut Vec<String>) {
    require(
        violations,
        contract.schema_version == "hartevo-mission-route-graph-contract/v2"
            && contract.contract_version == "desktop-2026-08-13-signal01-ct01-v1"
            && contract.evidence_level == "E1",
        "Mission route graphs must use the frozen v2 E1 contract",
    );
}

fn validate_graph_identity_closure(
    missions: &MissionCatalog,
    contract: &RouteGraphContract,
    violations: &mut Vec<String>,
) {
    let mission_versions = missions
        .missions
        .iter()
        .map(|mission| (mission.id.as_str(), mission.version))
        .collect::<BTreeMap<_, _>>();
    let graph_mission_ids = contract
        .graphs
        .iter()
        .map(|graph| graph.mission_id.as_str())
        .collect::<BTreeSet<_>>();
    let graph_ids = contract
        .graphs
        .iter()
        .map(|graph| graph.id.as_str())
        .collect::<BTreeSet<_>>();
    require(
        violations,
        graph_mission_ids.len() == contract.graphs.len()
            && graph_mission_ids == mission_versions.keys().copied().collect(),
        "route graph contract must contain exactly one graph for every Mission",
    );
    require(
        violations,
        contract
            .graphs
            .iter()
            .map(|graph| graph.mission_id.as_str())
            .eq(missions.missions.iter().map(|mission| mission.id.as_str())),
        "route graphs must preserve the frozen Mission order",
    );
    require(
        violations,
        graph_ids.len() == contract.graphs.len(),
        "route graph ids must be unique",
    );
    for graph in &contract.graphs {
        let expected_graph_id = format!("{}.route-graph/v2", mission_slug(&graph.mission_id));
        require(
            violations,
            graph.id == expected_graph_id
                && mission_versions
                    .get(graph.mission_id.as_str())
                    .is_some_and(|version| *version == graph.mission_version),
            format!(
                "route graph {} must bind the exact current Mission id and version",
                graph.id
            ),
        );
    }
}

fn validate_graph_shape(
    graph: &MissionRouteGraph,
    mission: &MissionManifest,
    violations: &mut Vec<String>,
) {
    let node_ids = graph
        .nodes
        .iter()
        .map(|node| node.checkpoint_id.as_str())
        .collect::<Vec<_>>();
    require(
        violations,
        node_ids
            == mission
                .checkpoint_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        format!(
            "{} route graph nodes must exactly preserve the Mission checkpoint order",
            mission.id
        ),
    );
    require(
        violations,
        mission
            .checkpoint_ids
            .first()
            .is_some_and(|checkpoint| graph.entry_checkpoint_id == checkpoint.as_str()),
        format!(
            "{} route graph must bind its unique first checkpoint entry",
            mission.id
        ),
    );

    let mut entry_nodes = 0_usize;
    for (index, node) in graph.nodes.iter().enumerate() {
        let expected_dependencies = index
            .checked_sub(1)
            .and_then(|previous| mission.checkpoint_ids.get(previous))
            .map(|checkpoint| vec![checkpoint.as_str()])
            .unwrap_or_default();
        let actual_dependencies = node
            .depends_on
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        require(
            violations,
            actual_dependencies == expected_dependencies,
            format!(
                "{} checkpoint {} must preserve the exact linear dependency baseline",
                mission.id, node.checkpoint_id
            ),
        );
        entry_nodes += usize::from(node.depends_on.is_empty());
        let optional_expected = mission.id == "VM-11" && node.checkpoint_id == "candidate_learning";
        require(
            violations,
            node.optional == optional_expected,
            format!(
                "{} checkpoint {} optionality must mean only the VM-11 Stop bypass",
                mission.id, node.checkpoint_id
            ),
        );
        validate_waiting_conditions(node, mission, violations);
    }
    require(
        violations,
        entry_nodes == 1,
        format!(
            "{} route graph must contain exactly one dependency-free entry",
            mission.id
        ),
    );
    validate_terminal_shape(graph, mission, violations);
}

fn validate_waiting_conditions(
    node: &RouteGraphNode,
    mission: &MissionManifest,
    violations: &mut Vec<String>,
) {
    let actual = node
        .waiting_user_conditions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let expected =
        if mission.id == "VM-11" && node.checkpoint_id == "next_contract_or_valid_terminal" {
            BTreeSet::from([
                RouteCondition::OutcomeReviewScaleWithRevisedContractWaitingUser,
                RouteCondition::OutcomeReviewTestWithNewExperimentWaitingUser,
            ])
        } else {
            BTreeSet::new()
        };
    require(
        violations,
        actual == expected && actual.len() == node.waiting_user_conditions.len(),
        format!(
            "{} checkpoint {} must expose the exact typed WaitingUser resolution set",
            mission.id, node.checkpoint_id
        ),
    );
}

fn validate_terminal_shape(
    graph: &MissionRouteGraph,
    mission: &MissionManifest,
    violations: &mut Vec<String>,
) {
    let expected_id = terminal_id(&mission.id);
    let expected_disposition =
        (mission.id == "VM-11").then_some(RouteGraphTerminalDisposition::Completed);
    require(
        violations,
        graph.terminals.as_slice().first().is_some_and(|terminal| {
            graph.terminals.len() == 1
                && terminal.id == expected_id
                && terminal.kind == RouteGraphTerminalKind::ValidMissionTerminal
                && terminal.mission_disposition == expected_disposition
        }),
        format!(
            "{} route graph must define exactly one stable valid terminal",
            mission.id
        ),
    );
}

fn validate_completion_gates(
    graph: &MissionRouteGraph,
    mission: &MissionManifest,
    effect_readback: &EffectReadbackRouteContract,
    violations: &mut Vec<String>,
) {
    for node in &graph.nodes {
        let is_vm08_effect_readback =
            mission.id == "VM-08" && node.checkpoint_id == "listing_write_readback";
        let valid = if is_vm08_effect_readback {
            node.completion_gate.kind
                == RouteNodeCompletionGateKind::EffectReadbackV2TerminalVerification
                && node.completion_gate.flow_id.as_deref()
                    == Some("vm08.listing-write-account-readback/v2")
        } else {
            node.completion_gate.kind == RouteNodeCompletionGateKind::CheckpointRoutePolicy
                && node.completion_gate.flow_id.is_none()
        };
        require(
            violations,
            valid,
            format!(
                "{} checkpoint {} must bind the exact completion gate",
                mission.id, node.checkpoint_id
            ),
        );
    }

    if mission.id != "VM-08" {
        return;
    }
    let flow = effect_readback.flows.iter().find(|flow| {
        flow.id == "vm08.listing-write-account-readback/v2"
            && flow.mission_id == mission.id
            && flow.mission_version == mission.version
            && flow.parent_checkpoint_id == "listing_write_readback"
    });
    require(
        violations,
        flow.is_some_and(|flow| {
            flow.parent_completion_policy == "effect_readback_v2"
                && flow.terminal_condition.success
                    == "verification_bound_to_receipt_and_canonical_target_diff"
                && !flow.terminal_condition.receipt_candidate_alone_completes
                && !flow.terminal_condition.corroboration_alone_completes
                && flow.terminal_condition.on_missing_or_mismatch == "inconclusive_fail_closed"
        }),
        "VM-08 graph completion must bind the entire effect-readback v2 terminal Verification condition",
    );
}

fn validate_transition_closure(
    graph: &MissionRouteGraph,
    mission: &MissionManifest,
    violations: &mut Vec<String>,
) {
    let terminal = terminal_id(&mission.id);
    let expected = expected_transition_signatures(mission, &terminal);
    let mut actual = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut source_conditions = BTreeSet::new();
    for transition in &graph.transitions {
        ids.insert(transition.id.as_str());
        validate_transition_id(transition, mission, violations);
        let target = transition_target_key(&transition.target, graph, violations);
        actual.insert((
            transition.source_checkpoint_id.clone(),
            transition.condition,
            target,
        ));
        require(
            violations,
            source_conditions.insert((
                transition.source_checkpoint_id.as_str(),
                transition.condition,
            )),
            format!(
                "{} source {} cannot reuse one branch condition",
                mission.id, transition.source_checkpoint_id
            ),
        );
    }
    require(
        violations,
        ids.len() == graph.transitions.len(),
        format!("{} transition ids must be unique", mission.id),
    );
    require(
        violations,
        actual == expected && actual.len() == graph.transitions.len(),
        format!(
            "{} normal transitions must exactly close every legal checkpoint resolution",
            mission.id
        ),
    );

    for node in &graph.nodes {
        for condition in &node.waiting_user_conditions {
            require(
                violations,
                source_conditions.insert((node.checkpoint_id.as_str(), *condition)),
                format!(
                    "{} checkpoint {} cannot match both WaitingUser and an outgoing transition",
                    mission.id, node.checkpoint_id
                ),
            );
        }
    }

    if mission.id == "VM-11" {
        let exact_resolution_set = source_conditions
            .iter()
            .filter(|(source, _)| *source == "next_contract_or_valid_terminal")
            .map(|(_, condition)| *condition)
            .collect::<BTreeSet<_>>();
        require(
            violations,
            exact_resolution_set
                == BTreeSet::from([
                    RouteCondition::OutcomeReviewStopValidTerminal,
                    RouteCondition::OutcomeReviewContinueCurrentContract,
                    RouteCondition::OutcomeReviewScaleWithRevisedContractWaitingUser,
                    RouteCondition::OutcomeReviewTestWithNewExperimentWaitingUser,
                ]),
            "VM-11 must exhaust the exact OutcomeReviewNextContractResolution action/intent closure",
        );
    }
}

fn expected_transition_signatures(
    mission: &MissionManifest,
    terminal: &str,
) -> BTreeSet<(String, RouteCondition, String)> {
    let mut expected = BTreeSet::new();
    for pair in mission.checkpoint_ids.windows(2) {
        let source = pair[0].clone();
        let target = pair[1].clone();
        let condition = match (mission.id.as_str(), source.as_str()) {
            ("VM-08", "listing_write_readback") => {
                RouteCondition::EffectReadbackV2TerminalVerificationSatisfied
            }
            ("VM-11", "next_contract_or_valid_terminal") => {
                RouteCondition::OutcomeReviewContinueCurrentContract
            }
            _ => RouteCondition::CheckpointCompleted,
        };
        expected.insert((source, condition, format!("checkpoint:{target}")));
    }
    let Some(last) = mission.checkpoint_ids.last().cloned() else {
        return expected;
    };
    let terminal_condition = if mission.id == "VM-07" {
        RouteCondition::Vm07ValidTerminal
    } else {
        RouteCondition::CheckpointCompleted
    };
    expected.insert((last, terminal_condition, format!("terminal:{terminal}")));
    if mission.id == "VM-11" {
        expected.insert((
            "next_contract_or_valid_terminal".into(),
            RouteCondition::OutcomeReviewStopValidTerminal,
            format!("terminal:{terminal}"),
        ));
    }
    expected
}

fn validate_transition_id(
    transition: &RouteGraphTransition,
    mission: &MissionManifest,
    violations: &mut Vec<String>,
) {
    let slug = mission_slug(&mission.id);
    let expected = match transition.target.kind {
        RouteGraphTransitionTargetKind::Checkpoint => transition
            .target
            .checkpoint_id
            .as_deref()
            .map(|target| format!("{slug}.{}.to.{target}/v2", transition.source_checkpoint_id)),
        RouteGraphTransitionTargetKind::Terminal
            if mission.id == "VM-11"
                && transition.source_checkpoint_id == "next_contract_or_valid_terminal" =>
        {
            Some("vm11.next_contract_or_valid_terminal.to.valid-terminal.stop/v2".into())
        }
        RouteGraphTransitionTargetKind::Terminal => Some(format!(
            "{slug}.{}.to.valid-terminal/v2",
            transition.source_checkpoint_id
        )),
    };
    require(
        violations,
        expected.as_deref() == Some(transition.id.as_str()),
        format!(
            "{} transition from {} must use its stable v2 id",
            mission.id, transition.source_checkpoint_id
        ),
    );
}

fn transition_target_key(
    target: &RouteGraphTransitionTarget,
    graph: &MissionRouteGraph,
    violations: &mut Vec<String>,
) -> String {
    match target.kind {
        RouteGraphTransitionTargetKind::Checkpoint => {
            let checkpoint = target.checkpoint_id.as_deref();
            require(
                violations,
                checkpoint.is_some_and(|checkpoint| {
                    graph
                        .nodes
                        .iter()
                        .any(|node| node.checkpoint_id == checkpoint)
                }) && target.terminal_id.is_none(),
                format!(
                    "{} transition checkpoint target must be exact",
                    graph.mission_id
                ),
            );
            format!("checkpoint:{}", checkpoint.unwrap_or("<missing>"))
        }
        RouteGraphTransitionTargetKind::Terminal => {
            let terminal = target.terminal_id.as_deref();
            require(
                violations,
                terminal.is_some_and(|terminal| {
                    graph
                        .terminals
                        .iter()
                        .any(|candidate| candidate.id == terminal)
                }) && target.checkpoint_id.is_none(),
                format!(
                    "{} transition terminal target must be exact",
                    graph.mission_id
                ),
            );
            format!("terminal:{}", terminal.unwrap_or("<missing>"))
        }
    }
}

fn validate_redirect_closure(
    graph: &MissionRouteGraph,
    mission: &MissionManifest,
    capabilities: &CapabilityCatalog,
    violations: &mut Vec<String>,
) {
    if mission.id != "VM-07" {
        require(
            violations,
            graph.redirects.is_empty(),
            format!("{} must not define a redirect", mission.id),
        );
        return;
    }
    let expected_region = [
        "go_no_go_need_more_evidence",
        "prioritized_experiments",
        "replan_or_terminal",
    ];
    let Some(redirect) = graph.redirects.first() else {
        violations.push("VM-07 must define its one bounded replan redirect".into());
        return;
    };
    require(
        violations,
        graph.redirects.len() == 1
            && redirect.id == "vm07.replan_or_terminal.redirect.go_no_go_need_more_evidence/v2"
            && redirect.source_checkpoint_id == "replan_or_terminal"
            && redirect.condition == RouteCondition::Vm07Replan
            && redirect.target_checkpoint_id == "go_no_go_need_more_evidence"
            && redirect
                .reset_region_checkpoint_ids
                .iter()
                .map(String::as_str)
                .eq(expected_region)
            && redirect.max_traversals_per_cycle == 1
            && redirect.effect_replay_policy == EffectReplayPolicy::Forbidden
            && redirect.preserve_completed_artifacts == PreservedArtifactsPolicy::AuditOnly
            && redirect.completion_evidence_reuse_policy
                == CompletionEvidenceReusePolicy::Forbidden,
        "VM-07 redirect must be the frozen bounded typed replan with audit-only artifacts and no completion reuse",
    );

    let capabilities_by_id = capabilities
        .capabilities
        .iter()
        .map(|capability| (capability.id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();
    for checkpoint_id in &redirect.reset_region_checkpoint_ids {
        let route = mission
            .checkpoint_routes
            .iter()
            .find(|route| route.checkpoint_id == checkpoint_id.as_str());
        let safe = route.is_some_and(|route| {
            route.executor != "effect_broker"
                && capabilities_by_id
                    .get(route.capability_id.as_str())
                    .is_some_and(|capability| {
                        !capability.provider_required && capability.effect_class != "external_write"
                    })
        });
        require(
            violations,
            safe,
            format!(
                "VM-07 redirect reset checkpoint {checkpoint_id} must exclude Effect Broker, external-write and provider-required work"
            ),
        );
    }

    let terminal_conditions = graph
        .transitions
        .iter()
        .filter(|transition| transition.source_checkpoint_id == redirect.source_checkpoint_id)
        .map(|transition| transition.condition)
        .collect::<BTreeSet<_>>();
    require(
        violations,
        terminal_conditions == BTreeSet::from([RouteCondition::Vm07ValidTerminal])
            && !terminal_conditions.contains(&redirect.condition),
        "VM-07 replan and valid-terminal resolutions must be mutually exclusive and exhaustive",
    );
}

fn validate_reachability(graph: &MissionRouteGraph, violations: &mut Vec<String>) {
    let mut queue = VecDeque::from([graph.entry_checkpoint_id.as_str()]);
    let mut reachable_nodes = BTreeSet::new();
    let mut reachable_terminals = BTreeSet::new();
    while let Some(source) = queue.pop_front() {
        if !reachable_nodes.insert(source) {
            continue;
        }
        for transition in graph
            .transitions
            .iter()
            .filter(|transition| transition.source_checkpoint_id == source)
        {
            match transition.target.kind {
                RouteGraphTransitionTargetKind::Checkpoint => {
                    if let Some(target) = transition.target.checkpoint_id.as_deref() {
                        queue.push_back(target);
                    }
                }
                RouteGraphTransitionTargetKind::Terminal => {
                    if let Some(target) = transition.target.terminal_id.as_deref() {
                        reachable_terminals.insert(target);
                    }
                }
            }
        }
    }
    require(
        violations,
        reachable_nodes.len() == graph.nodes.len()
            && reachable_terminals.len() == graph.terminals.len(),
        format!(
            "{} route graph must make every node and terminal reachable from its unique entry",
            graph.mission_id
        ),
    );

    let positions = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.checkpoint_id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    for transition in &graph.transitions {
        if let Some(target) = transition.target.checkpoint_id.as_deref() {
            require(
                violations,
                positions
                    .get(transition.source_checkpoint_id.as_str())
                    .zip(positions.get(target))
                    .is_some_and(|(source, target)| source < target),
                format!(
                    "{} normal transitions must be acyclic and forward-only",
                    graph.mission_id
                ),
            );
        }
    }
    for redirect in &graph.redirects {
        require(
            violations,
            positions
                .get(redirect.source_checkpoint_id.as_str())
                .zip(positions.get(redirect.target_checkpoint_id.as_str()))
                .is_some_and(|(source, target)| target <= source)
                && redirect.max_traversals_per_cycle > 0,
            format!(
                "{} backward edge must be an explicitly bounded redirect",
                graph.mission_id
            ),
        );
    }
}

fn validate_frozen_counts(contract: &RouteGraphContract, violations: &mut Vec<String>) {
    require(
        violations,
        contract.graphs.len() == EXPECTED_ROUTE_GRAPH_COUNT
            && route_graph_node_count(contract) == EXPECTED_ROUTE_GRAPH_NODE_COUNT
            && route_graph_normal_edge_count(contract) == EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT
            && route_graph_redirect_edge_count(contract)
                == EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT
            && route_graph_terminal_count(contract) == EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT,
        format!(
            "route graph contract must freeze {EXPECTED_ROUTE_GRAPH_COUNT} graphs, {EXPECTED_ROUTE_GRAPH_NODE_COUNT} nodes, {EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT} normal edges, {EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT} bounded redirect and {EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT} terminals"
        ),
    );
}

fn mission_slug(mission_id: &str) -> String {
    mission_id.to_ascii_lowercase().replace('-', "")
}

fn terminal_id(mission_id: &str) -> String {
    format!("{}.valid-terminal/v2", mission_slug(mission_id))
}

fn require(violations: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        violations.push(message.into());
    }
}
