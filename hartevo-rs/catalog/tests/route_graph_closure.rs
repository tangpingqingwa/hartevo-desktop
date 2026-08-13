use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_catalog::{
    Catalog, CompletionEvidenceReusePolicy, EXPECTED_ROUTE_GRAPH_COUNT,
    EXPECTED_ROUTE_GRAPH_NODE_COUNT, EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT,
    EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT, EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT,
    EffectReplayPolicy, PreservedArtifactsPolicy, ReleaseEvidence, RouteCondition,
    RouteGraphContract, RouteGraphTerminalDisposition, RouteGraphTransitionTargetKind,
    RouteNodeCompletionGateKind, route_graph_node_count, route_graph_normal_edge_count,
    route_graph_redirect_edge_count, route_graph_terminal_count, validate_route_graph_closure,
};

fn route_graph_violations(contract: &RouteGraphContract) -> Vec<String> {
    let catalog = Catalog::load().expect("valid production Catalog");
    validate_route_graph_closure(
        &catalog.missions,
        &catalog.capabilities,
        &catalog.effect_readback_routes,
        contract,
    )
    .expect_err("adversarial route graph mutation must fail closed")
}

fn has_violation(violations: &[String], needle: &str) -> bool {
    violations
        .iter()
        .any(|violation| violation.contains(needle))
}

#[test]
fn production_route_graph_and_snapshot_v4_have_the_frozen_shape() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let contract = &catalog.route_graphs;
    let snapshot = catalog.snapshot().expect("valid Catalog Snapshot v4");

    assert_eq!(
        contract.schema_version,
        "hartevo-mission-route-graph-contract/v2"
    );
    assert_eq!(
        contract.contract_version,
        "desktop-2026-08-13-signal01-ct01-v1"
    );
    assert_eq!(contract.evidence_level, "E1");
    assert!(!contract.runtime_authority.branch_execution());
    assert!(!contract.runtime_authority.redirect_execution());
    assert!(!contract.runtime_authority.optional_skip_execution());
    assert!(!contract.runtime_authority.terminal_execution());
    assert_eq!(contract.graphs.len(), EXPECTED_ROUTE_GRAPH_COUNT);
    assert_eq!(
        route_graph_node_count(contract),
        EXPECTED_ROUTE_GRAPH_NODE_COUNT
    );
    assert_eq!(
        route_graph_normal_edge_count(contract),
        EXPECTED_ROUTE_GRAPH_NORMAL_EDGE_COUNT
    );
    assert_eq!(
        route_graph_redirect_edge_count(contract),
        EXPECTED_ROUTE_GRAPH_REDIRECT_EDGE_COUNT
    );
    assert_eq!(
        route_graph_terminal_count(contract),
        EXPECTED_ROUTE_GRAPH_TERMINAL_COUNT
    );
    let serialized_contract = serde_json::to_value(contract).expect("route graph JSON");
    assert_eq!(
        serialized_contract.get("runtimeAuthority"),
        Some(&serde_json::json!({
            "branchExecution": false,
            "redirectExecution": false,
            "optionalSkipExecution": false,
            "terminalExecution": false,
        }))
    );
    let round_trip = serde_json::from_value::<RouteGraphContract>(serialized_contract)
        .expect("deny-only runtime authority round-trip");
    assert_eq!(&round_trip, contract);

    assert_eq!(snapshot.schema_version, "hartevo-catalog-snapshot/v4");
    assert_eq!(
        snapshot.route_graph_contract_version,
        "desktop-2026-08-13-signal01-ct01-v1"
    );
    assert_eq!(snapshot.summary.route_graph_count, 12);
    assert_eq!(snapshot.summary.route_graph_node_count, 124);
    assert_eq!(snapshot.summary.route_graph_normal_edge_count, 125);
    assert_eq!(snapshot.summary.route_graph_redirect_edge_count, 1);
    assert_eq!(snapshot.summary.route_graph_terminal_count, 12);
    let serialized = serde_json::to_value(&snapshot).expect("Snapshot v4 JSON");
    assert_eq!(
        serialized
            .get("routeGraphContractVersion")
            .and_then(serde_json::Value::as_str),
        Some("desktop-2026-08-13-signal01-ct01-v1")
    );
}

#[test]
fn vm11_exact_typed_resolution_closure_makes_only_candidate_optional() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let graph = catalog
        .route_graphs
        .graphs
        .iter()
        .find(|graph| graph.mission_id == "VM-11")
        .expect("VM-11 graph");
    let candidate = graph
        .nodes
        .iter()
        .find(|node| node.checkpoint_id == "candidate_learning")
        .expect("candidate_learning");
    let resolution = graph
        .nodes
        .iter()
        .find(|node| node.checkpoint_id == "next_contract_or_valid_terminal")
        .expect("next contract resolution");
    assert!(candidate.optional);
    assert!(
        graph
            .nodes
            .iter()
            .filter(|node| node.optional)
            .all(|node| node.checkpoint_id == "candidate_learning")
    );
    assert_eq!(
        resolution
            .waiting_user_conditions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            RouteCondition::OutcomeReviewScaleWithRevisedContractWaitingUser,
            RouteCondition::OutcomeReviewTestWithNewExperimentWaitingUser,
        ])
    );
    let outgoing = graph
        .transitions
        .iter()
        .filter(|transition| transition.source_checkpoint_id == "next_contract_or_valid_terminal")
        .collect::<Vec<_>>();
    assert_eq!(outgoing.len(), 2);
    assert!(outgoing.iter().any(|transition| {
        transition.condition == RouteCondition::OutcomeReviewStopValidTerminal
            && transition.target.kind == RouteGraphTransitionTargetKind::Terminal
            && transition.target.terminal_id.as_deref() == Some("vm11.valid-terminal/v2")
    }));
    assert!(outgoing.iter().any(|transition| {
        transition.condition == RouteCondition::OutcomeReviewContinueCurrentContract
            && transition.target.kind == RouteGraphTransitionTargetKind::Checkpoint
            && transition.target.checkpoint_id.as_deref() == Some("candidate_learning")
    }));
    assert!(!outgoing.iter().any(|transition| {
        matches!(
            transition.condition,
            RouteCondition::OutcomeReviewScaleWithRevisedContractWaitingUser
                | RouteCondition::OutcomeReviewTestWithNewExperimentWaitingUser
        )
    }));
    assert!(graph.transitions.iter().any(|transition| {
        transition.source_checkpoint_id == "candidate_learning"
            && transition.condition == RouteCondition::CheckpointCompleted
            && transition.target.kind == RouteGraphTransitionTargetKind::Terminal
            && transition.target.terminal_id.as_deref() == Some("vm11.valid-terminal/v2")
    }));
    assert_eq!(
        graph.terminals[0].mission_disposition,
        Some(RouteGraphTerminalDisposition::Completed)
    );
}

#[test]
fn vm07_redirect_is_bounded_safe_and_cannot_reuse_completion_evidence() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let graph = catalog
        .route_graphs
        .graphs
        .iter()
        .find(|graph| graph.mission_id == "VM-07")
        .expect("VM-07 graph");
    let redirect = graph.redirects.first().expect("VM-07 redirect");
    assert_eq!(graph.redirects.len(), 1);
    assert_eq!(redirect.condition, RouteCondition::Vm07Replan);
    assert_eq!(redirect.source_checkpoint_id, "replan_or_terminal");
    assert_eq!(redirect.target_checkpoint_id, "go_no_go_need_more_evidence");
    assert_eq!(
        redirect.reset_region_checkpoint_ids,
        [
            "go_no_go_need_more_evidence",
            "prioritized_experiments",
            "replan_or_terminal",
        ]
    );
    assert_eq!(redirect.max_traversals_per_cycle, 1);
    assert_eq!(redirect.effect_replay_policy, EffectReplayPolicy::Forbidden);
    assert_eq!(
        redirect.preserve_completed_artifacts,
        PreservedArtifactsPolicy::AuditOnly
    );
    assert_eq!(
        redirect.completion_evidence_reuse_policy,
        CompletionEvidenceReusePolicy::Forbidden
    );
    assert!(graph.transitions.iter().any(|transition| {
        transition.source_checkpoint_id == "replan_or_terminal"
            && transition.condition == RouteCondition::Vm07ValidTerminal
            && transition.target.kind == RouteGraphTransitionTargetKind::Terminal
    }));
}

#[test]
fn vm08_checkpoint_progress_requires_the_entire_effect_readback_terminal() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let graph = catalog
        .route_graphs
        .graphs
        .iter()
        .find(|graph| graph.mission_id == "VM-08")
        .expect("VM-08 graph");
    let node = graph
        .nodes
        .iter()
        .find(|node| node.checkpoint_id == "listing_write_readback")
        .expect("effect/readback node");
    assert_eq!(
        node.completion_gate.kind,
        RouteNodeCompletionGateKind::EffectReadbackV2TerminalVerification
    );
    assert_eq!(
        node.completion_gate.flow_id.as_deref(),
        Some("vm08.listing-write-account-readback/v2")
    );
    let outgoing = graph
        .transitions
        .iter()
        .filter(|transition| transition.source_checkpoint_id == "listing_write_readback")
        .collect::<Vec<_>>();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(
        outgoing[0].condition,
        RouteCondition::EffectReadbackV2TerminalVerificationSatisfied
    );
    assert_eq!(
        outgoing[0].target.checkpoint_id.as_deref(),
        Some("conversion_return_rank_profit_review")
    );
    let flow = catalog
        .effect_readback_routes
        .flows
        .iter()
        .find(|flow| flow.id == "vm08.listing-write-account-readback/v2")
        .expect("effect/readback companion");
    assert_eq!(
        flow.terminal_condition.success,
        "verification_bound_to_receipt_and_canonical_target_diff"
    );
    assert!(!flow.terminal_condition.receipt_candidate_alone_completes);
    assert!(!flow.terminal_condition.corroboration_alone_completes);
    assert_eq!(
        flow.terminal_condition.on_missing_or_mismatch,
        "inconclusive_fail_closed"
    );
}

#[test]
fn branch_optionality_and_reachability_mutations_fail_closed() {
    let catalog = Catalog::load().expect("valid production Catalog");

    let mut optional = catalog.route_graphs.clone();
    optional
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-11")
        .expect("VM-11")
        .nodes
        .iter_mut()
        .find(|node| node.checkpoint_id == "candidate_learning")
        .expect("candidate")
        .optional = false;
    assert!(has_violation(
        &route_graph_violations(&optional),
        "optionality must mean only the VM-11 Stop bypass"
    ));

    let mut conflicting = catalog.route_graphs.clone();
    conflicting
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-11")
        .expect("VM-11")
        .transitions
        .iter_mut()
        .find(|transition| transition.condition == RouteCondition::OutcomeReviewStopValidTerminal)
        .expect("Stop branch")
        .condition = RouteCondition::OutcomeReviewContinueCurrentContract;
    let violations = route_graph_violations(&conflicting);
    assert!(
        has_violation(&violations, "cannot reuse one branch condition")
            || has_violation(
                &violations,
                "exactly close every legal checkpoint resolution"
            )
    );

    let mut unreachable = catalog.route_graphs.clone();
    let vm00 = unreachable
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-00")
        .expect("VM-00");
    vm00.transitions[0].target.checkpoint_id = Some("encryption_workspace_ready".into());
    assert!(has_violation(
        &route_graph_violations(&unreachable),
        "reachable from its unique entry"
    ));

    let mut extra_nodes = catalog.route_graphs.clone();
    let vm00 = extra_nodes
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-00")
        .expect("VM-00");
    let mut first_extra = vm00.nodes.last().expect("VM-00 last node").clone();
    first_extra.checkpoint_id = "uncontracted_extra_one".into();
    first_extra.depends_on = vec!["mission_handoff".into()];
    let mut second_extra = first_extra.clone();
    second_extra.checkpoint_id = "uncontracted_extra_two".into();
    second_extra.depends_on = vec!["uncontracted_extra_one".into()];
    vm00.nodes.extend([first_extra, second_extra]);
    assert!(has_violation(
        &route_graph_violations(&extra_nodes),
        "must exactly preserve the Mission checkpoint order"
    ));
}

#[test]
fn illegal_redirect_and_effect_readback_mutations_fail_closed() {
    let catalog = Catalog::load().expect("valid production Catalog");

    let mut redirect = catalog.route_graphs.clone();
    redirect
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-07")
        .expect("VM-07")
        .redirects[0]
        .reset_region_checkpoint_ids
        .push("scoped_collection".into());
    let violations = route_graph_violations(&redirect);
    assert!(has_violation(&violations, "provider-required work"));

    let mut unbounded = catalog.route_graphs.clone();
    unbounded
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-07")
        .expect("VM-07")
        .redirects[0]
        .max_traversals_per_cycle = 0;
    assert!(has_violation(
        &route_graph_violations(&unbounded),
        "frozen bounded typed replan"
    ));

    let mut branch_conflict = catalog.route_graphs.clone();
    branch_conflict
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-07")
        .expect("VM-07")
        .transitions
        .iter_mut()
        .find(|transition| transition.source_checkpoint_id == "replan_or_terminal")
        .expect("VM-07 terminal branch")
        .condition = RouteCondition::Vm07Replan;
    let violations = route_graph_violations(&branch_conflict);
    assert!(
        has_violation(
            &violations,
            "exactly close every legal checkpoint resolution"
        ) || has_violation(&violations, "mutually exclusive and exhaustive")
    );

    let mut readback = catalog.route_graphs.clone();
    readback
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-08")
        .expect("VM-08")
        .nodes
        .iter_mut()
        .find(|node| node.checkpoint_id == "listing_write_readback")
        .expect("effect/readback")
        .completion_gate
        .kind = RouteNodeCompletionGateKind::CheckpointRoutePolicy;
    assert!(has_violation(
        &route_graph_violations(&readback),
        "must bind the exact completion gate"
    ));

    let mut early_completion = catalog.route_graphs.clone();
    early_completion
        .graphs
        .iter_mut()
        .find(|graph| graph.mission_id == "VM-08")
        .expect("VM-08")
        .transitions
        .iter_mut()
        .find(|transition| transition.source_checkpoint_id == "listing_write_readback")
        .expect("VM-08 effect/readback transition")
        .condition = RouteCondition::CheckpointCompleted;
    assert!(has_violation(
        &route_graph_violations(&early_completion),
        "exactly close every legal checkpoint resolution"
    ));

    let mut weakened_terminal = catalog.effect_readback_routes.clone();
    weakened_terminal.flows[0]
        .terminal_condition
        .on_missing_or_mismatch = "receipt_candidate_may_complete".into();
    let violations = validate_route_graph_closure(
        &catalog.missions,
        &catalog.capabilities,
        &weakened_terminal,
        &catalog.route_graphs,
    )
    .expect_err("weakened VM-08 terminal condition must fail closed");
    assert!(has_violation(
        &violations,
        "entire effect-readback v2 terminal Verification condition"
    ));
}

#[test]
fn route_graph_json_schema_and_branch_condition_enum_are_fail_closed() {
    let contract = Catalog::load()
        .expect("valid production Catalog")
        .route_graphs;

    let mut unknown = serde_json::to_value(&contract).expect("route graph JSON");
    unknown["graphs"][0]["nodes"][0]["completionGate"]["unversionedEscape"] =
        serde_json::Value::Bool(false);
    let error = serde_json::from_value::<RouteGraphContract>(unknown)
        .expect_err("unknown nested route graph field must fail closed");
    assert!(
        error
            .to_string()
            .contains("unknown field `unversionedEscape`")
    );

    for invalid_authority in [
        serde_json::Value::Bool(true),
        serde_json::Value::Null,
        serde_json::json!(1),
        serde_json::Value::String("false".into()),
    ] {
        let mut claimed_authority = serde_json::to_value(&contract).expect("route graph JSON");
        claimed_authority["runtimeAuthority"]["branchExecution"] = invalid_authority;
        serde_json::from_value::<RouteGraphContract>(claimed_authority)
            .expect_err("non-false runtime authority must fail closed while parsing");
    }

    let mut missing = serde_json::to_value(&contract).expect("route graph JSON");
    missing["runtimeAuthority"]
        .as_object_mut()
        .expect("runtime authority")
        .remove("terminalExecution");
    let error = serde_json::from_value::<RouteGraphContract>(missing)
        .expect_err("missing runtime authority field must fail closed");
    assert!(
        error
            .to_string()
            .contains("missing field `terminalExecution`")
    );

    let mut unknown_authority = serde_json::to_value(&contract).expect("route graph JSON");
    unknown_authority["runtimeAuthority"]["unversionedAuthority"] = serde_json::Value::Bool(false);
    let error = serde_json::from_value::<RouteGraphContract>(unknown_authority)
        .expect_err("unknown runtime authority field must fail closed");
    assert!(
        error
            .to_string()
            .contains("unknown field `unversionedAuthority`")
    );

    let mut unknown_condition = serde_json::to_value(&contract).expect("route graph JSON");
    unknown_condition["graphs"][0]["transitions"][0]["condition"] =
        serde_json::Value::String("free_string_branch".into());
    let error = serde_json::from_value::<RouteGraphContract>(unknown_condition)
        .expect_err("free-string branch condition must fail closed");
    assert!(
        error
            .to_string()
            .contains("unknown variant `free_string_branch`")
    );
}

#[test]
fn release_evidence_v23_consumes_snapshot_v4_without_schema_drift() {
    let snapshot = Catalog::load()
        .expect("valid production Catalog")
        .snapshot()
        .expect("Catalog Snapshot v4");
    let observed_at = Utc
        .with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
        .single()
        .expect("valid time");
    let evidence = ReleaseEvidence::wave_zero_baseline(
        &snapshot,
        "238f51ee3b1f4d996bdc89022b0e2bc943ec7dfd",
        observed_at,
    );
    assert_eq!(evidence.schema_version, "2.3.0");
    assert_eq!(evidence.catalog_digest, snapshot.digest);
    assert_eq!(
        (
            evidence.application_route_count,
            evidence.implemented_application_handler_count,
            evidence.not_implemented_application_route_count,
        ),
        (
            snapshot.summary.application_route_count,
            snapshot.summary.implemented_application_handler_count,
            snapshot.summary.not_implemented_application_route_count,
        )
    );
    assert!(evidence.validate_fail_closed().is_ok());
    let serialized = serde_json::to_value(&evidence).expect("release evidence v2.3 JSON");
    assert_eq!(
        serialized
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str),
        Some("2.3.0")
    );
}
