use chrono::{TimeZone, Utc};
use hartevo_catalog::{
    Catalog, ReleaseEvidence, ReleaseStage, RouteRuntimeAuthorityContract,
    RouteTerminalExecutionAuthority, StageApplicationHandlerStatus, StageApplicationRouteAuthority,
    StageApplicationRouteScope, StageApplicationRouteScopeContract, StageGenericRuntimeAuthority,
    StageMissionAnyOfKind, materialize_stage_application_route_scopes,
    validate_materialized_stage_application_route_scopes,
    validate_stage_application_route_scope_closure,
};

fn contract_violations(
    catalog: &Catalog,
    contract: &StageApplicationRouteScopeContract,
) -> Vec<String> {
    validate_stage_application_route_scope_closure(
        &catalog.missions,
        &catalog.route_graphs,
        &catalog.application_handlers,
        &catalog.route_runtime_authority,
        contract,
    )
    .expect_err("adversarial stage scope contract mutation must fail closed")
}

fn authority_violations(
    catalog: &Catalog,
    authority: &RouteRuntimeAuthorityContract,
) -> Vec<String> {
    validate_stage_application_route_scope_closure(
        &catalog.missions,
        &catalog.route_graphs,
        &catalog.application_handlers,
        authority,
        &catalog.stage_application_route_scope_contract,
    )
    .expect_err("adversarial terminal authority mutation must fail closed")
}

fn has_violation(violations: &[String], needle: &str) -> bool {
    violations
        .iter()
        .any(|violation| violation.contains(needle))
}

fn scope(
    scopes: &[StageApplicationRouteScope],
    stage: ReleaseStage,
) -> &StageApplicationRouteScope {
    scopes
        .iter()
        .find(|scope| scope.stage == stage)
        .expect("stage Application route scope")
}

#[test]
fn production_scopes_bind_stage_missions_routes_handlers_authority_and_terminals() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let scopes = catalog
        .stage_application_route_scopes()
        .expect("valid stage Application route scopes");
    assert_contract_binding(&catalog, &scopes);
    assert_foundation_and_beta_scope(&scopes);
    let ga = scope(&scopes, ReleaseStage::GeneralAvailability);
    assert_ga_handler_scope(ga);
    assert_terminal_and_runtime_boundaries(&catalog, ga);
}

fn assert_contract_binding(catalog: &Catalog, scopes: &[StageApplicationRouteScope]) {
    let contract = &catalog.stage_application_route_scope_contract;
    assert_eq!(
        contract.schema_version,
        "hartevo-stage-application-route-scope-contract/v1"
    );
    assert_eq!(contract.contract_version, "desktop-2026-08-13-ct04-v1");
    assert_eq!(contract.evidence_level, "E1");
    assert_eq!(contract.release_evidence_schema_version, "2.3.0");
    assert_eq!(
        contract.mission_catalog_version,
        catalog.missions.catalog_version
    );
    assert_eq!(
        contract.route_graph_contract_version,
        catalog.route_graphs.contract_version
    );
    assert_eq!(
        contract.application_handler_registry_version,
        catalog.application_handlers.registry_version
    );
    assert_eq!(
        contract.route_runtime_authority_contract_version,
        catalog.route_runtime_authority.contract_version
    );
    assert_eq!(
        contract.generic_runtime_authority,
        StageGenericRuntimeAuthority::Denied
    );
    assert_eq!(scopes.len(), 5);
}

fn assert_foundation_and_beta_scope(scopes: &[StageApplicationRouteScope]) {
    let foundation = scope(scopes, ReleaseStage::EngineeringFoundation);
    assert_eq!(
        foundation
            .mission_scopes
            .iter()
            .map(|mission| mission.mission_id.as_str())
            .collect::<Vec<_>>(),
        [
            "VM-00", "VM-01", "VM-03", "VM-04", "VM-05", "VM-07", "VM-11"
        ]
    );
    assert_eq!(foundation.summary.eligible_mission_count, 7);
    assert_eq!(foundation.summary.application_route_count, 29);
    assert_eq!(foundation.summary.implemented_handler_count, 17);
    assert_eq!(foundation.summary.not_implemented_handler_count, 12);
    assert_eq!(foundation.summary.terminal_count, 7);
    assert_eq!(foundation.summary.terminal_transition_count, 8);
    assert_eq!(foundation.summary.application_terminal_transition_count, 7);
    assert_eq!(
        foundation.summary.non_application_terminal_transition_count,
        1
    );
    assert_eq!(
        foundation
            .summary
            .implemented_terminal_transition_authority_count,
        1
    );
    let writing = foundation
        .selection
        .required_any_of_mission_sets
        .first()
        .expect("writing Mission selection");
    assert_eq!(writing.kind, StageMissionAnyOfKind::WritingMission);
    assert_eq!(writing.minimum_selected, 1);

    let beta = scope(scopes, ReleaseStage::ControlledBeta);
    assert_eq!(beta.summary.eligible_mission_count, 6);
    assert_eq!(beta.summary.application_route_count, 22);
    assert_eq!(beta.summary.implemented_handler_count, 3);
    assert_eq!(beta.summary.not_implemented_handler_count, 19);
    assert_eq!(beta.summary.terminal_count, 6);
    assert_eq!(beta.summary.terminal_transition_count, 6);
    assert_eq!(beta.summary.application_terminal_transition_count, 5);
    assert_eq!(beta.summary.non_application_terminal_transition_count, 1);
}

fn assert_ga_handler_scope(ga: &StageApplicationRouteScope) {
    assert_eq!(ga.summary.eligible_mission_count, 12);
    assert_eq!(ga.summary.application_route_count, 52);
    assert_eq!(ga.summary.implemented_handler_count, 17);
    assert_eq!(ga.summary.not_implemented_handler_count, 35);
    assert_eq!(ga.summary.terminal_count, 12);
    assert_eq!(ga.summary.terminal_transition_count, 13);
    assert_eq!(ga.summary.application_terminal_transition_count, 12);
    assert_eq!(ga.summary.non_application_terminal_transition_count, 1);

    let routes = ga
        .mission_scopes
        .iter()
        .flat_map(|mission| &mission.application_routes)
        .collect::<Vec<_>>();
    assert_eq!(routes.len(), 52);
    assert!(
        routes
            .iter()
            .all(|route| route.route.executor == "application")
    );
    assert_eq!(
        routes
            .iter()
            .filter(|route| route.handler.status == StageApplicationHandlerStatus::Implemented)
            .count(),
        17
    );
    assert!(routes.iter().all(|route| {
        match (
            route.handler.status,
            &route.handler.manifest,
            &route.authority,
        ) {
            (
                StageApplicationHandlerStatus::Implemented,
                Some(handler),
                StageApplicationRouteAuthority::RegisteredApplicationHandler { handler_id, .. },
            ) => {
                handler.handler_id == *handler_id
                    && matches!(handler.mission_id.as_str(), "VM-00" | "VM-04" | "VM-11")
            }
            (
                StageApplicationHandlerStatus::NotImplemented,
                None,
                StageApplicationRouteAuthority::DeniedNotImplemented,
            ) => true,
            _ => false,
        }
    }));

    let serialized = serde_json::to_value(ga).expect("GA stage scope JSON");
    let wire_routes = serialized["missionScopes"]
        .as_array()
        .expect("Mission scopes")
        .iter()
        .flat_map(|mission| {
            mission["applicationRoutes"]
                .as_array()
                .expect("Application routes")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        wire_routes
            .iter()
            .filter(|route| route
                .pointer("/handler/status")
                .and_then(serde_json::Value::as_str)
                == Some("NOT_IMPLEMENTED"))
            .count(),
        35
    );
    assert!(
        wire_routes
            .iter()
            .filter(|route| {
                route
                    .pointer("/handler/status")
                    .and_then(serde_json::Value::as_str)
                    == Some("NOT_IMPLEMENTED")
            })
            .all(|route| {
                route
                    .pointer("/authority/kind")
                    .and_then(serde_json::Value::as_str)
                    == Some("denied_not_implemented")
            })
    );
}

fn assert_terminal_and_runtime_boundaries(catalog: &Catalog, ga: &StageApplicationRouteScope) {
    let vm11 = ga
        .mission_scopes
        .iter()
        .find(|mission| mission.mission_id == "VM-11")
        .expect("VM-11 scope");
    assert_eq!(vm11.terminals.len(), 1);
    assert_eq!(vm11.terminals[0].id, "vm11.valid-terminal/v2");
    let stop = vm11
        .application_routes
        .iter()
        .find(|route| route.route.checkpoint_id == "next_contract_or_valid_terminal")
        .expect("VM-11 Stop route");
    assert_eq!(stop.terminal_transition_authorities.len(), 1);
    assert!(matches!(
        stop.terminal_transition_authorities[0].authority,
        RouteTerminalExecutionAuthority::ApplicationHandler(_)
    ));
    let candidate = vm11
        .application_routes
        .iter()
        .find(|route| route.route.checkpoint_id == "candidate_learning")
        .expect("VM-11 candidate route");
    assert_eq!(
        candidate.handler.status,
        StageApplicationHandlerStatus::NotImplemented
    );
    assert!(matches!(
        candidate.authority,
        StageApplicationRouteAuthority::DeniedNotImplemented
    ));
    assert!(matches!(
        candidate.terminal_transition_authorities[0].authority,
        RouteTerminalExecutionAuthority::Denied(_)
    ));

    let vm03 = ga
        .mission_scopes
        .iter()
        .find(|mission| mission.mission_id == "VM-03")
        .expect("VM-03 scope");
    assert_eq!(
        vm03.non_application_terminal_transition_authorities.len(),
        1
    );
    let runtime_terminal = &vm03.non_application_terminal_transition_authorities[0];
    assert_eq!(
        runtime_terminal.source_checkpoint_id,
        "analytics_form_lead_ready"
    );
    assert!(matches!(
        runtime_terminal.authority,
        RouteTerminalExecutionAuthority::Denied(_)
    ));

    assert!(!catalog.route_graphs.runtime_authority.branch_execution());
    assert!(!catalog.route_graphs.runtime_authority.redirect_execution());
    assert!(
        !catalog
            .route_graphs
            .runtime_authority
            .optional_skip_execution()
    );
    assert!(!catalog.route_graphs.runtime_authority.terminal_execution());
}

#[test]
fn contract_and_source_drift_cannot_expand_a_stage_scope() {
    let catalog = Catalog::load().expect("valid production Catalog");

    let mut inflated_evidence = catalog.stage_application_route_scope_contract.clone();
    inflated_evidence.evidence_level = "E2".into();
    assert!(has_violation(
        &contract_violations(&catalog, &inflated_evidence),
        "CT-04 E1 contract"
    ));

    let mut missing_stage = catalog.stage_application_route_scope_contract.clone();
    missing_stage.stages.pop();
    assert!(has_violation(
        &contract_violations(&catalog, &missing_stage),
        "exact five Release-stage Mission selections"
    ));

    let mut reordered = catalog.stage_application_route_scope_contract.clone();
    reordered.stages.swap(0, 1);
    assert!(has_violation(
        &contract_violations(&catalog, &reordered),
        "exact five Release-stage Mission selections"
    ));

    let mut weakened_writing = catalog.stage_application_route_scope_contract.clone();
    weakened_writing.stages[0].required_any_of_mission_sets[0]
        .mission_ids
        .pop();
    assert!(has_violation(
        &contract_violations(&catalog, &weakened_writing),
        "exact five Release-stage Mission selections"
    ));

    let mut impossible_selection = catalog.stage_application_route_scope_contract.clone();
    impossible_selection.stages[0].required_any_of_mission_sets[0].minimum_selected = 0;
    assert!(has_violation(
        &contract_violations(&catalog, &impossible_selection),
        "unique, non-overlapping and satisfiable"
    ));

    let mut missing_handler_registry = catalog.application_handlers.clone();
    missing_handler_registry.handlers.pop();
    let violations = validate_stage_application_route_scope_closure(
        &catalog.missions,
        &catalog.route_graphs,
        &missing_handler_registry,
        &catalog.route_runtime_authority,
        &catalog.stage_application_route_scope_contract,
    )
    .expect_err("missing registered handler must remain NOT_IMPLEMENTED and fail frozen scope");
    assert!(has_violation(&violations, "handler/terminal counts"));

    let mut missing_graph_node = catalog.route_graphs.clone();
    missing_graph_node.graphs[0].nodes.remove(0);
    let violations = validate_stage_application_route_scope_closure(
        &catalog.missions,
        &missing_graph_node,
        &catalog.application_handlers,
        &catalog.route_runtime_authority,
        &catalog.stage_application_route_scope_contract,
    )
    .expect_err("missing route graph node must fail closed");
    assert!(has_violation(&violations, "has no exact graph node"));

    let mut false_terminal_authority = catalog.route_runtime_authority.clone();
    let implemented = false_terminal_authority
        .terminal_transitions
        .iter()
        .find(|binding| {
            matches!(
                binding.authority,
                RouteTerminalExecutionAuthority::ApplicationHandler(_)
            )
        })
        .expect("implemented terminal authority")
        .authority
        .clone();
    false_terminal_authority.terminal_transitions[0].authority = implemented;
    assert!(has_violation(
        &authority_violations(&catalog, &false_terminal_authority),
        "must remain denied"
    ));
}

#[test]
fn materialized_scope_and_json_schema_fail_closed_without_promoting_release() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let scopes = materialize_stage_application_route_scopes(
        &catalog.missions,
        &catalog.route_graphs,
        &catalog.application_handlers,
        &catalog.route_runtime_authority,
        &catalog.stage_application_route_scope_contract,
    )
    .expect("materialized scopes");

    let mut guessed = scopes.clone();
    let ga = guessed
        .iter_mut()
        .find(|scope| scope.stage == ReleaseStage::GeneralAvailability)
        .expect("GA scope");
    let denied = ga
        .mission_scopes
        .iter_mut()
        .flat_map(|mission| &mut mission.application_routes)
        .find(|route| route.handler.status == StageApplicationHandlerStatus::NotImplemented)
        .expect("NOT_IMPLEMENTED route");
    denied.handler.status = StageApplicationHandlerStatus::Implemented;
    assert!(
        validate_materialized_stage_application_route_scopes(
            &catalog.missions,
            &catalog.route_graphs,
            &catalog.application_handlers,
            &catalog.route_runtime_authority,
            &catalog.stage_application_route_scope_contract,
            &guessed,
        )
        .is_err()
    );

    let serialized = serde_json::to_value(&catalog.stage_application_route_scope_contract)
        .expect("stage scope JSON");
    let round_trip =
        serde_json::from_value::<StageApplicationRouteScopeContract>(serialized.clone())
            .expect("typed stage scope round-trip");
    assert_eq!(round_trip, catalog.stage_application_route_scope_contract);

    let mut unknown = serialized.clone();
    unknown["runtimeGuess"] = serde_json::Value::Bool(false);
    serde_json::from_value::<StageApplicationRouteScopeContract>(unknown)
        .expect_err("unknown contract field must fail closed");

    let mut missing_stage = serialized.clone();
    missing_stage["stages"][0]
        .as_object_mut()
        .expect("stage object")
        .remove("requiredMissionIds");
    serde_json::from_value::<StageApplicationRouteScopeContract>(missing_stage)
        .expect_err("missing stage field must fail closed");

    for invalid in [
        serde_json::Value::Null,
        serde_json::Value::Bool(false),
        serde_json::Value::String("allowed".into()),
        serde_json::Value::from(1),
    ] {
        let mut runtime_guess = serialized.clone();
        runtime_guess["genericRuntimeAuthority"] = invalid;
        serde_json::from_value::<StageApplicationRouteScopeContract>(runtime_guess)
            .expect_err("generic runtime authority cannot be guessed");
    }

    let snapshot = catalog.snapshot().expect("Catalog Snapshot v4");
    let release = ReleaseEvidence::wave_zero_baseline(
        &snapshot,
        "a".repeat(40),
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time"),
    );
    assert!(!release.passed);
    assert!(!release.traceability_complete);
    assert!(
        release
            .missing_required_evidence
            .iter()
            .any(|missing| missing == "stage_application_route_scope")
    );
}
