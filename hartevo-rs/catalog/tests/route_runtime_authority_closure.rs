use hartevo_catalog::{
    ApplicationHandlerRouteTerminalExecutionAuthority,
    ApplicationHandlerRouteTerminalExecutionAuthorityKind, Catalog,
    DefaultTerminalExecutionAuthority, DeniedRouteTerminalExecutionAuthority,
    DeniedRouteTerminalExecutionAuthorityKind, EXPECTED_DENIED_TERMINAL_TRANSITION_AUTHORITY_COUNT,
    EXPECTED_IMPLEMENTED_TERMINAL_TRANSITION_AUTHORITY_COUNT,
    EXPECTED_TERMINAL_TRANSITION_AUTHORITY_COUNT, RouteGraphTerminalDisposition,
    RouteRuntimeAuthorityContract, RouteTerminalAuthorityExecutor, RouteTerminalCompletionPolicy,
    RouteTerminalExecutionAuthority, denied_terminal_transition_authority_count,
    implemented_terminal_transition_authority_count, terminal_transition_authority_count,
    validate_route_runtime_authority_closure,
};

const VM04_CHANNEL_REBALANCE_TRANSITION_ID: &str = "vm04.channel_rebalance.to.valid-terminal/v2";
const VM11_STOP_TRANSITION_ID: &str =
    "vm11.next_contract_or_valid_terminal.to.valid-terminal.stop/v2";

fn authority_violations(contract: &RouteRuntimeAuthorityContract) -> Vec<String> {
    let catalog = Catalog::load().expect("valid production Catalog");
    validate_route_runtime_authority_closure(
        &catalog.missions,
        &catalog.route_graphs,
        &catalog.application_handlers,
        contract,
    )
    .expect_err("adversarial runtime authority mutation must fail closed")
}

fn has_violation(violations: &[String], needle: &str) -> bool {
    violations
        .iter()
        .any(|violation| violation.contains(needle))
}

fn vm11_application_authority() -> RouteTerminalExecutionAuthority {
    RouteTerminalExecutionAuthority::ApplicationHandler(
        ApplicationHandlerRouteTerminalExecutionAuthority {
            kind: ApplicationHandlerRouteTerminalExecutionAuthorityKind::ApplicationHandler,
            executor: RouteTerminalAuthorityExecutor::Application,
            handler_id: "vm11.next-contract-or-valid-terminal/v1".into(),
            implementation_crate: "hartevo-application".into(),
            completion_policy: RouteTerminalCompletionPolicy::DeterministicEvidence,
            mission_disposition: RouteGraphTerminalDisposition::Completed,
            skipped_checkpoint_ids: vec!["candidate_learning".into()],
        },
    )
}

fn vm04_application_authority() -> RouteTerminalExecutionAuthority {
    RouteTerminalExecutionAuthority::ApplicationHandler(
        ApplicationHandlerRouteTerminalExecutionAuthority {
            kind: ApplicationHandlerRouteTerminalExecutionAuthorityKind::ApplicationHandler,
            executor: RouteTerminalAuthorityExecutor::Application,
            handler_id: "vm04.channel-rebalance/v1".into(),
            implementation_crate: "hartevo-application".into(),
            completion_policy: RouteTerminalCompletionPolicy::DeterministicEvidence,
            mission_disposition: RouteGraphTerminalDisposition::Completed,
            skipped_checkpoint_ids: Vec::new(),
        },
    )
}

fn denied_authority() -> RouteTerminalExecutionAuthority {
    RouteTerminalExecutionAuthority::Denied(DeniedRouteTerminalExecutionAuthority {
        kind: DeniedRouteTerminalExecutionAuthorityKind::Denied,
    })
}

#[test]
fn production_contract_grants_only_the_exact_vm04_and_vm11_terminals() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let contract = &catalog.route_runtime_authority;

    assert_eq!(
        contract.schema_version,
        "hartevo-mission-route-runtime-authority-contract/v1"
    );
    assert_eq!(contract.contract_version, "desktop-2026-09-05-ct03-v2");
    assert_eq!(contract.evidence_level, "E1");
    assert_eq!(
        contract.default_terminal_execution_authority,
        DefaultTerminalExecutionAuthority::Denied
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
        terminal_transition_authority_count(contract),
        EXPECTED_TERMINAL_TRANSITION_AUTHORITY_COUNT
    );
    assert_eq!(
        implemented_terminal_transition_authority_count(contract),
        EXPECTED_IMPLEMENTED_TERMINAL_TRANSITION_AUTHORITY_COUNT
    );
    assert_eq!(
        denied_terminal_transition_authority_count(contract),
        EXPECTED_DENIED_TERMINAL_TRANSITION_AUTHORITY_COUNT
    );

    let implemented = contract
        .terminal_transitions
        .iter()
        .filter(|binding| {
            matches!(
                binding.authority,
                RouteTerminalExecutionAuthority::ApplicationHandler(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(implemented.len(), 2);
    assert_eq!(
        implemented[0].transition_id,
        VM04_CHANNEL_REBALANCE_TRANSITION_ID
    );
    assert_eq!(implemented[0].mission_id, "VM-04");
    assert_eq!(implemented[0].mission_version, 3);
    assert_eq!(implemented[0].source_checkpoint_id, "channel_rebalance");
    assert_eq!(implemented[0].terminal_id, "vm04.valid-terminal/v2");
    assert_eq!(implemented[0].authority, vm04_application_authority());

    assert_eq!(implemented[1].transition_id, VM11_STOP_TRANSITION_ID);
    assert_eq!(implemented[1].mission_id, "VM-11");
    assert_eq!(implemented[1].mission_version, 3);
    assert_eq!(
        implemented[1].source_checkpoint_id,
        "next_contract_or_valid_terminal"
    );
    assert_eq!(implemented[1].terminal_id, "vm11.valid-terminal/v2");
    assert_eq!(implemented[1].authority, vm11_application_authority());

    let candidate_terminal = contract
        .terminal_transitions
        .iter()
        .find(|binding| binding.transition_id == "vm11.candidate_learning.to.valid-terminal/v2")
        .expect("VM-11 candidate terminal binding");
    assert_eq!(candidate_terminal.authority, denied_authority());

    assert!(!catalog.route_graphs.runtime_authority.branch_execution());
    assert!(!catalog.route_graphs.runtime_authority.redirect_execution());
    assert!(
        !catalog
            .route_graphs
            .runtime_authority
            .optional_skip_execution()
    );
    assert!(!catalog.route_graphs.runtime_authority.terminal_execution());

    let snapshot = catalog.snapshot().expect("valid Catalog Snapshot v4");
    assert_eq!(snapshot.schema_version, "hartevo-catalog-snapshot/v4");
    assert_eq!(
        snapshot.route_graph_contract_version,
        "desktop-2026-09-05-ct02-v2"
    );
}

#[test]
fn terminal_authority_coverage_and_implementation_claims_fail_closed() {
    let catalog = Catalog::load().expect("valid production Catalog");

    let mut missing = catalog.route_runtime_authority.clone();
    missing.terminal_transitions.remove(0);
    assert!(has_violation(
        &authority_violations(&missing),
        "cover every terminal transition exactly once"
    ));

    let mut reordered = catalog.route_runtime_authority.clone();
    reordered.terminal_transitions.swap(0, 1);
    assert!(has_violation(
        &authority_violations(&reordered),
        "frozen graph order"
    ));

    let mut false_claim = catalog.route_runtime_authority.clone();
    false_claim.terminal_transitions[0].authority = vm11_application_authority();
    assert!(has_violation(
        &authority_violations(&false_claim),
        "is not implemented and must remain denied"
    ));

    let mut removed_claim = catalog.route_runtime_authority.clone();
    removed_claim
        .terminal_transitions
        .iter_mut()
        .find(|binding| binding.transition_id == VM04_CHANNEL_REBALANCE_TRANSITION_ID)
        .expect("VM-04 channel-rebalance authority")
        .authority = denied_authority();
    assert!(has_violation(
        &authority_violations(&removed_claim),
        "VM-04 channel rebalance must bind its exact implemented Application terminal authority"
    ));

    let mut removed_claim = catalog.route_runtime_authority.clone();
    removed_claim
        .terminal_transitions
        .iter_mut()
        .find(|binding| binding.transition_id == VM11_STOP_TRANSITION_ID)
        .expect("VM-11 Stop authority")
        .authority = denied_authority();
    assert!(has_violation(
        &authority_violations(&removed_claim),
        "VM-11 Stop must bind its exact implemented Application terminal authority"
    ));

    let mut wrong_handler = catalog.route_runtime_authority.clone();
    let binding = wrong_handler
        .terminal_transitions
        .iter_mut()
        .find(|binding| binding.transition_id == VM11_STOP_TRANSITION_ID)
        .expect("VM-11 Stop authority");
    let RouteTerminalExecutionAuthority::ApplicationHandler(authority) = &mut binding.authority
    else {
        panic!("VM-11 Stop Application authority");
    };
    authority.handler_id = "vm11.unregistered-terminal/v1".into();
    assert!(has_violation(
        &authority_violations(&wrong_handler),
        "exact Mission route and registered production handler"
    ));

    let mut wrong_capability_registry = catalog.application_handlers.clone();
    wrong_capability_registry
        .handlers
        .iter_mut()
        .find(|handler| handler.handler_id == "vm11.next-contract-or-valid-terminal/v1")
        .expect("VM-11 Stop handler")
        .capability_id = "candidate.propose".into();
    let violations = validate_route_runtime_authority_closure(
        &catalog.missions,
        &catalog.route_graphs,
        &wrong_capability_registry,
        &catalog.route_runtime_authority,
    )
    .expect_err("handler Capability drift must fail closed");
    assert!(has_violation(
        &violations,
        "exact Mission route and registered production handler"
    ));

    let mut missing_oracle_registry = catalog.application_handlers.clone();
    missing_oracle_registry
        .handlers
        .iter_mut()
        .find(|handler| handler.handler_id == "vm11.next-contract-or-valid-terminal/v1")
        .expect("VM-11 Stop handler")
        .oracle_ids
        .pop();
    let violations = validate_route_runtime_authority_closure(
        &catalog.missions,
        &catalog.route_graphs,
        &missing_oracle_registry,
        &catalog.route_runtime_authority,
    )
    .expect_err("handler Oracle drift must fail closed");
    assert!(has_violation(
        &violations,
        "exact Mission route and registered production handler"
    ));

    let mut inflated_evidence = catalog.route_runtime_authority.clone();
    inflated_evidence.evidence_level = "E2".into();
    assert!(has_violation(
        &authority_violations(&inflated_evidence),
        "CT-03 E1 contract"
    ));
}

#[test]
fn terminal_authority_json_is_an_exact_deny_unknown_typed_union() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let serialized =
        serde_json::to_value(&catalog.route_runtime_authority).expect("runtime authority JSON");
    let round_trip = serde_json::from_value::<RouteRuntimeAuthorityContract>(serialized.clone())
        .expect("typed runtime authority round-trip");
    assert_eq!(round_trip, catalog.route_runtime_authority);

    let mut unknown_contract = serialized.clone();
    unknown_contract["unversionedAuthority"] = serde_json::Value::Bool(false);
    serde_json::from_value::<RouteRuntimeAuthorityContract>(unknown_contract)
        .expect_err("unknown contract field must fail closed");

    let mut missing_default = serialized.clone();
    missing_default
        .as_object_mut()
        .expect("runtime authority object")
        .remove("defaultTerminalExecutionAuthority");
    serde_json::from_value::<RouteRuntimeAuthorityContract>(missing_default)
        .expect_err("missing default authority must fail closed");

    let mut unknown_denied_field = serialized.clone();
    unknown_denied_field["terminalTransitions"][0]["authority"]["reason"] =
        serde_json::Value::String("not implemented".into());
    serde_json::from_value::<RouteRuntimeAuthorityContract>(unknown_denied_field)
        .expect_err("unknown denied-authority field must fail closed");

    let mut unknown_kind = serialized.clone();
    unknown_kind["terminalTransitions"][0]["authority"]["kind"] =
        serde_json::Value::String("runtime".into());
    serde_json::from_value::<RouteRuntimeAuthorityContract>(unknown_kind)
        .expect_err("unknown authority kind must fail closed");

    let stop_index = serialized["terminalTransitions"]
        .as_array()
        .expect("terminal transitions")
        .iter()
        .position(|binding| binding["transitionId"].as_str() == Some(VM11_STOP_TRANSITION_ID))
        .expect("VM-11 Stop index");
    let mut missing_skip_binding = serialized.clone();
    missing_skip_binding["terminalTransitions"][stop_index]["authority"]
        .as_object_mut()
        .expect("Application authority")
        .remove("skippedCheckpointIds");
    serde_json::from_value::<RouteRuntimeAuthorityContract>(missing_skip_binding)
        .expect_err("missing Application authority field must fail closed");

    for invalid in [
        serde_json::Value::Null,
        serde_json::Value::Bool(false),
        serde_json::Value::from(1),
        serde_json::Value::String("denied".into()),
    ] {
        let mut malformed = serialized.clone();
        malformed["terminalTransitions"][0]["authority"] = invalid;
        serde_json::from_value::<RouteRuntimeAuthorityContract>(malformed)
            .expect_err("non-object terminal authority must fail closed");
    }
}
