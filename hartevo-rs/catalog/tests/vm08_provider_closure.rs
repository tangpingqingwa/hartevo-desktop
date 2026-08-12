use hartevo_catalog::{
    CapabilityCatalog, Catalog, EXPECTED_CHECKPOINT_ROUTE_COUNT, EXPECTED_EXECUTABLE_STAGE_COUNT,
    EffectReadbackRouteContract, MissionCatalog, ProviderCatalog, expanded_execution_stage_count,
    validate_provider_route_closure,
};

fn loaded_contracts() -> (
    MissionCatalog,
    CapabilityCatalog,
    ProviderCatalog,
    EffectReadbackRouteContract,
) {
    let catalog = Catalog::load().expect("valid production Catalog");
    (
        catalog.missions,
        catalog.capabilities,
        catalog.providers,
        catalog.effect_readback_routes,
    )
}

fn violations(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    providers: &ProviderCatalog,
    contract: &EffectReadbackRouteContract,
) -> Vec<String> {
    validate_provider_route_closure(missions, capabilities, providers, contract)
        .expect_err("adversarial mutation must fail closed")
}

#[test]
fn vm08_effect_and_account_readback_are_machine_separated() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let mission = catalog.mission("VM-08").expect("VM-08");
    let route = mission
        .checkpoint_routes
        .iter()
        .find(|route| route.checkpoint_id == "listing_write_readback")
        .expect("VM-08 effect/readback parent route");
    let flow = catalog
        .effect_readback_routes
        .flows
        .first()
        .expect("VM-08 effect/readback flow");

    assert_eq!(mission.version, 4);
    assert_eq!(route.capability_id, "marketplace.write");
    assert_eq!(route.completion_policy, "effect_readback_v2");
    assert_eq!(
        flow.stages
            .iter()
            .map(|stage| (stage.id.as_str(), stage.provider_id.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("vm08.listing-write.effect/v1", "amazon-sp-api"),
            ("vm08.listing-write.account-readback/v1", "amazon-sp-api"),
        ]
    );
    assert_eq!(flow.stages[0].evidence_class, "receipt_candidate");
    assert_eq!(flow.stages[1].role, "independent_account_readback");
    assert!(flow.stages[1].independent_read_path_required);
    assert!(flow.stages[1].read_only_credential_required);
    assert!(flow.stages[1].execution_lease_forbidden);
    assert_eq!(
        flow.stages[1].correlation_source_stage_id.as_deref(),
        Some(flow.stages[0].id.as_str())
    );
    assert!(!flow.terminal_condition.receipt_candidate_alone_completes);
    assert!(!flow.terminal_condition.corroboration_alone_completes);
}

#[test]
fn snapshot_freezes_checkpoint_routes_separately_from_executable_stages() {
    let catalog = Catalog::load().expect("valid production Catalog");
    let snapshot = catalog.snapshot().expect("valid Catalog snapshot");

    assert_eq!(snapshot.schema_version, "hartevo-catalog-snapshot/v4");
    assert_eq!(
        snapshot.effect_readback_route_contract_version,
        "desktop-2026-08-12-ct00b-v1"
    );
    assert_eq!(
        snapshot.summary.checkpoint_route_count,
        EXPECTED_CHECKPOINT_ROUTE_COUNT
    );
    assert_eq!(
        snapshot.summary.executable_stage_count,
        EXPECTED_EXECUTABLE_STAGE_COUNT
    );
    assert_eq!(snapshot.summary.dataset_case_count, 420);
    assert_eq!(
        expanded_execution_stage_count(&catalog.missions, &catalog.effect_readback_routes),
        EXPECTED_EXECUTABLE_STAGE_COUNT
    );
}

#[test]
fn a_global_provider_cannot_hide_a_per_mission_route_gap() {
    let (mut missions, capabilities, providers, contract) = loaded_contracts();
    let vm08 = missions
        .missions
        .iter_mut()
        .find(|mission| mission.id == "VM-08")
        .expect("VM-08");
    vm08.provider_ids
        .retain(|provider_id| provider_id != "amazon-sp-api");

    assert!(
        violations(&missions, &capabilities, &providers, &contract)
            .iter()
            .any(|violation| {
                violation.contains(
                    "Mission VM-08 checkpoint listing_write_readback requires capability marketplace.write, but no provider in that Mission exposes it",
                )
            })
    );
    assert!(
        providers
            .providers
            .iter()
            .any(|provider| provider.id == "amazon-sp-api")
    );
}

#[test]
fn sorftime_cannot_replace_the_amazon_account_readback_stage() {
    let (missions, capabilities, providers, mut contract) = loaded_contracts();
    contract.flows[0].stages[1].provider_id = "sorftime".into();

    assert!(
        violations(&missions, &capabilities, &providers, &contract)
            .iter()
            .any(|violation| violation.contains("frozen independent Amazon account readback"))
    );
}

#[test]
fn receipt_correlation_and_independent_read_path_are_mandatory() {
    let (missions, capabilities, providers, mut contract) = loaded_contracts();
    contract.flows[0].stages[1].correlation_source_stage_id = None;
    contract.flows[0].stages[1].independent_read_path_required = false;

    assert!(
        violations(&missions, &capabilities, &providers, &contract)
            .iter()
            .any(|violation| violation.contains("bound to stage 1"))
    );
}

#[test]
fn receipt_candidate_and_corroboration_cannot_complete_or_confirm() {
    let (missions, capabilities, providers, mut contract) = loaded_contracts();
    contract.flows[0]
        .terminal_condition
        .receipt_candidate_alone_completes = true;
    contract.flows[0].corroboration[0].may_confirm_write = true;

    let violations = violations(&missions, &capabilities, &providers, &contract);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("must never complete"))
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("must remain non-completing and non-confirming"))
    );
}

#[test]
fn claim_authority_is_exact_deny_all_and_schema_closed() {
    let (missions, capabilities, providers, mut contract) = loaded_contracts();
    contract.claim_authority.provider.execution = true;
    assert!(
        violations(&missions, &capabilities, &providers, &contract)
            .iter()
            .any(|violation| violation.contains("must not claim adapter"))
    );

    let (_, _, _, contract) = loaded_contracts();
    let mut unknown = serde_json::to_value(&contract).expect("serialize route contract");
    unknown["claimAuthority"]["provider"]["connected"] = serde_json::Value::Bool(false);
    let unknown_error = serde_json::from_value::<EffectReadbackRouteContract>(unknown)
        .expect_err("unknown nested claim field must fail closed");
    assert!(
        unknown_error
            .to_string()
            .contains("unknown field `connected`")
    );

    let mut missing = serde_json::to_value(&contract).expect("serialize route contract");
    missing["claimAuthority"]["product"]
        .as_object_mut()
        .expect("product claim object")
        .remove("businessVerification");
    let missing_error = serde_json::from_value::<EffectReadbackRouteContract>(missing)
        .expect_err("missing nested claim field must fail closed");
    assert!(
        missing_error
            .to_string()
            .contains("missing field `businessVerification`")
    );
}

#[test]
fn free_json_or_missing_substage_cannot_escape_catalog_validation() {
    let (missions, capabilities, providers, mut contract) = loaded_contracts();
    contract.flows[0].id = "unbound.free-json/v2".into();
    contract.flows[0].stages.pop();

    let violations = violations(&missions, &capabilities, &providers, &contract);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("exactly bind VM-08 v4"))
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("exactly two stages"))
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("exactly 124 executable stages"))
    );
}

#[test]
fn capability_authority_no_longer_assigns_publication_verify_to_vm08() {
    let (_, capabilities, _, _) = loaded_contracts();
    let publication_verify = capabilities
        .capabilities
        .iter()
        .find(|capability| capability.id == "publication.verify")
        .expect("publication.verify");
    let marketplace_write = capabilities
        .capabilities
        .iter()
        .find(|capability| capability.id == "marketplace.write")
        .expect("marketplace.write");

    assert!(!publication_verify.mission_ids.contains(&"VM-08".into()));
    assert!(marketplace_write.mission_ids.contains(&"VM-08".into()));
}
