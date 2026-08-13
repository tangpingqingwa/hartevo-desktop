use hartevo_catalog::{
    CapabilityCatalog, Catalog, EXPECTED_CAPABILITY_COUNT, EXPECTED_CHECKPOINT_ROUTE_COUNT,
    EXPECTED_MISSION_COUNT, MissionCatalog, validate_mission_contract_closure,
};

fn loaded_contracts() -> (MissionCatalog, CapabilityCatalog) {
    let catalog = Catalog::load().expect("valid production Catalog");
    (catalog.missions, catalog.capabilities)
}

fn violations(missions: &MissionCatalog, capabilities: &CapabilityCatalog) -> Vec<String> {
    validate_mission_contract_closure(missions, capabilities)
        .expect_err("adversarial mutation must fail closed")
}

#[test]
fn production_mission_contract_has_frozen_shape_and_bidirectional_closure() {
    let (missions, capabilities) = loaded_contracts();

    assert_eq!(missions.missions.len(), EXPECTED_MISSION_COUNT);
    assert_eq!(
        missions
            .missions
            .iter()
            .map(|mission| mission.checkpoint_routes.len())
            .sum::<usize>(),
        EXPECTED_CHECKPOINT_ROUTE_COUNT
    );
    assert_eq!(capabilities.capabilities.len(), EXPECTED_CAPABILITY_COUNT);
    assert!(validate_mission_contract_closure(&missions, &capabilities).is_ok());
}

#[test]
fn frozen_shape_rejects_missing_mission_route_or_capability() {
    let (mut missions, capabilities) = loaded_contracts();
    missions.missions.pop();
    assert!(
        violations(&missions, &capabilities)
            .iter()
            .any(|violation| violation.contains("exactly VM-00 through VM-11"))
    );

    let (mut missions, capabilities) = loaded_contracts();
    missions.missions[0].checkpoint_routes.pop();
    assert!(
        violations(&missions, &capabilities)
            .iter()
            .any(|violation| violation.contains("exactly 124 checkpoint routes"))
    );

    let (missions, mut capabilities) = loaded_contracts();
    capabilities.capabilities.pop();
    assert!(
        violations(&missions, &capabilities)
            .iter()
            .any(|violation| violation.contains("exactly 49 capabilities"))
    );
}

#[test]
fn mission_to_capability_mapping_must_have_the_reverse_edge() {
    let (missions, mut capabilities) = loaded_contracts();
    let attribution = capabilities
        .capabilities
        .iter_mut()
        .find(|capability| capability.id == "attribution.compute")
        .expect("attribution.compute");
    attribution
        .mission_ids
        .retain(|mission_id| mission_id != "VM-11");

    assert!(violations(&missions, &capabilities).iter().any(|violation| {
        violation
            == "Mission VM-11 maps to capability attribution.compute, but the Capability does not map back"
    }));
}

#[test]
fn capability_to_mission_mapping_must_have_the_reverse_edge() {
    let (mut missions, capabilities) = loaded_contracts();
    let vm11 = missions
        .missions
        .iter_mut()
        .find(|mission| mission.id == "VM-11")
        .expect("VM-11");
    vm11.capability_ids
        .retain(|capability_id| capability_id != "attribution.compute");

    assert!(violations(&missions, &capabilities).iter().any(|violation| {
        violation
            == "capability attribution.compute maps to VM-11, but the Mission does not map back"
    }));
}

#[test]
fn duplicate_route_and_reference_edges_fail_closed() {
    let (mut missions, capabilities) = loaded_contracts();
    missions.missions[0].checkpoint_routes[1].checkpoint_id = missions.missions[0]
        .checkpoint_routes[0]
        .checkpoint_id
        .clone();
    assert!(
        violations(&missions, &capabilities)
            .iter()
            .any(|violation| violation == "Mission/checkpoint route keys must be unique")
    );

    let (mut missions, capabilities) = loaded_contracts();
    let duplicate = missions.missions[0].capability_ids[0].clone();
    missions.missions[0].capability_ids.push(duplicate);
    assert!(
        violations(&missions, &capabilities)
            .iter()
            .any(|violation| violation == "Mission VM-00 capability references must be unique")
    );
}
