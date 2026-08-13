use std::collections::{BTreeMap, BTreeSet};

use crate::{CapabilityCatalog, EXPECTED_MISSION_COUNT, MissionCatalog};

pub const EXPECTED_CHECKPOINT_ROUTE_COUNT: usize = 124;
pub const EXPECTED_CAPABILITY_COUNT: usize = 49;

/// Validates the frozen Mission/route/Capability shape and both directions of
/// Mission-to-Capability authority. Keeping this separate from Provider and
/// executor validation makes a one-sided mapping impossible to hide behind an
/// otherwise valid route or globally available Provider.
pub fn validate_mission_contract_closure(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    validate_frozen_shape(missions, capabilities, &mut violations);
    validate_mission_to_capability_edges(missions, capabilities, &mut violations);
    validate_capability_to_mission_edges(missions, capabilities, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn validate_frozen_shape(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    violations: &mut Vec<String>,
) {
    let expected_mission_ids = (0..EXPECTED_MISSION_COUNT)
        .map(|index| format!("VM-{index:02}"))
        .collect::<BTreeSet<_>>();
    let mission_ids = missions
        .missions
        .iter()
        .map(|mission| mission.id.as_str())
        .collect::<BTreeSet<_>>();
    if missions.missions.len() != EXPECTED_MISSION_COUNT
        || mission_ids.len() != EXPECTED_MISSION_COUNT
        || !expected_mission_ids
            .iter()
            .all(|mission_id| mission_ids.contains(mission_id.as_str()))
    {
        violations.push("mission contract must contain exactly VM-00 through VM-11".into());
    }

    let route_count = missions
        .missions
        .iter()
        .map(|mission| mission.checkpoint_routes.len())
        .sum::<usize>();
    if route_count != EXPECTED_CHECKPOINT_ROUTE_COUNT {
        violations.push(format!(
            "mission contract must contain exactly {EXPECTED_CHECKPOINT_ROUTE_COUNT} checkpoint routes, found {route_count}"
        ));
    }
    let route_keys = missions
        .missions
        .iter()
        .flat_map(|mission| {
            mission
                .checkpoint_routes
                .iter()
                .map(|route| (mission.id.as_str(), route.checkpoint_id.as_str()))
        })
        .collect::<BTreeSet<_>>();
    if route_keys.len() != route_count {
        violations.push("Mission/checkpoint route keys must be unique".into());
    }

    if capabilities.capabilities.len() != EXPECTED_CAPABILITY_COUNT {
        violations.push(format!(
            "capability contract must contain exactly {EXPECTED_CAPABILITY_COUNT} capabilities, found {}",
            capabilities.capabilities.len()
        ));
    }
    let capability_ids = capabilities
        .capabilities
        .iter()
        .map(|capability| capability.id.as_str())
        .collect::<BTreeSet<_>>();
    if capability_ids.len() != capabilities.capabilities.len() {
        violations.push("capability contract ids must be unique".into());
    }
}

fn validate_mission_to_capability_edges(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    violations: &mut Vec<String>,
) {
    let capabilities_by_id = capabilities
        .capabilities
        .iter()
        .map(|capability| (capability.id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();

    for mission in &missions.missions {
        let mission_capability_ids = mission
            .capability_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if mission_capability_ids.len() != mission.capability_ids.len() {
            violations.push(format!(
                "Mission {} capability references must be unique",
                mission.id
            ));
        }
        for capability_id in mission_capability_ids {
            match capabilities_by_id.get(capability_id) {
                Some(capability) if !capability.mission_ids.contains(&mission.id) => {
                    violations.push(format!(
                        "Mission {} maps to capability {capability_id}, but the Capability does not map back",
                        mission.id
                    ));
                }
                None => violations.push(format!(
                    "Mission {} references unknown capability {capability_id}",
                    mission.id
                )),
                _ => {}
            }
        }
    }
}

fn validate_capability_to_mission_edges(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    violations: &mut Vec<String>,
) {
    let missions_by_id = missions
        .missions
        .iter()
        .map(|mission| (mission.id.as_str(), mission))
        .collect::<BTreeMap<_, _>>();
    for capability in &capabilities.capabilities {
        let capability_mission_ids = capability
            .mission_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if capability_mission_ids.len() != capability.mission_ids.len() {
            violations.push(format!(
                "capability {} Mission references must be unique",
                capability.id
            ));
        }
        for mission_id in capability_mission_ids {
            match missions_by_id.get(mission_id) {
                Some(mission) if !mission.capability_ids.contains(&capability.id) => {
                    violations.push(format!(
                        "capability {} maps to {mission_id}, but the Mission does not map back",
                        capability.id
                    ));
                }
                None => violations.push(format!(
                    "capability {} references unknown Mission {mission_id}",
                    capability.id
                )),
                _ => {}
            }
        }
    }
}
