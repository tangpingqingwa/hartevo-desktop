use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{CapabilityCatalog, MissionCatalog, MissionManifest, ProviderCatalog};

pub(crate) const EFFECT_READBACK_ROUTE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/missions/effect-readback-routes.v2.json");

pub const EXPECTED_EXECUTABLE_STAGE_COUNT: usize = 124;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectReadbackRouteContract {
    pub schema_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub claim_authority: RouteClaimAuthority,
    pub flows: Vec<EffectReadbackFlow>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteClaimAuthority {
    pub adapter_registered: bool,
    pub provider: ProviderClaimAuthority,
    pub product: ProductClaimAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderClaimAuthority {
    pub execution: bool,
    pub receipt: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProductClaimAuthority {
    pub business_verification: bool,
    pub e4: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectReadbackFlow {
    pub id: String,
    pub mission_id: String,
    pub mission_version: u32,
    pub parent_checkpoint_id: String,
    pub parent_completion_policy: String,
    pub stages: Vec<EffectReadbackStage>,
    pub corroboration: Vec<CorroborationBinding>,
    pub terminal_condition: EffectReadbackTerminalCondition,
    pub fail_closed_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectReadbackStage {
    pub id: String,
    pub ordinal: u32,
    pub role: String,
    pub capability_id: String,
    pub executor: String,
    pub effect_class: String,
    pub provider_id: String,
    pub operation: String,
    pub evidence_class: String,
    pub terminal_contribution: String,
    pub binding_fields: Vec<String>,
    pub correlation_source_stage_id: Option<String>,
    pub independent_read_path_required: bool,
    pub read_only_credential_required: bool,
    pub execution_lease_forbidden: bool,
    pub comparison: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorroborationBinding {
    pub provider_id: String,
    pub capability_id: String,
    pub authority: String,
    pub required_for_completion: bool,
    pub may_confirm_write: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectReadbackTerminalCondition {
    pub success: String,
    pub receipt_candidate_alone_completes: bool,
    pub corroboration_alone_completes: bool,
    pub on_missing_or_mismatch: String,
}

pub fn expanded_execution_stage_count(
    missions: &MissionCatalog,
    contract: &EffectReadbackRouteContract,
) -> usize {
    let checkpoint_route_count = missions
        .missions
        .iter()
        .map(|mission| mission.checkpoint_routes.len())
        .sum::<usize>();
    checkpoint_route_count
        + contract
            .flows
            .iter()
            .map(|flow| flow.stages.len().saturating_sub(1))
            .sum::<usize>()
}

pub fn validate_provider_route_closure(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    providers: &ProviderCatalog,
    contract: &EffectReadbackRouteContract,
) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    validate_contract_header(contract, &mut violations);
    validate_provider_required_routes(missions, capabilities, providers, &mut violations);
    validate_effect_readback_flows(missions, capabilities, providers, contract, &mut violations);
    validate_special_policy_bindings(missions, contract, &mut violations);
    require(
        &mut violations,
        expanded_execution_stage_count(missions, contract) == EXPECTED_EXECUTABLE_STAGE_COUNT,
        format!(
            "Mission execution graph must contain exactly {EXPECTED_EXECUTABLE_STAGE_COUNT} executable stages"
        ),
    );

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn validate_contract_header(contract: &EffectReadbackRouteContract, violations: &mut Vec<String>) {
    require(
        violations,
        contract.schema_version == "hartevo-effect-readback-route-contract/v2"
            && contract.contract_version == "desktop-2026-08-12-ct00b-v1"
            && contract.evidence_level == "E1",
        "effect/readback routes must use the frozen v2 E1 contract",
    );
    let authority = &contract.claim_authority;
    require(
        violations,
        !authority.adapter_registered
            && !authority.provider.execution
            && !authority.provider.receipt
            && !authority.product.business_verification
            && !authority.product.e4,
        "effect/readback route metadata must not claim adapter, Provider, Receipt, Verification or E4 authority",
    );
    require(
        violations,
        contract.flows.len() == 1,
        "effect/readback route contract must contain exactly the VM-08 flow",
    );
}

fn validate_provider_required_routes(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    providers: &ProviderCatalog,
    violations: &mut Vec<String>,
) {
    let capabilities_by_id = capabilities
        .capabilities
        .iter()
        .map(|capability| (capability.id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();
    let providers_by_id = providers
        .providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect::<BTreeMap<_, _>>();

    for mission in &missions.missions {
        let mission_provider_ids = mission
            .provider_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        require(
            violations,
            mission_provider_ids.len() == mission.provider_ids.len(),
            format!("{} provider references must be unique", mission.id),
        );
        for route in &mission.checkpoint_routes {
            let Some(capability) = capabilities_by_id.get(route.capability_id.as_str()) else {
                continue;
            };
            if !capability.provider_required {
                continue;
            }
            let covered = mission_provider_ids.iter().any(|provider_id| {
                providers_by_id
                    .get(provider_id)
                    .is_some_and(|provider| provider.capability_ids.contains(&route.capability_id))
            });
            require(
                violations,
                covered,
                format!(
                    "Mission {} checkpoint {} requires capability {}, but no provider in that Mission exposes it",
                    mission.id, route.checkpoint_id, route.capability_id
                ),
            );
        }
    }
}

fn validate_effect_readback_flows(
    missions: &MissionCatalog,
    capabilities: &CapabilityCatalog,
    providers: &ProviderCatalog,
    contract: &EffectReadbackRouteContract,
    violations: &mut Vec<String>,
) {
    let flow_ids = contract
        .flows
        .iter()
        .map(|flow| flow.id.as_str())
        .collect::<BTreeSet<_>>();
    require(
        violations,
        flow_ids.len() == contract.flows.len(),
        "effect/readback flow ids must be unique",
    );

    for flow in &contract.flows {
        validate_flow_identity(flow, missions, violations);
        let Some(mission) = missions
            .missions
            .iter()
            .find(|mission| mission.id == flow.mission_id)
        else {
            continue;
        };
        validate_flow_stages(flow, mission, capabilities, providers, violations);
        validate_corroboration(flow, providers, violations);
        validate_terminal_condition(flow, violations);
    }
}

fn validate_flow_identity(
    flow: &EffectReadbackFlow,
    missions: &MissionCatalog,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        flow.id == "vm08.listing-write-account-readback/v2"
            && flow.mission_id == "VM-08"
            && flow.mission_version == 4
            && flow.parent_checkpoint_id == "listing_write_readback"
            && flow.parent_completion_policy == "effect_readback_v2",
        "effect/readback flow must exactly bind VM-08 v4 listing_write_readback",
    );
    let Some(mission) = missions
        .missions
        .iter()
        .find(|mission| mission.id == flow.mission_id)
    else {
        violations.push(format!(
            "effect/readback flow {} references unknown Mission {}",
            flow.id, flow.mission_id
        ));
        return;
    };
    require(
        violations,
        mission.version == flow.mission_version,
        format!(
            "effect/readback flow {} binds Mission version {}, found {}",
            flow.id, flow.mission_version, mission.version
        ),
    );
    let parent = mission
        .checkpoint_routes
        .iter()
        .find(|route| route.checkpoint_id == flow.parent_checkpoint_id);
    require(
        violations,
        parent.is_some_and(|route| {
            route.capability_id == "marketplace.write"
                && route.executor == "effect_broker"
                && route.completion_policy == flow.parent_completion_policy
        }),
        format!(
            "effect/readback flow {} must exactly bind its parent checkpoint route",
            flow.id
        ),
    );
}

fn validate_flow_stages(
    flow: &EffectReadbackFlow,
    mission: &MissionManifest,
    capabilities: &CapabilityCatalog,
    providers: &ProviderCatalog,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        flow.stages.len() == 2,
        format!(
            "effect/readback flow {} must contain exactly two stages",
            flow.id
        ),
    );
    let stage_ids = flow
        .stages
        .iter()
        .map(|stage| stage.id.as_str())
        .collect::<BTreeSet<_>>();
    require(
        violations,
        stage_ids.len() == flow.stages.len(),
        format!("effect/readback flow {} stage ids must be unique", flow.id),
    );
    for stage in &flow.stages {
        validate_stage_provider_coverage(stage, mission, capabilities, providers, violations);
    }
    let [effect, readback] = flow.stages.as_slice() else {
        return;
    };
    validate_effect_stage(effect, violations);
    validate_readback_stage(readback, effect, violations);
}

fn validate_stage_provider_coverage(
    stage: &EffectReadbackStage,
    mission: &MissionManifest,
    capabilities: &CapabilityCatalog,
    providers: &ProviderCatalog,
    violations: &mut Vec<String>,
) {
    let capability = capabilities
        .capabilities
        .iter()
        .find(|capability| capability.id == stage.capability_id);
    require(
        violations,
        capability.is_some_and(|capability| {
            capability.provider_required
                && capability.effect_class == stage.effect_class
                && mission.capability_ids.contains(&stage.capability_id)
        }),
        format!(
            "stage {} capability {} must be a matching provider-required Mission capability with effect class {}",
            stage.id, stage.capability_id, stage.effect_class
        ),
    );
    let provider = providers
        .providers
        .iter()
        .find(|provider| provider.id == stage.provider_id);
    require(
        violations,
        mission.provider_ids.contains(&stage.provider_id)
            && provider
                .is_some_and(|provider| provider.capability_ids.contains(&stage.capability_id)),
        format!(
            "stage {} requires Mission provider {} to expose {}",
            stage.id, stage.provider_id, stage.capability_id
        ),
    );
}

fn validate_effect_stage(stage: &EffectReadbackStage, violations: &mut Vec<String>) {
    require(
        violations,
        stage.id == "vm08.listing-write.effect/v1"
            && stage.ordinal == 1
            && stage.role == "write_effect"
            && stage.capability_id == "marketplace.write"
            && stage.executor == "effect_broker"
            && stage.effect_class == "external_write"
            && stage.provider_id == "amazon-sp-api"
            && stage.operation == "execute"
            && stage.evidence_class == "receipt_candidate"
            && stage.terminal_contribution == "receipt_candidate_only"
            && stage.correlation_source_stage_id.is_none()
            && !stage.independent_read_path_required
            && !stage.read_only_credential_required
            && !stage.execution_lease_forbidden
            && stage.comparison.is_none(),
        "VM-08 stage 1 must be the frozen Amazon marketplace.write ReceiptCandidate effect",
    );
    require_exact_fields(
        violations,
        &stage.binding_fields,
        &[
            "seller_account_id",
            "marketplace_id",
            "sku_or_asin",
            "locale",
            "canonical_field_diff",
            "idempotency_key",
            "approval_scope",
        ],
        "VM-08 write effect bindings",
    );
}

fn validate_readback_stage(
    stage: &EffectReadbackStage,
    effect: &EffectReadbackStage,
    violations: &mut Vec<String>,
) {
    require(
        violations,
        stage.id == "vm08.listing-write.account-readback/v1"
            && stage.ordinal == 2
            && stage.role == "independent_account_readback"
            && stage.capability_id == "marketplace.read"
            && stage.executor == "runtime"
            && stage.effect_class == "read"
            && stage.provider_id == "amazon-sp-api"
            && stage.operation == "read"
            && stage.evidence_class == "read_observation"
            && stage.terminal_contribution == "verification_required"
            && stage.correlation_source_stage_id.as_deref() == Some(effect.id.as_str())
            && stage.independent_read_path_required
            && stage.read_only_credential_required
            && stage.execution_lease_forbidden
            && stage.comparison.as_deref() == Some("canonical_target_field_diff"),
        "VM-08 stage 2 must be the frozen independent Amazon account readback bound to stage 1",
    );
    require_exact_fields(
        violations,
        &stage.binding_fields,
        &[
            "receipt_candidate_digest",
            "seller_account_id",
            "marketplace_id",
            "sku_or_asin",
            "locale",
            "canonical_field_diff",
        ],
        "VM-08 account readback bindings",
    );
}

fn validate_corroboration(
    flow: &EffectReadbackFlow,
    providers: &ProviderCatalog,
    violations: &mut Vec<String>,
) {
    let provider_ids = flow
        .corroboration
        .iter()
        .map(|binding| binding.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    require(
        violations,
        flow.corroboration.len() == 2 && provider_ids.len() == 2,
        "VM-08 corroboration must contain exactly Sorftime and browser-workspace",
    );
    for binding in &flow.corroboration {
        let provider = providers
            .providers
            .iter()
            .find(|provider| provider.id == binding.provider_id);
        require(
            violations,
            provider
                .is_some_and(|provider| provider.capability_ids.contains(&binding.capability_id)),
            format!(
                "corroborating provider {} must expose {}",
                binding.provider_id, binding.capability_id
            ),
        );
        require(
            violations,
            !binding.required_for_completion
                && !binding.may_confirm_write
                && matches!(
                    (
                        binding.provider_id.as_str(),
                        binding.capability_id.as_str(),
                        binding.authority.as_str()
                    ),
                    ("sorftime", "marketplace.read", "estimate_only")
                        | (
                            "browser-workspace",
                            "publication.verify",
                            "public_view_only"
                        )
                ),
            format!(
                "corroborating provider {} must remain non-completing and non-confirming",
                binding.provider_id
            ),
        );
    }
}

fn validate_terminal_condition(flow: &EffectReadbackFlow, violations: &mut Vec<String>) {
    let terminal = &flow.terminal_condition;
    require(
        violations,
        terminal.success == "verification_bound_to_receipt_and_canonical_target_diff"
            && !terminal.receipt_candidate_alone_completes
            && !terminal.corroboration_alone_completes
            && terminal.on_missing_or_mismatch == "inconclusive_fail_closed",
        "VM-08 ReceiptCandidate or corroboration must never complete the effect/readback flow",
    );
    let required_failures = BTreeSet::from([
        "missing_receipt_correlation",
        "seller_account_mismatch",
        "marketplace_mismatch",
        "sku_or_asin_mismatch",
        "locale_mismatch",
        "canonical_field_diff_mismatch",
        "readback_not_independent",
        "readback_credential_not_read_only",
        "corroboration_conflict",
    ]);
    let actual_failures = flow
        .fail_closed_on
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    require(
        violations,
        actual_failures == required_failures && actual_failures.len() == flow.fail_closed_on.len(),
        "VM-08 effect/readback fail-closed families must be exact and unique",
    );
}

fn validate_special_policy_bindings(
    missions: &MissionCatalog,
    contract: &EffectReadbackRouteContract,
    violations: &mut Vec<String>,
) {
    let bound_routes = contract
        .flows
        .iter()
        .map(|flow| {
            (
                flow.mission_id.as_str(),
                flow.mission_version,
                flow.parent_checkpoint_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    for mission in &missions.missions {
        for route in &mission.checkpoint_routes {
            if route.completion_policy == "effect_readback_v2" {
                require(
                    violations,
                    bound_routes.contains(&(
                        mission.id.as_str(),
                        mission.version,
                        route.checkpoint_id.as_str(),
                    )),
                    format!(
                        "Mission {} checkpoint {} uses effect_readback_v2 without a versioned flow binding",
                        mission.id, route.checkpoint_id
                    ),
                );
            }
        }
    }
}

fn require_exact_fields(
    violations: &mut Vec<String>,
    actual: &[String],
    expected: &[&str],
    label: &str,
) {
    let actual_fields = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_fields = expected.iter().copied().collect::<BTreeSet<_>>();
    require(
        violations,
        actual_fields == expected_fields && actual_fields.len() == actual.len(),
        format!("{label} must be exact and unique"),
    );
}

fn require(violations: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        violations.push(message.into());
    }
}
