use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::digest::{digest_json, is_lower_hex, sha256_hex};
use crate::model::{
    AggregateVerdict, AttemptDisposition, BrowserAttempt, BrowserCaseDefinition,
    BrowserCaseRegistry, BrowserReplay, BrowserRunReceipt, BrowserWorld, CampaignKind,
    CostMeasurement, EffectBoundary, EffectState, EvidenceCeiling, EvidenceClass,
    ExecutionModeKind, ExecutionStatus, FaultKind, OutcomeCounts, ProviderMode, ReadbackEvidence,
    ReplayEventKind,
};

pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-browser-contract-validation/v1";
pub const VALIDATION_AUTHORITY: &str = "browser_harness_contract_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";

const REGISTRY_SCHEMA_VERSION: &str = "hartevo-browser-case-registry/v1";
const WORLD_SCHEMA_VERSION: &str = "hartevo-browser-world/v1";
const REPLAY_SCHEMA_VERSION: &str = "hartevo-browser-replay/v1";
const RECEIPT_SCHEMA_VERSION: &str = "hartevo-browser-run-receipt/v1";
const SOURCE_COMMIT: &str = "752488888ab45596be242ecca3acae567ace2239";
const CATALOG_SCHEMA_VERSION: &str = "hartevo-catalog-snapshot/v4";
const CATALOG_DIGEST: &str = "3999b3084e0c3c1323ece5853203b75bcf2f76d69f50b5d1f0e003596d378a4b";
const ROUTE_GRAPH_CONTRACT_VERSION: &str = "desktop-2026-08-12-ct02-v1";
const RELEASE_EVIDENCE_SCHEMA_VERSION: &str = "2.3.0";
const EIGHT_HOURS_MS: u64 = 28_800_000;
const SOAK_MAX_SAMPLE_GAP_MS: u64 = 300_000;
const CASE_DEFINITION_DIGEST_DOMAIN: &str = "hartevo-browser-case-definition/v1";
const SEMANTIC_REPLAY_DIGEST_DOMAIN: &str = "hartevo-browser-semantic-replay/v1";
const DETERMINISM_GROUP_DIGEST_DOMAIN: &str = "hartevo-browser-determinism-group/v1";
const RESOURCE_SET_DIGEST_DOMAIN: &str = "hartevo-browser-resource-set/v1";
const COST_SET_DIGEST_DOMAIN: &str = "hartevo-browser-cost-set/v1";
const CONCURRENCY_SCHEDULE_DIGEST_DOMAIN: &str = "hartevo-browser-concurrency-schedule/v1";

const EXPECTED_NAMESPACES: [&str; 4] =
    ["BROWSER-REC", "BROWSER-SEC", "BROWSER-FILE", "BROWSER-INJ"];

const EXPECTED_DISPOSITIONS: [&str; 6] = [
    "PASS",
    "FAIL",
    "BLOCKED_ENV",
    "NOT_IMPLEMENTED",
    "NOT_RUN",
    "IGNORED",
];

const RELEASE_SAFETY_INVARIANT_IDS: [&str; 28] = [
    "approval_bypass",
    "approved_payload_substitution",
    "attribution_identity_violation",
    "browser_or_recipe_effect_broker_bypass",
    "browser_profile_or_session_scope_violation",
    "capability_or_subagent_authority_escalation",
    "consent_or_opt_out_violation",
    "creator_payout_before_acceptance_or_duplicate",
    "crm_stage_or_missing_order_claimed_as_revenue",
    "cross_cell_data_leak",
    "cross_project_data_leak",
    "cross_project_memory_recall",
    "cross_tenant_data_leak",
    "duplicate_external_effect",
    "false_complete_without_verified_outcome",
    "human_handoff_violation",
    "out_of_scope_delete_export_payment_or_contact",
    "path_traversal_or_attachment_scope_escape",
    "private_dataset_leak",
    "private_reasoning_leak",
    "prompt_injection_authority_change",
    "provider_success_claimed_as_publish_or_payment",
    "public_partner_candidate_autocontact",
    "secret_or_pii_leak",
    "token_cookie_or_provider_header_leak",
    "uncertain_auto_replay",
    "unsigned_update_plugin_recipe_or_harness_promotion",
    "wrong_money_or_currency",
];

const EXPECTED_CASE_IDS: [&str; 26] = [
    "BROWSER-REC-001",
    "BROWSER-REC-002",
    "BROWSER-REC-003",
    "BROWSER-REC-004",
    "BROWSER-REC-005",
    "BROWSER-REC-006",
    "BROWSER-REC-007",
    "BROWSER-REC-008",
    "BROWSER-REC-009",
    "BROWSER-REC-010",
    "BROWSER-SEC-001",
    "BROWSER-SEC-002",
    "BROWSER-SEC-003",
    "BROWSER-SEC-004",
    "BROWSER-SEC-005",
    "BROWSER-SEC-006",
    "BROWSER-FILE-001",
    "BROWSER-FILE-002",
    "BROWSER-FILE-003",
    "BROWSER-FILE-004",
    "BROWSER-FILE-005",
    "BROWSER-FILE-006",
    "BROWSER-INJ-001",
    "BROWSER-INJ-002",
    "BROWSER-INJ-003",
    "BROWSER-INJ-004",
];

const IMPLEMENTED_RUNNER_SELECTORS: [&str; 19] = [
    "hartevo-application::tests::real_chromium_application_handoff_and_restart_smoke",
    "hartevo-browser-adapter::chromium_host::tests::duplicate_accessible_role_and_name_never_becomes_a_unique_locator",
    "hartevo-browser-adapter::chromium_host::tests::real_chromium_pipe_health_ax_and_root_frame_smoke",
    "hartevo-browser-adapter::fake_host::tests::account_drift_is_detected_before_batch_execution",
    "hartevo-browser-adapter::fake_host::tests::caller_cannot_downgrade_click_risk_or_open_script_protocol_surfaces",
    "hartevo-browser-adapter::fake_host::tests::debug_surfaces_redact_credential_and_temporary_element_reference",
    "hartevo-browser-adapter::fake_host::tests::fresh_continue_lease_works_but_old_lease_never_recovers",
    "hartevo-browser-adapter::fake_host::tests::host_receipt_is_only_a_candidate_and_post_write_failure_is_uncertain",
    "hartevo-browser-adapter::fake_host::tests::host_restart_invalidates_inflight_cursor_and_requires_reobservation",
    "hartevo-browser-adapter::fake_host::tests::page_change_and_hidden_reference_are_independently_fenced",
    "hartevo-browser-adapter::fake_host::tests::prompt_injection_allows_observation_but_blocks_followup_action",
    "hartevo-browser-adapter::fake_host::tests::user_takeover_hard_stops_every_queued_write_surface",
    "hartevo-browser-adapter::file_broker::tests::exact_clean_file_grant_claim_and_completion_is_single_use_and_redacted",
    "hartevo-browser-adapter::file_broker::tests::prepared_revoke_plan_is_exact_and_deletes_only_after_commit",
    "hartevo-browser-adapter::file_broker::tests::scanner_mutation_is_detected_after_a_claimed_clean_verdict",
    "hartevo-browser-adapter::file_broker::tests::source_symlink_escape_and_in_project_symlink_are_both_rejected",
    "hartevo-browser-adapter::file_broker::tests::wrong_type_active_content_and_oversize_are_rejected_before_a_grant",
    "hartevo-browser-adapter::navigation::tests::origin_manifests_reject_paths_duplicates_and_public_http",
    "hartevo-browser-adapter::recipe::tests::production_recipe_rejects_origin_selector_and_approved_payload_substitution",
];

#[derive(Debug)]
pub struct RegistryValidation {
    case_definition_digests: BTreeMap<String, String>,
}

impl RegistryValidation {
    fn case_definition_digest(&self, case_id: &str) -> Result<&str> {
        self.case_definition_digests
            .get(case_id)
            .map(String::as_str)
            .with_context(|| format!("no definition digest for Browser case {case_id}"))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptValidationSummary {
    pub case_id: String,
    pub campaign_kind: CampaignKind,
    pub verdict: AggregateVerdict,
    pub recorded_attempt_count: usize,
    pub executed_attempt_count: usize,
    pub receipt_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeterminismDigestMaterial<'a> {
    ordinal: u32,
    replay_digest: &'a str,
    semantic_projection_digest: &'a str,
    state_digest: &'a str,
    trace_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceSetDigestMaterial<'a> {
    ordinal: u32,
    evidence_digest: &'a str,
    sample_set_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConcurrencyScheduleDigestMaterial<'a> {
    ordinal: u32,
    attempt_id: &'a str,
    profile_id: &'a str,
    execution_started: bool,
    started_at: &'a str,
    completed_at: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum CostSetDigestMaterial<'a> {
    Known {
        ordinal: u32,
        currency: &'a str,
        amount_micros: u64,
        evidence_digest: &'a str,
    },
    Unknown {
        ordinal: u32,
        reason_code: &'a str,
        evidence_digest: &'a str,
    },
}

pub fn validate_registry(registry: &BrowserCaseRegistry) -> Result<RegistryValidation> {
    ensure!(
        registry.schema_version == REGISTRY_SCHEMA_VERSION
            && registry.authority == VALIDATION_AUTHORITY,
        "Browser registry schema or authority is invalid"
    );
    ensure!(
        registry.source_commit == SOURCE_COMMIT && is_lower_hex(&registry.source_commit, 20),
        "Browser registry sourceCommit must be the published integration baseline"
    );
    ensure!(
        registry.catalog_binding.snapshot_schema_version == CATALOG_SCHEMA_VERSION
            && registry.catalog_binding.snapshot_digest == CATALOG_DIGEST
            && registry.catalog_binding.route_graph_contract_version
                == ROUTE_GRAPH_CONTRACT_VERSION,
        "Browser registry Catalog Snapshot v4 binding is invalid"
    );
    ensure!(
        registry.release_evidence_contract.schema_version == RELEASE_EVIDENCE_SCHEMA_VERSION
            && registry.release_evidence_contract.mapping_authority == "informational_subset_only"
            && !registry.release_evidence_contract.writes_release_evidence
            && !registry
                .release_evidence_contract
                .clears_evaluation_run_result_references,
        "Browser registry cannot write ReleaseEvidence or clear the evaluation-run gate"
    );
    validate_exact_string_list(
        &registry.case_id_namespaces,
        &EXPECTED_NAMESPACES,
        "caseIdNamespaces",
    )?;
    ensure!(
        registry.catalog_metadata_reference_policy.allowed_suite_ids
            == ["REC".to_owned(), "SAFE".to_owned()]
            && registry.catalog_metadata_reference_policy.authority == "metadata_only"
            && !registry
                .catalog_metadata_reference_policy
                .increments_executed_cross_cutting_case_count,
        "Catalog SAFE/REC references must remain metadata only"
    );
    validate_evidence_policy(registry)?;
    validate_exact_string_list(
        &registry.safety_invariant_ids,
        &RELEASE_SAFETY_INVARIANT_IDS,
        "safetyInvariantIds",
    )?;
    validate_cases(registry)
}

fn validate_evidence_policy(registry: &BrowserCaseRegistry) -> Result<()> {
    let policy = &registry.evidence_policy;
    validate_exact_string_list(
        &policy.allowed_dispositions,
        &EXPECTED_DISPOSITIONS,
        "allowedDispositions",
    )?;
    ensure!(
        !policy.zero_executed_cases_can_pass
            && !policy.ignored_can_pass
            && !policy.blocked_env_can_pass
            && !policy.not_implemented_can_pass
            && !policy.not_run_can_pass
            && !policy.host_receipt_is_provider_receipt
            && !policy.host_corroboration_is_business_verification
            && policy.provider_or_business_claim_maximum == "E1",
        "Browser evidence policy permits a false-green or authority upgrade"
    );
    Ok(())
}

fn validate_cases(registry: &BrowserCaseRegistry) -> Result<RegistryValidation> {
    let expected = EXPECTED_CASE_IDS.to_vec();
    ensure!(
        registry.cases.len() == expected.len(),
        "Browser case registry must contain exactly {} cases",
        expected.len()
    );
    let safety_ids = registry
        .safety_invariant_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let implemented_selectors = IMPLEMENTED_RUNNER_SELECTORS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut seen_case_ids = BTreeSet::new();
    let mut seen_selectors = BTreeSet::new();
    let mut case_definition_digests = BTreeMap::new();

    for (case, expected_id) in registry.cases.iter().zip(expected) {
        ensure!(
            case.case_id == expected_id,
            "Browser case order is not canonical"
        );
        validate_case_id(&case.case_id)?;
        ensure!(
            seen_case_ids.insert(case.case_id.as_str()),
            "duplicate Browser case id"
        );
        ensure!(case.case_version == 1, "Browser caseVersion must be one");
        validate_bounded_text(&case.title, 160, "case title")?;
        validate_unique_tokens(&case.required_oracle_ids, "requiredOracleIds")?;
        ensure!(
            !case.required_oracle_ids.is_empty(),
            "Browser case requires at least one oracle"
        );
        validate_sorted_unique_strings(
            &case.release_safety_invariant_ids,
            "releaseSafetyInvariantIds",
        )?;
        ensure!(
            case.release_safety_invariant_ids
                .iter()
                .all(|id| safety_ids.contains(id.as_str())),
            "Browser case references an unknown Release 2.3 safety invariant"
        );
        validate_catalog_metadata_case_ids(&case.catalog_metadata_case_ids)?;
        validate_case_implementation(case, &implemented_selectors, &mut seen_selectors)?;
        let digest = digest_json(CASE_DEFINITION_DIGEST_DOMAIN, case)
            .context("digesting Browser case definition")?;
        ensure!(
            case_definition_digests
                .insert(case.case_id.clone(), digest)
                .is_none(),
            "duplicate Browser case definition digest entry"
        );
    }
    ensure!(
        seen_selectors == implemented_selectors,
        "implemented Browser runner selector inventory is incomplete"
    );
    Ok(RegistryValidation {
        case_definition_digests,
    })
}

fn validate_case_implementation<'a>(
    case: &'a BrowserCaseDefinition,
    implemented_selectors: &BTreeSet<&str>,
    seen_selectors: &mut BTreeSet<&'a str>,
) -> Result<()> {
    match case.execution_status {
        ExecutionStatus::ImplementedDefaultTest => {
            ensure!(
                case.evidence_ceiling == EvidenceCeiling::E2Local,
                "implemented default test must remain E2_LOCAL"
            );
            let selector = case
                .runner_selector
                .as_deref()
                .context("implemented Browser case requires runnerSelector")?;
            ensure!(
                implemented_selectors.contains(selector),
                "implemented Browser runner selector is not in the source-audited allow-list"
            );
            ensure!(
                !selector.contains("real_chromium"),
                "real Chromium tests must remain ignored-environment cases"
            );
            ensure!(seen_selectors.insert(selector), "duplicate runnerSelector");
        }
        ExecutionStatus::ImplementedIgnoredEnvTest => {
            ensure!(
                case.evidence_ceiling == EvidenceCeiling::E2Local,
                "ignored environment test must remain E2_LOCAL"
            );
            let selector = case
                .runner_selector
                .as_deref()
                .context("ignored Browser case requires runnerSelector")?;
            ensure!(
                implemented_selectors.contains(selector) && selector.contains("real_chromium"),
                "ignored Browser case must bind an exact real Chromium selector"
            );
            ensure!(seen_selectors.insert(selector), "duplicate runnerSelector");
        }
        ExecutionStatus::NotImplemented => ensure!(
            case.evidence_ceiling == EvidenceCeiling::None && case.runner_selector.is_none(),
            "NOT_IMPLEMENTED Browser case cannot bind a runner or evidence ceiling"
        ),
    }
    if case.case_id == "BROWSER-SEC-006" {
        ensure!(
            case.release_safety_invariant_ids.is_empty(),
            "malware/scanner case has no dedicated Release 2.3 invariant"
        );
    }
    Ok(())
}

pub fn validate_schema_contracts(
    world_schema: &Value,
    replay_schema: &Value,
    receipt_schema: &Value,
) -> Result<()> {
    validate_schema_identity(
        world_schema,
        "https://hartevo.example/contracts/browser-eval/browser-world/1.0.0",
        "Hartevo Deterministic Browser World",
    )?;
    validate_schema_identity(
        replay_schema,
        "https://hartevo.example/contracts/browser-eval/browser-replay/1.0.0",
        "Hartevo Browser Semantic Replay",
    )?;
    validate_schema_identity(
        receipt_schema,
        "https://hartevo.example/contracts/browser-eval/browser-run-receipt/1.0.0",
        "Hartevo Browser Run Receipt Payload",
    )?;
    validate_schema_const(
        world_schema,
        "/properties/schemaVersion/const",
        WORLD_SCHEMA_VERSION,
    )?;
    validate_schema_const(
        replay_schema,
        "/properties/schemaVersion/const",
        REPLAY_SCHEMA_VERSION,
    )?;
    validate_schema_const(
        receipt_schema,
        "/properties/schemaVersion/const",
        RECEIPT_SCHEMA_VERSION,
    )?;
    validate_schema_const(
        receipt_schema,
        "/properties/authority/const",
        "browser_harness_evidence_only",
    )?;
    validate_schema_const(
        receipt_schema,
        "/properties/releaseDecision/const",
        RELEASE_DECISION,
    )?;
    ensure!(
        receipt_schema.pointer("/$defs/safetyInvariantId/enum")
            == Some(&Value::Array(
                RELEASE_SAFETY_INVARIANT_IDS
                    .iter()
                    .map(|value| Value::String((*value).to_owned()))
                    .collect()
            )),
        "receipt schema safety invariant enum differs from Release 2.3"
    );
    validate_schema_const(
        receipt_schema,
        "/$defs/authorityClaims/properties/providerReceiptAuthority/const",
        false,
    )?;
    validate_schema_const(
        receipt_schema,
        "/$defs/authorityClaims/properties/businessVerificationAuthority/const",
        false,
    )?;
    validate_schema_const(
        receipt_schema,
        "/$defs/authorityClaims/properties/releaseEvidenceAuthority/const",
        false,
    )?;
    validate_schema_const(
        receipt_schema,
        "/$defs/latencySummary/properties/p99Reported/const",
        false,
    )?;
    Ok(())
}

pub fn validate_release_and_run_seam(
    registry: &BrowserCaseRegistry,
    release_schema: &Value,
    evaluation_run_schema: &Value,
) -> Result<()> {
    let expected_safety_ids = Value::Array(
        RELEASE_SAFETY_INVARIANT_IDS
            .iter()
            .map(|value| Value::String((*value).to_owned()))
            .collect(),
    );
    ensure!(
        release_schema.pointer("/properties/schemaVersion/const")
            == Some(&Value::String(RELEASE_EVIDENCE_SCHEMA_VERSION.to_owned()))
            && release_schema.pointer("/$defs/safetyEvidence/required")
                == Some(&expected_safety_ids)
            && release_schema.pointer("/properties/missingRequiredEvidence/contains/const")
                == Some(&Value::String(
                    "evaluation_run_result_references".to_owned()
                ))
            && release_schema.pointer("/properties/missingRequiredEvidence/minItems")
                == Some(&Value::from(1)),
        "Release Evidence 2.3 safety or missing-evaluation-run seam changed"
    );
    ensure!(
        evaluation_run_schema.pointer("/$defs/safetyInvariantId/enum")
            == Some(&expected_safety_ids)
            && evaluation_run_schema.pointer("/$defs/runReceipt/properties/authority/const")
                == Some(&Value::String("run_evidence_only".to_owned()))
            && evaluation_run_schema.pointer("/$defs/runReceipt/properties/runId/$ref")
                == Some(&Value::String("#/$defs/digest".to_owned()))
            && evaluation_run_schema.pointer("/$defs/runReceipt/properties/resultSetDigest/$ref")
                == Some(&Value::String("#/$defs/digest".to_owned())),
        "RUN-01 public runId/resultSetDigest or safety seam changed"
    );
    ensure!(
        registry.safety_invariant_ids
            == RELEASE_SAFETY_INVARIANT_IDS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
            && !registry.release_evidence_contract.writes_release_evidence
            && !registry
                .release_evidence_contract
                .clears_evaluation_run_result_references,
        "Browser registry attempts to exceed the Release/RUN seam"
    );
    Ok(())
}

fn validate_schema_identity(schema: &Value, expected_id: &str, expected_title: &str) -> Result<()> {
    ensure!(
        schema.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
            && schema.get("$id").and_then(Value::as_str) == Some(expected_id)
            && schema.get("title").and_then(Value::as_str) == Some(expected_title)
            && schema.get("type").and_then(Value::as_str) == Some("object")
            && schema.get("additionalProperties") == Some(&Value::Bool(false)),
        "Browser JSON Schema identity or closed-object root is invalid"
    );
    Ok(())
}

fn validate_schema_const(schema: &Value, pointer: &str, expected: impl Into<Value>) -> Result<()> {
    let expected = expected.into();
    ensure!(
        schema.pointer(pointer) == Some(&expected),
        "Browser JSON Schema const is invalid at {pointer}"
    );
    Ok(())
}

// World validation is deliberately linear: every fail-closed invariant is visible in wire order.
#[allow(clippy::too_many_lines)]
pub fn validate_world(world: &BrowserWorld) -> Result<String> {
    ensure!(
        world.schema_version == WORLD_SCHEMA_VERSION,
        "Browser World schemaVersion is invalid"
    );
    validate_world_id(&world.world_id)?;
    ensure!(world.world_version > 0, "worldVersion must be positive");
    validate_digest(&world.deterministic_seed, "deterministicSeed")?;
    validate_digest(&world.initial_state_digest, "initialStateDigest")?;
    validate_digest(&world.fixture_set_digest, "fixtureSetDigest")?;
    ensure!(
        world.virtual_clock.timezone == "UTC"
            && !world.virtual_clock.wall_clock_reads_allowed
            && world.virtual_clock.tick_duration_ms > 0
            && world.virtual_clock.tick_duration_ms <= 60_000,
        "Browser World requires a bounded deterministic UTC virtual clock"
    );
    ensure!(
        !world.profiles.is_empty() && world.profiles.len() <= 8,
        "Browser World profile count must be 1..=8"
    );
    let mut profile_ids = BTreeSet::new();
    for profile in &world.profiles {
        validate_token(&profile.profile_id, "profileId")?;
        ensure!(
            profile_ids.insert(profile.profile_id.as_str()),
            "duplicate Browser World profileId"
        );
        for (digest, label) in [
            (&profile.profile_digest, "profileDigest"),
            (&profile.tenant_scope_digest, "tenantScopeDigest"),
            (&profile.project_scope_digest, "projectScopeDigest"),
            (&profile.account_scope_digest, "accountScopeDigest"),
            (&profile.storage_template_digest, "storageTemplateDigest"),
        ] {
            validate_digest(digest, label)?;
        }
    }
    validate_token(&world.provider.provider_id, "providerId")?;
    validate_digest(&world.provider.provider_digest, "providerDigest")?;
    validate_digest(&world.provider.account_scope_digest, "accountScopeDigest")?;
    validate_digest(
        &world.provider.credential_reference_digest,
        "credentialReferenceDigest",
    )?;
    ensure!(
        !world.provider.credential_material_embedded,
        "Browser World cannot embed credential material"
    );
    ensure!(
        world
            .profiles
            .iter()
            .all(|profile| profile.account_scope_digest == world.provider.account_scope_digest),
        "World profile and provider account scopes differ"
    );
    ensure!(
        world.network_policy.deny_by_default,
        "Browser World network policy must deny by default"
    );
    validate_sorted_unique_digests(
        &world.network_policy.allowed_origin_digests,
        "allowedOriginDigests",
    )?;
    validate_digest(
        &world.network_policy.fixture_response_set_digest,
        "fixtureResponseSetDigest",
    )?;
    if world.provider.mode == ProviderMode::ControlledSimulator {
        ensure!(
            !world.network_policy.external_network_allowed,
            "controlled simulator Browser World cannot allow external network"
        );
    }
    ensure!(
        world.effect_policy.effect_broker_required && world.effect_policy.approval_required,
        "Browser World cannot bypass Effect Broker approval"
    );
    validate_sorted_unique_tokens(
        &world.effect_policy.allowed_effect_class_ids,
        "allowedEffectClassIds",
    )?;
    validate_sorted_unique_tokens(&world.effect_policy.denied_surface_ids, "deniedSurfaceIds")?;
    ensure!(
        world
            .effect_policy
            .denied_surface_ids
            .iter()
            .any(|surface| surface == "page_script")
            && world
                .effect_policy
                .denied_surface_ids
                .iter()
                .any(|surface| surface == "raw_protocol"),
        "Browser World must deny page_script and raw_protocol"
    );
    let mut previous_fault_event = None;
    for (index, fault) in world.faults.iter().enumerate() {
        ensure!(
            fault.ordinal as usize == index,
            "Browser World fault ordinals must be contiguous from zero"
        );
        if let Some(previous) = previous_fault_event {
            ensure!(
                fault.at_event_ordinal >= previous,
                "Browser World faults must be sorted by event ordinal"
            );
        }
        previous_fault_event = Some(fault.at_event_ordinal);
        validate_digest(&fault.fault_digest, "faultDigest")?;
        if matches!(
            fault.kind,
            crate::model::FaultKind::BrowserProcessKill
                | crate::model::FaultKind::RendererProcessKill
                | crate::model::FaultKind::HarnessProcessKill
        ) {
            ensure!(
                fault.external_process_action,
                "process-kill World fault must be externally performed"
            );
        }
        if fault.effect_boundary.rank() >= EffectBoundary::DispatchStarted.rank() {
            ensure!(
                !fault.automatic_replay_allowed_at_fault,
                "post-dispatch World fault cannot permit automatic Effect replay"
            );
        }
    }
    validate_sorted_unique_tokens(&world.oracle_ids, "oracleIds")?;
    ensure!(
        !world.oracle_ids.is_empty(),
        "Browser World requires oracles"
    );
    ensure!(
        world.cleanup_policy.required
            && world.cleanup_policy.profile_reset_required
            && world.cleanup_policy.maximum_orphan_process_count == 0
            && world.cleanup_policy.maximum_retained_profile_artifact_count == 0
            && world.cleanup_policy.retention_mode == "digest_only",
        "Browser World cleanup policy is not fail-closed"
    );
    digest_json("hartevo-browser-world/v1", world).context("digesting Browser World")
}

pub fn validate_replay(replay: &BrowserReplay, world: &BrowserWorld) -> Result<String> {
    let world_digest = validate_world(world)?;
    ensure!(
        replay.schema_version == REPLAY_SCHEMA_VERSION,
        "Browser Replay schemaVersion is invalid"
    );
    validate_replay_id(&replay.replay_id)?;
    validate_case_id(&replay.case_id)?;
    ensure!(
        replay.case_version > 0,
        "Replay caseVersion must be positive"
    );
    ensure!(
        replay.world_id == world.world_id
            && replay.world_version == world.world_version
            && replay.world_digest == world_digest
            && replay.deterministic_seed == world.deterministic_seed,
        "Browser Replay does not bind the exact World"
    );
    validate_digest(&replay.recorded_input_digest, "recordedInputDigest")?;
    ensure!(
        replay.policy.semantic_only && !replay.policy.raw_wall_time_equality_claimed,
        "Browser Replay must be semantic and cannot claim raw wall-time equality"
    );
    ensure!(
        replay.events.len() >= 2 && replay.events.len() <= 4096,
        "Browser Replay event count must be 2..=4096"
    );
    let mut maximum_boundary = EffectBoundary::NoEffect;
    let mut previous_virtual_time = 0;
    for (index, event) in replay.events.iter().enumerate() {
        ensure!(
            event.ordinal as usize == index,
            "Browser Replay event ordinals must be contiguous from zero"
        );
        if index == 0 {
            ensure!(
                event.kind == ReplayEventKind::WorldReset && event.virtual_time_ms == 0,
                "Browser Replay must begin with world_reset at virtual time zero"
            );
        } else {
            ensure!(
                event.virtual_time_ms >= previous_virtual_time,
                "Browser Replay virtual time must be monotonic"
            );
        }
        previous_virtual_time = event.virtual_time_ms;
        maximum_boundary = if event.effect_boundary.rank() > maximum_boundary.rank() {
            event.effect_boundary
        } else {
            maximum_boundary
        };
        validate_digest(&event.input_digest, "Replay event inputDigest")?;
        validate_digest(&event.output_digest, "Replay event outputDigest")?;
    }
    ensure!(
        replay.events.last().map(|event| event.kind) == Some(ReplayEventKind::Terminal),
        "Browser Replay must end with a terminal event"
    );
    if replay.policy.uncertain_effect_observed
        || maximum_boundary.rank() >= EffectBoundary::DispatchStarted.rank()
    {
        ensure!(
            !replay.policy.automatic_effect_replay_allowed,
            "uncertain or post-dispatch Replay cannot permit automatic Effect replay"
        );
    }
    validate_digest(&replay.final_state_digest, "finalStateDigest")?;
    let expected_projection = digest_json(
        SEMANTIC_REPLAY_DIGEST_DOMAIN,
        &(
            &replay.case_id,
            replay.case_version,
            &replay.world_digest,
            &replay.recorded_input_digest,
            &replay.policy,
            &replay.events,
            &replay.final_state_digest,
        ),
    )
    .context("deriving Browser Replay semantic projection digest")?;
    ensure!(
        replay.semantic_projection_digest == expected_projection,
        "Browser Replay semanticProjectionDigest is invalid"
    );
    digest_json("hartevo-browser-replay/v1", replay).context("digesting Browser Replay")
}

#[allow(clippy::too_many_arguments)]
pub fn validate_receipt(
    receipt: &BrowserRunReceipt,
    receipt_bytes: &[u8],
    registry: &BrowserCaseRegistry,
    registry_validation: &RegistryValidation,
    registry_digest: &str,
    world_schema_digest: &str,
    replay_schema_digest: &str,
    receipt_schema_digest: &str,
    world: &BrowserWorld,
    world_digest: &str,
    replay: &BrowserReplay,
    replay_digest: &str,
    evaluation_run: &hartevo_eval::EvaluationRunReceipt,
    evaluation_plan: &Value,
) -> Result<ReceiptValidationSummary> {
    ensure!(
        receipt.schema_version == RECEIPT_SCHEMA_VERSION
            && receipt.authority == "browser_harness_evidence_only"
            && receipt.release_decision == RELEASE_DECISION,
        "Browser receipt schema, authority or releaseDecision is invalid"
    );
    ensure!(
        receipt.contract_bindings.case_registry_digest == registry_digest
            && receipt.contract_bindings.world_schema_digest == world_schema_digest
            && receipt.contract_bindings.replay_schema_digest == replay_schema_digest
            && receipt.contract_bindings.receipt_schema_digest == receipt_schema_digest,
        "Browser receipt does not bind the exact contract bytes"
    );
    ensure!(
        receipt.evaluation_run.run_id == evaluation_run.run_id()
            && receipt.evaluation_run.result_set_digest == evaluation_run.result_set_digest()
            && receipt.evaluation_run.structurally_complete
                == evaluation_run.structurally_complete()
            && receipt.evaluation_run.partition_complete == evaluation_run.partition_complete()
            && receipt.evaluation_run.executed_case_count == evaluation_run.executed_case_count(),
        "Browser receipt does not bind the exact validated RUN-01 receipt"
    );
    ensure!(
        evaluation_run.structurally_complete()
            && evaluation_run.partition_complete()
            && evaluation_run.executed_case_count() > 0,
        "Browser receipt requires a structurally complete RUN-01 result set"
    );
    ensure!(
        evaluation_plan.pointer("/schemaVersion")
            == Some(&Value::String("hartevo-evaluation-run/v1".to_owned()))
            && evaluation_plan.pointer("/documentType")
                == Some(&Value::String("run_plan".to_owned()))
            && evaluation_plan.pointer("/authority")
                == Some(&Value::String("run_evidence_only".to_owned()))
            && evaluation_plan.pointer("/runId")
                == Some(&Value::String(evaluation_run.run_id().to_owned()))
            && evaluation_plan.pointer("/releaseCommit")
                == Some(&Value::String(receipt.binary.source_commit.clone()))
            && evaluation_plan.pointer("/environmentDigest")
                == Some(&Value::String(
                    receipt.environment.environment_digest.clone()
                ))
            && evaluation_plan.pointer("/catalog/snapshotDigest")
                == Some(&Value::String(CATALOG_DIGEST.to_owned())),
        "Browser receipt commit/environment does not bind the validated RUN-01 plan"
    );
    validate_binary_and_environment(receipt)?;
    validate_profile_and_provider_bindings(receipt, world)?;
    let case = registry
        .cases
        .iter()
        .find(|case| case.case_id == receipt.case.case_id)
        .context("Browser receipt case is absent from registry")?;
    ensure!(
        receipt.case.case_version == case.case_version
            && receipt.case.case_definition_digest
                == registry_validation.case_definition_digest(&case.case_id)?
            && receipt.case.release_safety_invariant_ids == case.release_safety_invariant_ids
            && receipt.campaign.kind == case.campaign_kind,
        "Browser receipt case binding is invalid"
    );
    ensure!(
        replay.case_id == case.case_id && replay.case_version == case.case_version,
        "Browser Replay does not bind the receipt case"
    );
    ensure!(
        receipt.world.world_id == world.world_id
            && receipt.world.world_version == world.world_version
            && receipt.world.world_digest == world_digest
            && receipt.world.deterministic_seed == world.deterministic_seed,
        "Browser receipt World binding is invalid"
    );
    ensure!(
        receipt.replay.replay_id == replay.replay_id
            && receipt.replay.replay_digest == replay_digest
            && receipt.replay.semantic_projection_digest == replay.semantic_projection_digest,
        "Browser receipt Replay binding is invalid"
    );
    ensure!(
        !receipt.authority_claims.provider_receipt_authority
            && !receipt.authority_claims.business_verification_authority
            && !receipt.authority_claims.release_evidence_authority
            && receipt.authority_claims.e_level == "E1_MAX",
        "Browser receipt claims provider, business, Release or E4 authority"
    );
    validate_campaign_envelope(receipt)?;
    validate_attempts(receipt, world, replay)?;
    validate_aggregate(receipt, replay, world)?;
    ensure_case_status_consistency(case, receipt)?;
    Ok(ReceiptValidationSummary {
        case_id: case.case_id.clone(),
        campaign_kind: receipt.campaign.kind,
        verdict: receipt.aggregate.verdict,
        recorded_attempt_count: receipt.attempts.len(),
        executed_attempt_count: executed_attempt_count(&receipt.attempts),
        receipt_digest: sha256_hex(receipt_bytes),
    })
}

fn validate_binary_and_environment(receipt: &BrowserRunReceipt) -> Result<()> {
    ensure!(
        is_lower_hex(&receipt.binary.source_commit, 20),
        "Browser receipt sourceCommit must be 40 lowercase hexadecimal characters"
    );
    for (digest, label) in [
        (
            &receipt.binary.application_binary_digest,
            "applicationBinaryDigest",
        ),
        (&receipt.binary.runner_binary_digest, "runnerBinaryDigest"),
        (&receipt.binary.browser_binary_digest, "browserBinaryDigest"),
        (
            &receipt.binary.browser_version_digest,
            "browserVersionDigest",
        ),
        (&receipt.environment.environment_digest, "environmentDigest"),
        (
            &receipt.environment.provider_environment_digest,
            "providerEnvironmentDigest",
        ),
        (
            &receipt.environment.profile_root_policy_digest,
            "profileRootPolicyDigest",
        ),
        (&receipt.provider.provider_digest, "providerDigest"),
        (&receipt.provider.account_scope_digest, "accountScopeDigest"),
    ] {
        validate_digest(digest, label)?;
    }
    ensure!(
        receipt.binary.application_binary_byte_count > 0,
        "application binary byte count must be positive"
    );
    validate_token(&receipt.binary.target_triple, "targetTriple")?;
    Ok(())
}

fn validate_profile_and_provider_bindings(
    receipt: &BrowserRunReceipt,
    world: &BrowserWorld,
) -> Result<()> {
    ensure!(
        receipt.provider.provider_id == world.provider.provider_id
            && receipt.provider.mode == world.provider.mode
            && receipt.provider.provider_digest == world.provider.provider_digest
            && receipt.provider.account_scope_digest == world.provider.account_scope_digest,
        "Browser receipt provider differs from World"
    );
    ensure!(
        !receipt.profiles.is_empty() && receipt.profiles.len() == world.profiles.len(),
        "Browser receipt profile set differs from World"
    );
    let expected = world
        .profiles
        .iter()
        .map(|profile| (profile.profile_id.as_str(), profile.profile_digest.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut prior = None;
    for profile in &receipt.profiles {
        validate_token(&profile.profile_id, "profileId")?;
        validate_digest(&profile.profile_digest, "profileDigest")?;
        if let Some(previous) = prior {
            ensure!(
                previous < profile.profile_id.as_str(),
                "profiles must be sorted unique"
            );
        }
        prior = Some(profile.profile_id.as_str());
        ensure!(
            expected.get(profile.profile_id.as_str()) == Some(&profile.profile_digest.as_str()),
            "Browser receipt profile binding differs from World"
        );
    }
    ensure!(
        (1..=8).contains(
            &receipt
                .execution_mode
                .max_configured_cross_profile_concurrency
        ),
        "cross-profile concurrency bound must be 1..=8"
    );
    if receipt.execution_mode.kind == ExecutionModeKind::SingleProfileSerial {
        ensure!(
            receipt.profiles.len() == 1
                && receipt
                    .execution_mode
                    .max_configured_cross_profile_concurrency
                    == 1,
            "single-profile serial mode must bind one profile and concurrency one"
        );
    } else {
        ensure!(
            receipt.profiles.len() >= 2,
            "cross-profile bounded mode requires at least two profiles"
        );
    }
    Ok(())
}

fn validate_campaign_envelope(receipt: &BrowserRunReceipt) -> Result<()> {
    ensure!(
        receipt.campaign.configured_attempt_count > 0
            && receipt.aggregate.configured_attempt_count
                == receipt.campaign.configured_attempt_count,
        "Browser campaign configured attempt count is invalid"
    );
    ensure!(
        receipt.campaign.campaign_duration_ms >= receipt.campaign.minimum_duration_ms,
        "Browser campaign is shorter than its declared minimum"
    );
    ensure!(
        receipt.campaign.campaign_duration_ms == attempt_span_ms(&receipt.attempts)?,
        "Browser campaign duration is not derived from exact attempt timestamps"
    );
    match receipt.campaign.kind {
        CampaignKind::SingleCase => ensure!(
            receipt.campaign.configured_attempt_count == 1,
            "single_case requires one configured attempt"
        ),
        CampaignKind::Journey30 => ensure!(
            receipt.campaign.configured_attempt_count == 30,
            "journey_30 requires exactly 30 configured attempts"
        ),
        CampaignKind::Race => ensure!(
            receipt.campaign.configured_attempt_count >= 2,
            "race requires at least two configured attempts"
        ),
        CampaignKind::ProcessKill => ensure!(
            receipt.campaign.configured_attempt_count >= 1,
            "process_kill requires an attempt"
        ),
        CampaignKind::Soak8h => ensure!(
            receipt.campaign.minimum_duration_ms == EIGHT_HOURS_MS
                && receipt.campaign.campaign_duration_ms >= EIGHT_HOURS_MS,
            "soak_8h requires at least 28,800,000 milliseconds"
        ),
        CampaignKind::ResourceCost => {}
    }
    Ok(())
}

fn validate_attempts(
    receipt: &BrowserRunReceipt,
    world: &BrowserWorld,
    replay: &BrowserReplay,
) -> Result<()> {
    ensure!(
        !receipt.attempts.is_empty() && receipt.attempts.len() <= 10_000,
        "Browser receipt attempt count must be 1..=10000"
    );
    let profile_ids = receipt
        .profiles
        .iter()
        .map(|profile| profile.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut attempt_ids = BTreeSet::new();
    for (index, attempt) in receipt.attempts.iter().enumerate() {
        ensure!(
            attempt.ordinal as usize == index + 1,
            "Browser attempt ordinals must be contiguous from one"
        );
        validate_token(&attempt.attempt_id, "attemptId")?;
        ensure!(
            attempt_ids.insert(attempt.attempt_id.as_str()),
            "duplicate attemptId"
        );
        ensure!(
            profile_ids.contains(attempt.profile_id.as_str()),
            "Browser attempt references an unknown profile"
        );
        ensure!(
            attempt.replay_digest == receipt.replay.replay_digest
                && attempt.semantic_projection_digest == replay.semantic_projection_digest,
            "Browser attempt Replay binding is invalid"
        );
        for (digest, label) in [
            (&attempt.state_digest, "attempt stateDigest"),
            (&attempt.trace_digest, "attempt traceDigest"),
            (&attempt.evidence_digest, "attempt evidenceDigest"),
            (
                &attempt.resource.sample_set_digest,
                "resource sampleSetDigest",
            ),
        ] {
            validate_digest(digest, label)?;
        }
        validate_attempt_time(attempt)?;
        validate_attempt_disposition(attempt)?;
        validate_readback(attempt)?;
        validate_resource_evidence(attempt)?;
        validate_cost(&attempt.cost)?;
        if attempt.effect_state == EffectState::UncertainAfterDispatch
            || replay.policy.uncertain_effect_observed
        {
            ensure!(
                !attempt.automatic_replay_performed,
                "uncertain Browser Effect was automatically replayed"
            );
        }
        ensure!(
            world.cleanup_policy.required,
            "Browser World unexpectedly lacks cleanup policy"
        );
    }
    Ok(())
}

fn validate_attempt_time(attempt: &BrowserAttempt) -> Result<()> {
    let started_at = DateTime::parse_from_rfc3339(&attempt.started_at)
        .context("Browser attempt startedAt is not RFC3339")?
        .with_timezone(&Utc);
    let completed_at = DateTime::parse_from_rfc3339(&attempt.completed_at)
        .context("Browser attempt completedAt is not RFC3339")?
        .with_timezone(&Utc);
    ensure!(
        completed_at >= started_at,
        "Browser attempt completed before it started"
    );
    let elapsed = completed_at
        .signed_duration_since(started_at)
        .num_milliseconds();
    let elapsed = u64::try_from(elapsed).context("Browser attempt duration is negative")?;
    ensure!(
        elapsed == attempt.duration_ms,
        "Browser attempt durationMs differs from RFC3339 timestamps"
    );
    if attempt.execution_started {
        ensure!(
            attempt.duration_ms > 0,
            "executed Browser attempt requires positive duration"
        );
    }
    Ok(())
}

fn validate_attempt_disposition(attempt: &BrowserAttempt) -> Result<()> {
    match attempt.disposition {
        AttemptDisposition::Pass | AttemptDisposition::Fail => ensure!(
            attempt.execution_started && attempt.blocker.is_none(),
            "PASS/FAIL requires real execution and cannot be blocked"
        ),
        AttemptDisposition::BlockedEnv => {
            ensure!(
                attempt.blocker.is_some(),
                "BLOCKED_ENV requires typed blocker evidence"
            );
            let blocker = attempt.blocker.as_ref().context("blocker missing")?;
            validate_token(&blocker.code, "blocker code")?;
            validate_digest(&blocker.observation_digest, "blocker observationDigest")?;
            validate_digest(
                &blocker.exit_condition_digest,
                "blocker exitConditionDigest",
            )?;
        }
        AttemptDisposition::NotImplemented | AttemptDisposition::NotRun => ensure!(
            !attempt.execution_started && !attempt.ignored_test && attempt.blocker.is_none(),
            "NOT_IMPLEMENTED/NOT_RUN cannot claim execution, ignored or blocker evidence"
        ),
        AttemptDisposition::Ignored => ensure!(
            !attempt.execution_started && attempt.ignored_test && attempt.blocker.is_none(),
            "IGNORED must be explicit and cannot claim execution"
        ),
    }
    match attempt.evidence_class {
        EvidenceClass::SourceAudit | EvidenceClass::NativePreflight => ensure!(
            !matches!(
                attempt.disposition,
                AttemptDisposition::Pass | AttemptDisposition::Fail
            ),
            "source audit or preflight evidence cannot become PASS/FAIL execution"
        ),
        EvidenceClass::DeterministicSimulator
        | EvidenceClass::NativeBrowser
        | EvidenceClass::NativeBrowserAccountReadback => {}
    }
    Ok(())
}

fn validate_readback(attempt: &BrowserAttempt) -> Result<()> {
    match (&attempt.effect_state, &attempt.readback) {
        (
            EffectState::NoEffect
            | EffectState::BeforeDispatchFailure
            | EffectState::UncertainAfterDispatch,
            ReadbackEvidence::None,
        )
        | (EffectState::ReceiptCandidate, ReadbackEvidence::ReceiptCandidate { .. })
        | (EffectState::HostCorroborated, ReadbackEvidence::HostCorroborated { .. })
        | (
            EffectState::IndependentAccountReadback,
            ReadbackEvidence::IndependentAccountReadback { .. },
        ) => {}
        _ => bail!("Browser attempt effectState and readback stage disagree"),
    }
    match &attempt.readback {
        ReadbackEvidence::None => {}
        ReadbackEvidence::ReceiptCandidate {
            receipt_candidate_digest,
        } => validate_digest(receipt_candidate_digest, "receiptCandidateDigest")?,
        ReadbackEvidence::HostCorroborated {
            receipt_candidate_digest,
            host_corroboration_digest,
        } => {
            validate_digest(receipt_candidate_digest, "receiptCandidateDigest")?;
            validate_digest(host_corroboration_digest, "hostCorroborationDigest")?;
        }
        ReadbackEvidence::IndependentAccountReadback {
            receipt_candidate_digest,
            host_corroboration_digest,
            independent_account_readback_digest,
        } => {
            validate_digest(receipt_candidate_digest, "receiptCandidateDigest")?;
            validate_digest(host_corroboration_digest, "hostCorroborationDigest")?;
            validate_digest(
                independent_account_readback_digest,
                "independentAccountReadbackDigest",
            )?;
        }
    }
    Ok(())
}

fn validate_resource_evidence(attempt: &BrowserAttempt) -> Result<()> {
    let resource = &attempt.resource;
    ensure!(
        resource.first_sample_offset_ms <= resource.last_sample_offset_ms
            && resource.last_sample_offset_ms <= attempt.duration_ms,
        "resource sample offsets escape attempt duration"
    );
    ensure!(
        resource.peak_rss_bytes >= resource.start_rss_bytes
            && resource.peak_rss_bytes >= resource.end_rss_bytes,
        "peak RSS is below an endpoint sample"
    );
    ensure!(
        resource.maximum_child_process_count >= resource.start_child_process_count
            && resource.maximum_child_process_count >= resource.end_child_process_count
            && resource.maximum_open_file_count >= resource.start_open_file_count
            && resource.maximum_open_file_count >= resource.end_open_file_count,
        "resource maximum is below an endpoint sample"
    );
    if attempt.execution_started {
        ensure!(
            resource.sample_count >= 2
                && resource.first_sample_offset_ms == 0
                && resource.last_sample_offset_ms == attempt.duration_ms,
            "executed Browser attempt requires exact resource endpoint coverage"
        );
    }
    Ok(())
}

fn validate_cost(cost: &CostMeasurement) -> Result<()> {
    match cost {
        CostMeasurement::Known {
            currency,
            evidence_digest,
            ..
        } => {
            ensure!(
                currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase()),
                "known Browser cost currency must be ISO-like uppercase"
            );
            validate_digest(evidence_digest, "cost evidenceDigest")?;
        }
        CostMeasurement::Unknown {
            reason_code,
            evidence_digest,
        } => {
            validate_token(reason_code, "unknown cost reasonCode")?;
            validate_digest(evidence_digest, "cost evidenceDigest")?;
        }
    }
    Ok(())
}

fn validate_aggregate(
    receipt: &BrowserRunReceipt,
    replay: &BrowserReplay,
    world: &BrowserWorld,
) -> Result<()> {
    let aggregate = &receipt.aggregate;
    ensure!(
        aggregate.recorded_attempt_count == receipt.attempts.len(),
        "aggregate recordedAttemptCount is invalid"
    );
    let outcomes = recompute_outcomes(&receipt.attempts);
    ensure!(
        aggregate.outcomes == outcomes,
        "aggregate outcome counts differ from Browser attempts"
    );
    let executed = receipt
        .attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.disposition,
                AttemptDisposition::Pass | AttemptDisposition::Fail
            )
        })
        .collect::<Vec<_>>();
    let expected_latency = latency_summary(&executed);
    ensure!(
        aggregate.latency.sample_count == expected_latency.0
            && aggregate.latency.p50_ms == expected_latency.1
            && aggregate.latency.p95_ms == expected_latency.2
            && aggregate.latency.max_ms == expected_latency.3
            && !aggregate.latency.p99_reported,
        "Browser latency summary is invalid or reports p99 below 100 samples"
    );
    let matching_projection_count = executed
        .iter()
        .filter(|attempt| {
            attempt.semantic_projection_digest == receipt.replay.semantic_projection_digest
        })
        .count();
    let determinism_material = executed
        .iter()
        .map(|attempt| DeterminismDigestMaterial {
            ordinal: attempt.ordinal,
            replay_digest: &attempt.replay_digest,
            semantic_projection_digest: &attempt.semantic_projection_digest,
            state_digest: &attempt.state_digest,
            trace_digest: &attempt.trace_digest,
        })
        .collect::<Vec<_>>();
    let determinism_digest = digest_json(DETERMINISM_GROUP_DIGEST_DOMAIN, &determinism_material)
        .context("deriving determinism group digest")?;
    ensure!(
        aggregate.determinism.executed_attempt_count == executed.len()
            && aggregate.determinism.matching_semantic_projection_count
                == matching_projection_count
            && aggregate.determinism.all_matched
                == (executed.len() == matching_projection_count && !executed.is_empty())
            && aggregate.determinism.group_digest == determinism_digest,
        "Browser determinism summary is invalid"
    );
    let concurrency = concurrency_observation(&receipt.attempts)?;
    ensure!(
        aggregate.concurrency.same_profile_overlap_count == concurrency.0
            && aggregate
                .concurrency
                .maximum_observed_same_profile_concurrency
                == concurrency.1
            && aggregate
                .concurrency
                .maximum_observed_cross_profile_concurrency
                == concurrency.2
            && aggregate.concurrency.schedule_digest == concurrency.3,
        "Browser concurrency summary is not derived from exact attempt intervals"
    );
    ensure!(
        concurrency.0 == 0
            && concurrency.1 <= 1
            && concurrency.2
                <= receipt
                    .execution_mode
                    .max_configured_cross_profile_concurrency,
        "Browser profile concurrency violates serial/bounded policy"
    );
    validate_resource_summary(receipt)?;
    validate_cost_summary(receipt)?;
    validate_cleanup_summary(receipt)?;
    validate_campaign_aggregate(receipt, &executed, replay, world)?;
    validate_aggregate_verdict(receipt)?;
    Ok(())
}

fn validate_resource_summary(receipt: &BrowserRunReceipt) -> Result<()> {
    let material = receipt
        .attempts
        .iter()
        .map(|attempt| ResourceSetDigestMaterial {
            ordinal: attempt.ordinal,
            evidence_digest: &attempt.evidence_digest,
            sample_set_digest: &attempt.resource.sample_set_digest,
        })
        .collect::<Vec<_>>();
    let expected_digest = digest_json(RESOURCE_SET_DIGEST_DOMAIN, &material)
        .context("deriving Browser resource evidence set digest")?;
    let peak_rss = receipt
        .attempts
        .iter()
        .map(|attempt| attempt.resource.peak_rss_bytes)
        .max()
        .unwrap_or(0);
    let max_growth = receipt
        .attempts
        .iter()
        .map(|attempt| {
            i128::from(attempt.resource.end_rss_bytes)
                - i128::from(attempt.resource.start_rss_bytes)
        })
        .max()
        .unwrap_or(0);
    let max_children = receipt
        .attempts
        .iter()
        .map(|attempt| attempt.resource.maximum_child_process_count)
        .max()
        .unwrap_or(0);
    let max_files = receipt
        .attempts
        .iter()
        .map(|attempt| attempt.resource.maximum_open_file_count)
        .max()
        .unwrap_or(0);
    ensure!(
        receipt.aggregate.resource.attempt_evidence_count == receipt.attempts.len()
            && receipt.aggregate.resource.peak_rss_bytes == peak_rss
            && receipt.aggregate.resource.maximum_end_minus_start_rss_bytes == max_growth
            && receipt.aggregate.resource.maximum_child_process_count == max_children
            && receipt.aggregate.resource.maximum_open_file_count == max_files
            && receipt.aggregate.resource.evidence_set_digest == expected_digest,
        "Browser aggregate resource summary is invalid"
    );
    Ok(())
}

fn validate_cost_summary(receipt: &BrowserRunReceipt) -> Result<()> {
    let mut known_count = 0;
    let mut unknown_count = 0;
    let mut currencies = BTreeSet::new();
    let mut total_micros = 0_u64;
    let mut material = Vec::with_capacity(receipt.attempts.len());
    for attempt in &receipt.attempts {
        match &attempt.cost {
            CostMeasurement::Known {
                currency,
                amount_micros,
                evidence_digest,
            } => {
                known_count += 1;
                currencies.insert(currency.as_str());
                total_micros = total_micros
                    .checked_add(*amount_micros)
                    .context("Browser cost total overflow")?;
                material.push(CostSetDigestMaterial::Known {
                    ordinal: attempt.ordinal,
                    currency,
                    amount_micros: *amount_micros,
                    evidence_digest,
                });
            }
            CostMeasurement::Unknown {
                reason_code,
                evidence_digest,
            } => {
                unknown_count += 1;
                material.push(CostSetDigestMaterial::Unknown {
                    ordinal: attempt.ordinal,
                    reason_code,
                    evidence_digest,
                });
            }
        }
    }
    let evidence_digest = digest_json(COST_SET_DIGEST_DOMAIN, &material)
        .context("deriving Browser cost evidence set digest")?;
    ensure!(
        receipt.aggregate.cost.known_attempt_count == known_count
            && receipt.aggregate.cost.unknown_attempt_count == unknown_count,
        "Browser aggregate cost counts are invalid"
    );
    match &receipt.aggregate.cost.measurement {
        CostMeasurement::Known {
            currency,
            amount_micros,
            evidence_digest: aggregate_digest,
        } => ensure!(
            unknown_count == 0
                && currencies.len() == 1
                && currencies.contains(currency.as_str())
                && *amount_micros == total_micros
                && *aggregate_digest == evidence_digest,
            "known Browser aggregate cost is not fully attributable"
        ),
        CostMeasurement::Unknown {
            reason_code,
            evidence_digest: aggregate_digest,
        } => ensure!(
            unknown_count > 0
                && reason_code == "one_or_more_attempt_costs_unknown"
                && *aggregate_digest == evidence_digest,
            "unknown Browser aggregate cost is incomplete or disguised as zero"
        ),
    }
    Ok(())
}

fn validate_cleanup_summary(receipt: &BrowserRunReceipt) -> Result<()> {
    let cleanup = &receipt.aggregate.cleanup;
    ensure!(
        cleanup.required
            && cleanup.attempted_count == receipt.attempts.len()
            && cleanup.succeeded_count <= cleanup.attempted_count
            && is_lower_hex(&cleanup.evidence_digest, 32),
        "Browser cleanup summary is invalid"
    );
    Ok(())
}

// Campaign-specific proofs stay together so evidence ceilings cannot drift across helpers.
#[allow(clippy::too_many_lines)]
fn validate_campaign_aggregate(
    receipt: &BrowserRunReceipt,
    executed: &[&BrowserAttempt],
    replay: &BrowserReplay,
    world: &BrowserWorld,
) -> Result<()> {
    match receipt.campaign.kind {
        CampaignKind::SingleCase => {}
        CampaignKind::Journey30 => ensure!(
            executed.len() == 30
                && receipt.aggregate.outcomes.pass == 30
                && receipt.aggregate.determinism.all_matched
                && receipt.aggregate.latency.sample_count == 30
                && executed
                    .iter()
                    .map(|attempt| attempt.state_digest.as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 1
                && executed
                    .iter()
                    .map(|attempt| attempt.trace_digest.as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 1
                && !receipt.aggregate.latency.p99_reported,
            "journey_30 requires exactly thirty deterministic PASS executions"
        ),
        CampaignKind::Race => {
            let race = receipt
                .aggregate
                .race
                .as_ref()
                .context("race campaign requires exact race evidence")?;
            validate_digest(&race.seed, "race seed")?;
            validate_digest(&race.barrier_digest, "race barrierDigest")?;
            validate_digest(&race.schedule_digest, "race scheduleDigest")?;
            ensure!(
                race.seed == world.deterministic_seed
                    && race.barrier_participant_count >= 2
                    && race.winner_count == 1
                    && race.external_effect_count <= 1
                    && race.schedule_digest == receipt.aggregate.concurrency.schedule_digest,
                "Browser race evidence does not prove a single bounded winner"
            );
        }
        CampaignKind::ProcessKill => {
            let kill = receipt
                .aggregate
                .process_kill
                .as_ref()
                .context("process_kill campaign requires exact kill evidence")?;
            validate_digest(
                &kill.target_process_identity_digest,
                "targetProcessIdentityDigest",
            )?;
            validate_digest(
                &kill.killer_process_identity_digest,
                "killerProcessIdentityDigest",
            )?;
            validate_digest(&kill.cleanup_digest, "process kill cleanupDigest")?;
            ensure!(
                kill.external_kill
                    && kill.distinct_process_confirmed
                    && kill.target_process_identity_digest != kill.killer_process_identity_digest
                    && matches!(kill.signal.as_str(), "SIGKILL" | "TerminateProcess")
                    && kill.termination_observed
                    && kill.cleanup_digest == receipt.aggregate.cleanup.evidence_digest,
                "process_kill evidence is not an external exact-identity kill"
            );
            let replay_fault = replay
                .events
                .get(kill.fault_event_ordinal as usize)
                .context("process-kill fault ordinal is absent from Replay")?;
            ensure!(
                replay_fault.ordinal == kill.fault_event_ordinal
                    && replay_fault.kind == ReplayEventKind::Fault,
                "process-kill evidence does not bind a Replay fault event"
            );
            ensure!(
                world.faults.iter().any(|fault| {
                    fault.at_event_ordinal == kill.fault_event_ordinal
                        && fault.external_process_action
                        && matches!(
                            (fault.kind, kill.target_kind),
                            (
                                FaultKind::BrowserProcessKill,
                                crate::model::KillTargetKind::Browser
                            ) | (
                                FaultKind::RendererProcessKill,
                                crate::model::KillTargetKind::Renderer
                            ) | (
                                FaultKind::HarnessProcessKill,
                                crate::model::KillTargetKind::Harness
                            )
                        )
                }),
                "process-kill evidence does not bind an external exact-kind World fault"
            );
        }
        CampaignKind::Soak8h => {
            ensure!(
                receipt.campaign.campaign_duration_ms >= EIGHT_HOURS_MS
                    && receipt
                        .attempts
                        .iter()
                        .all(|attempt| attempt.resource.sample_count >= 2
                            && attempt.resource.maximum_sample_gap_ms <= SOAK_MAX_SAMPLE_GAP_MS)
                    && receipt.attempts.iter().all(|attempt| {
                        attempt.resource.end_rss_bytes <= attempt.resource.start_rss_bytes
                            && attempt.resource.end_child_process_count
                                <= attempt.resource.start_child_process_count
                            && attempt.resource.end_open_file_count
                                <= attempt.resource.start_open_file_count
                    })
                    && !receipt.aggregate.resource.leak_detected,
                "soak_8h lacks duration, bounded sampling, or leak-free evidence"
            );
        }
        CampaignKind::ResourceCost => ensure!(
            receipt.aggregate.resource.attempt_evidence_count == receipt.attempts.len(),
            "resource_cost campaign lacks per-attempt resource evidence"
        ),
    }
    if !matches!(receipt.campaign.kind, CampaignKind::Race) {
        ensure!(
            receipt.aggregate.race.is_none(),
            "non-race campaign cannot carry race evidence"
        );
    }
    if !matches!(receipt.campaign.kind, CampaignKind::ProcessKill) {
        ensure!(
            receipt.aggregate.process_kill.is_none(),
            "non-process-kill campaign cannot carry process kill evidence"
        );
    }
    Ok(())
}

fn validate_aggregate_verdict(receipt: &BrowserRunReceipt) -> Result<()> {
    let outcomes = &receipt.aggregate.outcomes;
    let complete = receipt.aggregate.recorded_attempt_count
        == receipt.aggregate.configured_attempt_count
        && receipt.aggregate.cleanup.succeeded_count == receipt.attempts.len()
        && receipt.aggregate.cleanup.orphan_process_count_after == 0
        && receipt.aggregate.cleanup.retained_profile_artifact_count == 0;
    let expected = derived_aggregate_verdict(
        outcomes,
        complete,
        receipt.aggregate.determinism.all_matched,
        receipt.aggregate.resource.leak_detected,
    );
    ensure!(
        receipt.aggregate.verdict == expected,
        "Browser aggregate verdict is false-green or non-derived"
    );
    Ok(())
}

fn derived_aggregate_verdict(
    outcomes: &OutcomeCounts,
    complete: bool,
    determinism_all_matched: bool,
    resource_leak_detected: bool,
) -> AggregateVerdict {
    let executed = outcomes.pass + outcomes.fail;
    if outcomes.fail > 0 {
        AggregateVerdict::Fail
    } else if complete
        && executed > 0
        && outcomes.pass == executed
        && outcomes.blocked_env == 0
        && outcomes.not_implemented == 0
        && outcomes.not_run == 0
        && outcomes.ignored == 0
        && determinism_all_matched
        && !resource_leak_detected
    {
        AggregateVerdict::Pass
    } else {
        AggregateVerdict::Incomplete
    }
}

fn ensure_case_status_consistency(
    case: &BrowserCaseDefinition,
    receipt: &BrowserRunReceipt,
) -> Result<()> {
    match case.execution_status {
        ExecutionStatus::ImplementedDefaultTest => ensure!(
            receipt.attempts.iter().all(|attempt| !attempt.ignored_test),
            "default Browser case cannot claim an ignored test definition"
        ),
        ExecutionStatus::ImplementedIgnoredEnvTest => ensure!(
            receipt.attempts.iter().all(|attempt| attempt.ignored_test),
            "real-Chromium environment case must retain its ignored-test qualifier"
        ),
        ExecutionStatus::NotImplemented => ensure!(
            receipt.aggregate.verdict == AggregateVerdict::Incomplete
                && receipt.attempts.iter().all(|attempt| {
                    matches!(
                        attempt.disposition,
                        AttemptDisposition::NotImplemented | AttemptDisposition::NotRun
                    )
                }),
            "NOT_IMPLEMENTED Browser case cannot become PASS/FAIL/BLOCKED_ENV"
        ),
    }
    Ok(())
}

fn recompute_outcomes(attempts: &[BrowserAttempt]) -> OutcomeCounts {
    let mut counts = OutcomeCounts::zero();
    for attempt in attempts {
        counts.increment(attempt.disposition);
    }
    counts
}

fn executed_attempt_count(attempts: &[BrowserAttempt]) -> usize {
    attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.disposition,
                AttemptDisposition::Pass | AttemptDisposition::Fail
            )
        })
        .count()
}

fn latency_summary(executed: &[&BrowserAttempt]) -> (usize, u64, u64, u64) {
    let mut durations = executed
        .iter()
        .map(|attempt| attempt.duration_ms)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    if durations.is_empty() {
        return (0, 0, 0, 0);
    }
    let p50 = nearest_rank(&durations, 50);
    let p95 = nearest_rank(&durations, 95);
    let max = *durations.last().expect("non-empty durations");
    (durations.len(), p50, p95, max)
}

fn attempt_span_ms(attempts: &[BrowserAttempt]) -> Result<u64> {
    let mut earliest: Option<DateTime<Utc>> = None;
    let mut latest: Option<DateTime<Utc>> = None;
    for attempt in attempts {
        let started = DateTime::parse_from_rfc3339(&attempt.started_at)
            .context("Browser campaign startedAt is not RFC3339")?
            .with_timezone(&Utc);
        let completed = DateTime::parse_from_rfc3339(&attempt.completed_at)
            .context("Browser campaign completedAt is not RFC3339")?
            .with_timezone(&Utc);
        ensure!(
            completed >= started,
            "Browser campaign contains negative duration"
        );
        earliest = Some(match earliest {
            Some(current) => current.min(started),
            None => started,
        });
        latest = Some(match latest {
            Some(current) => current.max(completed),
            None => completed,
        });
    }
    let earliest = earliest.context("Browser campaign has no attempt start")?;
    let latest = latest.context("Browser campaign has no attempt completion")?;
    let span = latest.signed_duration_since(earliest).num_milliseconds();
    u64::try_from(span).context("Browser campaign span is negative")
}

fn concurrency_observation(attempts: &[BrowserAttempt]) -> Result<(usize, usize, usize, String)> {
    let timed = attempts
        .iter()
        .filter(|attempt| attempt.execution_started)
        .map(|attempt| {
            let started = DateTime::parse_from_rfc3339(&attempt.started_at)
                .context("Browser concurrency startedAt is not RFC3339")?
                .with_timezone(&Utc);
            let completed = DateTime::parse_from_rfc3339(&attempt.completed_at)
                .context("Browser concurrency completedAt is not RFC3339")?
                .with_timezone(&Utc);
            Ok((attempt, started, completed))
        })
        .collect::<Result<Vec<_>>>()?;
    let same_profile_overlap_count = timed
        .iter()
        .enumerate()
        .flat_map(|(index, left)| timed.iter().skip(index + 1).map(move |right| (left, right)))
        .filter(|(left, right)| {
            left.0.profile_id == right.0.profile_id && left.1 < right.2 && right.1 < left.2
        })
        .count();
    let mut maximum_same_profile = 0;
    let mut maximum_total = 0;
    for (_, instant, _) in &timed {
        let mut per_profile = BTreeMap::<&str, usize>::new();
        for (attempt, started, completed) in &timed {
            if started <= instant && instant < completed {
                *per_profile.entry(attempt.profile_id.as_str()).or_default() += 1;
            }
        }
        maximum_same_profile =
            maximum_same_profile.max(per_profile.values().copied().max().unwrap_or_default());
        maximum_total = maximum_total.max(per_profile.values().sum());
    }
    let schedule = attempts
        .iter()
        .map(|attempt| ConcurrencyScheduleDigestMaterial {
            ordinal: attempt.ordinal,
            attempt_id: &attempt.attempt_id,
            profile_id: &attempt.profile_id,
            execution_started: attempt.execution_started,
            started_at: &attempt.started_at,
            completed_at: &attempt.completed_at,
        })
        .collect::<Vec<_>>();
    let schedule_digest = digest_json(CONCURRENCY_SCHEDULE_DIGEST_DOMAIN, &schedule)
        .context("deriving Browser concurrency schedule digest")?;
    Ok((
        same_profile_overlap_count,
        maximum_same_profile,
        maximum_total,
        schedule_digest,
    ))
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percentile).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn validate_catalog_metadata_case_ids(values: &[String]) -> Result<()> {
    validate_sorted_unique_strings(values, "catalogMetadataCaseIds")?;
    ensure!(
        !values.is_empty()
            && values.iter().all(|value| {
                let mut parts = value.split('-');
                matches!(parts.next(), Some("REC" | "SAFE"))
                    && matches!(parts.next(), Some("VM"))
                    && parts.next().is_some_and(|number| {
                        number.len() == 2 && number.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    && parts.next() == Some("001")
                    && parts.next().is_none()
            }),
        "Catalog Browser references must be metadata-only SAFE/REC VM case ids"
    );
    Ok(())
}

fn validate_case_id(value: &str) -> Result<()> {
    let suffix = EXPECTED_NAMESPACES
        .iter()
        .find_map(|namespace| value.strip_prefix(&format!("{namespace}-")));
    ensure!(
        suffix.is_some_and(|suffix| {
            suffix.len() == 3 && suffix.bytes().all(|byte| byte.is_ascii_digit())
        }),
        "invalid Browser case id {value}"
    );
    Ok(())
}

fn validate_world_id(value: &str) -> Result<()> {
    validate_prefixed_upper_id(value, "BROWSER-WORLD-", "worldId")
}

fn validate_replay_id(value: &str) -> Result<()> {
    validate_prefixed_upper_id(value, "BROWSER-REPLAY-", "replayId")
}

fn validate_prefixed_upper_id(value: &str, prefix: &str, label: &str) -> Result<()> {
    let suffix = value.strip_prefix(prefix).unwrap_or_default();
    ensure!(
        !suffix.is_empty()
            && suffix.len() <= 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-'),
        "{label} is not a canonical prefixed uppercase id"
    );
    Ok(())
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            }),
        "{label} is not a canonical token"
    );
    Ok(())
}

fn validate_bounded_text(value: &str, maximum: usize, label: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control),
        "{label} must be non-empty bounded text without controls"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        is_lower_hex(value, 32),
        "{label} must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_sorted_unique_digests(values: &[String], label: &str) -> Result<()> {
    validate_sorted_unique_strings(values, label)?;
    values
        .iter()
        .try_for_each(|value| validate_digest(value, label))
}

fn validate_sorted_unique_tokens(values: &[String], label: &str) -> Result<()> {
    validate_sorted_unique_strings(values, label)?;
    values
        .iter()
        .try_for_each(|value| validate_token(value, label))
}

fn validate_unique_tokens(values: &[String], label: &str) -> Result<()> {
    let unique = values.iter().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(unique.len() == values.len(), "{label} must be unique");
    values
        .iter()
        .try_for_each(|value| validate_token(value, label))
}

fn validate_sorted_unique_strings(values: &[String], label: &str) -> Result<()> {
    ensure!(
        values
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str()),
        "{label} must be sorted and unique"
    );
    Ok(())
}

fn validate_exact_string_list<T: AsRef<str>>(
    actual: &[String],
    expected: &[T],
    label: &str,
) -> Result<()> {
    ensure!(
        actual.len() == expected.len()
            && actual
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual == expected.as_ref()),
        "{label} differs from the frozen contract"
    );
    Ok(())
}

pub fn raw_contract_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn validate_world_and_replay(
    world: &BrowserWorld,
    replay: &BrowserReplay,
) -> Result<(String, String)> {
    let world_digest = validate_world(world)?;
    let replay_digest = validate_replay(replay, world)?;
    Ok((world_digest, replay_digest))
}

pub fn repository_relative_contract_exists(repository_root: &Path, relative: &str) -> Result<()> {
    ensure!(
        repository_root.join(relative).is_file(),
        "required Browser contract is absent: {relative}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{derived_aggregate_verdict, nearest_rank, validate_case_id};
    use crate::model::{AggregateVerdict, OutcomeCounts};

    #[test]
    fn nearest_rank_and_case_namespace_are_fail_closed() {
        let values = (1..=30).collect::<Vec<_>>();
        assert_eq!(nearest_rank(&values, 50), 15);
        assert_eq!(nearest_rank(&values, 95), 29);
        assert!(validate_case_id("BROWSER-REC-001").is_ok());
        assert!(validate_case_id("BROWSER-FILE-001").is_ok());
        assert!(validate_case_id("REC-VM-04-001").is_err());
    }

    #[test]
    fn zero_failed_never_masks_missing_or_nonexecuted_browser_evidence() {
        let zero = OutcomeCounts::zero();
        assert_eq!(
            derived_aggregate_verdict(&zero, true, true, false),
            AggregateVerdict::Incomplete
        );

        let mut blocked = OutcomeCounts::zero();
        blocked.blocked_env = 1;
        assert_eq!(
            derived_aggregate_verdict(&blocked, true, true, false),
            AggregateVerdict::Incomplete
        );

        let mut ignored = OutcomeCounts::zero();
        ignored.ignored = 1;
        assert_eq!(
            derived_aggregate_verdict(&ignored, true, true, false),
            AggregateVerdict::Incomplete
        );

        let mut passing = OutcomeCounts::zero();
        passing.pass = 1;
        assert_eq!(
            derived_aggregate_verdict(&passing, true, true, false),
            AggregateVerdict::Pass
        );

        passing.fail = 1;
        assert_eq!(
            derived_aggregate_verdict(&passing, true, true, false),
            AggregateVerdict::Fail
        );
    }
}
