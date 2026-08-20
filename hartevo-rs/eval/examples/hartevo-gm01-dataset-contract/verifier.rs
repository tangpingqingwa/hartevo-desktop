use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::digest::{domain_digest_json, is_lower_hex, sha256_hex};
use crate::model::{
    CaseScope, Claim, ClaimClassification, Counterevidence, Dataset, DatasetBinding,
    DatasetRegistryDocument, DecisionGoal, ExpectedDecision, ObservationWindow, ReplayCase,
    SourceKind, TimelineEvent, Uncertainty, parse_strict_json,
};

pub const DATASET_PATH: &str = "contracts/datasets/gm01-de-market-replay-v1.json";
pub const REGISTRY_PATH: &str = "contracts/datasets/registry.v1.json";
pub const EXPECTED_REGISTRY_SCHEMA: &str = "hartevo-dataset-registry/v1";
pub const EXPECTED_REGISTRY_VERSION: &str = "desktop-2026-08-11-v4";
pub const EXPECTED_BINDING_ID: &str = "gm01-de-market-replay-v1";
pub const EXPECTED_BINDING_VERSION: &str = "desktop-2026-08-13-gm01-v1";
pub const EXPECTED_DATASET_SCHEMA: &str = "hartevo-gm01-dataset/v1";
pub const EXPECTED_DATASET_ID: &str = "gm01-de-market-replay";
pub const EXPECTED_DATASET_VERSION: &str = "2026-08-13.1";
pub const EXPECTED_MISSION_ID: &str = "VM-07";
pub const EXPECTED_FIXTURE_ID: &str = "mxzone-de-market-v1";
pub const EXPECTED_PARTITION: &str = "vertical-dev";
pub const EXPECTED_SPLIT: &str = "V0";
pub const EXPECTED_MARKET: &str = "DE";
pub const EXPECTED_LOCALE: &str = "de-DE";
pub const EXPECTED_CURRENCY: &str = "EUR";
pub const EXPECTED_START: &str = "2026-07-01T00:00:00Z";
pub const EXPECTED_END: &str = "2026-07-31T23:59:59Z";
pub const EXPECTED_TIME_ZONE: &str = "Europe/Berlin";
pub const EXPECTED_CASE_COUNT: usize = 3;
pub const EXPECTED_DATASET_RAW_DIGEST: &str =
    "975e1a882b437049d695e2622bebe20a42bd476c68fd3618ca9681f1b7967825";
pub const EXECUTION_MODE: &str = "SIMULATOR/REPLAY_ONLY";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-gm01-dataset-validation/v1";
const REPLAY_DIGEST_DOMAIN: &str = "hartevo-gm01-replay-digest/v1";

const EXPECTED_CASE_IDS: [&str; EXPECTED_CASE_COUNT] = [
    "gm01-de-001-demand-signal",
    "gm01-de-002-compliance-risk",
    "gm01-de-003-controlled-pilot",
];
const EXPECTED_CLASSIFICATIONS: [ClaimClassification; 4] = [
    ClaimClassification::ConfirmedFact,
    ClaimClassification::ProviderEstimate,
    ClaimClassification::AgentInference,
    ClaimClassification::Unknown,
];
const EXPECTED_FORBIDDEN_EFFECTS: [&str; 3] =
    ["native_execution", "production_write", "provider_write"];
const EXPECTED_FORBIDDEN_CHANNELS: [&str; 3] =
    ["paid_search", "unapproved_outreach", "production_write"];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub execution_mode: &'static str,
    pub dataset_id: String,
    pub dataset_version: String,
    pub binding_id: String,
    pub mission_id: String,
    pub fixture_id: String,
    pub partition: String,
    pub split: String,
    pub market: String,
    pub locale: String,
    pub currency: String,
    pub observation_window: ObservationWindow,
    pub raw_dataset_digest: String,
    pub registry_digest: String,
    pub replay_digest: String,
    pub case_count: usize,
    pub claim_count: usize,
    pub counterevidence_count: usize,
    pub native_receipt_count: usize,
    pub release_decision: &'static str,
    pub production_evaluation: &'static str,
    pub writes_performed: bool,
    pub claims_are_digest_bound: bool,
    pub counterevidence_is_digest_bound: bool,
}

pub fn validate_contracts(dataset_bytes: &[u8], registry_bytes: &[u8]) -> Result<ValidationReport> {
    let registry = parse_strict_json::<DatasetRegistryDocument>(registry_bytes)
        .context("dataset registry is not valid JSON with the GM-01 binding shape")?;
    ensure!(
        registry.schema_version == EXPECTED_REGISTRY_SCHEMA,
        "dataset registry schema drift: expected {EXPECTED_REGISTRY_SCHEMA}, got {}",
        registry.schema_version
    );
    ensure!(
        registry.registry_version == EXPECTED_REGISTRY_VERSION,
        "dataset registry version drift: expected {EXPECTED_REGISTRY_VERSION}, got {}",
        registry.registry_version
    );
    ensure!(
        registry.dataset_bindings.len() == 1,
        "GM-01 registry must contain exactly one isolated dataset binding"
    );

    let dataset = parse_strict_json::<Dataset>(dataset_bytes)
        .context("GM-01 dataset is not strict typed JSON")?;
    let raw_dataset_digest = sha256_hex(dataset_bytes);
    let binding = &registry.dataset_bindings[0];
    validate_registry_binding(binding, &dataset, &raw_dataset_digest)?;
    validate_dataset_contract(&dataset)?;
    let replay_digest = replay_digest(&dataset)?;

    Ok(ValidationReport {
        schema_version: VALIDATION_SCHEMA_VERSION,
        status: "PASS",
        execution_mode: EXECUTION_MODE,
        dataset_id: dataset.dataset_id.clone(),
        dataset_version: dataset.dataset_version.clone(),
        binding_id: binding.binding_id.clone(),
        mission_id: dataset.mission_id.clone(),
        fixture_id: dataset.fixture_id.clone(),
        partition: dataset.partition.clone(),
        split: dataset.split.clone(),
        market: dataset.world.market.clone(),
        locale: dataset.world.locale.clone(),
        currency: dataset.world.currency.clone(),
        observation_window: dataset.world.observation_window.clone(),
        raw_dataset_digest,
        registry_digest: sha256_hex(registry_bytes),
        replay_digest,
        case_count: dataset.cases.len(),
        claim_count: dataset.cases.iter().map(|case| case.claims.len()).sum(),
        counterevidence_count: dataset
            .cases
            .iter()
            .map(|case| case.counterevidence.len())
            .sum(),
        native_receipt_count: dataset.isolation.native_receipt_count,
        release_decision: RELEASE_DECISION,
        production_evaluation: RELEASE_DECISION,
        writes_performed: false,
        claims_are_digest_bound: true,
        counterevidence_is_digest_bound: true,
    })
}

pub fn replay_digest(dataset: &Dataset) -> Result<String> {
    domain_digest_json(REPLAY_DIGEST_DOMAIN, dataset)
        .context("serialize deterministic GM-01 replay digest material")
}

pub fn validate_registry_binding(
    binding: &DatasetBinding,
    dataset: &Dataset,
    raw_dataset_digest: &str,
) -> Result<()> {
    ensure!(
        binding.binding_id == EXPECTED_BINDING_ID,
        "dataset binding id drift: expected {EXPECTED_BINDING_ID}, got {}",
        binding.binding_id
    );
    ensure!(
        binding.binding_version == EXPECTED_BINDING_VERSION,
        "dataset binding version drift: expected {EXPECTED_BINDING_VERSION}, got {}",
        binding.binding_version
    );
    ensure!(
        binding.dataset_path == DATASET_PATH,
        "dataset binding path drift: expected {DATASET_PATH}, got {}",
        binding.dataset_path
    );
    ensure!(
        binding.dataset_id == dataset.dataset_id
            && binding.dataset_version == dataset.dataset_version
            && binding.mission_id == dataset.mission_id
            && binding.fixture_id == dataset.fixture_id,
        "dataset binding identity/version drift"
    );
    ensure!(
        binding.partition == EXPECTED_PARTITION && binding.split == EXPECTED_SPLIT,
        "dataset binding partition/split drift"
    );
    ensure!(
        binding.case_count == EXPECTED_CASE_COUNT && binding.case_count == dataset.cases.len(),
        "dataset binding case count drift"
    );
    ensure!(
        is_lower_hex(&binding.raw_digest, 32)
            && binding.raw_digest == EXPECTED_DATASET_RAW_DIGEST
            && raw_dataset_digest == EXPECTED_DATASET_RAW_DIGEST,
        "dataset raw digest drift: registry binding does not match the exact dataset bytes"
    );
    ensure!(
        binding.isolation_policy == EXECUTION_MODE
            && binding.native_receipt_count == 0
            && binding.release_decision == RELEASE_DECISION
            && !binding.private_content,
        "dataset binding isolation policy drift"
    );
    Ok(())
}

pub fn validate_dataset_contract(dataset: &Dataset) -> Result<()> {
    ensure!(
        dataset.schema_version == EXPECTED_DATASET_SCHEMA,
        "dataset schema drift: expected {EXPECTED_DATASET_SCHEMA}, got {}",
        dataset.schema_version
    );
    ensure!(
        dataset.dataset_id == EXPECTED_DATASET_ID
            && dataset.dataset_version == EXPECTED_DATASET_VERSION
            && dataset.mission_id == EXPECTED_MISSION_ID
            && dataset.fixture_id == EXPECTED_FIXTURE_ID,
        "dataset identity/version/mission/fixture drift"
    );
    ensure!(
        dataset.partition == EXPECTED_PARTITION && dataset.split == EXPECTED_SPLIT,
        "dataset partition/split drift"
    );
    ensure!(
        dataset.data_classification == "PUBLIC_SYNTHETIC_CONTRACT",
        "dataset classification drift: only PUBLIC_SYNTHETIC_CONTRACT is allowed"
    );
    validate_provenance(&dataset.provenance)?;
    validate_world(&dataset.world)?;
    validate_isolation(&dataset.isolation)?;
    ensure!(
        dataset.cases.len() == EXPECTED_CASE_COUNT,
        "dataset case count drift: expected {EXPECTED_CASE_COUNT}, got {}",
        dataset.cases.len()
    );

    let expected_case_ids = EXPECTED_CASE_IDS.into_iter().collect::<BTreeSet<_>>();
    let actual_case_ids = dataset
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual_case_ids == expected_case_ids,
        "dataset case ids drift or cross-case leakage detected"
    );

    let mut seen_claim_ids = BTreeSet::new();
    let mut seen_counterevidence_ids = BTreeSet::new();
    let mut seen_event_ids = BTreeSet::new();
    let mut seen_seeds = BTreeSet::new();
    let mut seen_scope_ids = BTreeSet::new();
    let mut seen_source_refs = BTreeSet::new();
    for case in &dataset.cases {
        validate_case(
            case,
            &dataset.world.observation_window,
            &mut seen_claim_ids,
            &mut seen_counterevidence_ids,
            &mut seen_event_ids,
            &mut seen_seeds,
            &mut seen_scope_ids,
            &mut seen_source_refs,
        )?;
    }
    Ok(())
}

fn validate_provenance(provenance: &crate::model::Provenance) -> Result<()> {
    ensure!(
        provenance.kind == "synthetic_authored"
            && provenance.source == "synthetic-authored-for-github-issue-43"
            && provenance.license == "CC0-1.0"
            && !provenance.private_provider_data
            && !provenance.customer_data
            && !provenance.credential_data,
        "dataset provenance or data classification drift"
    );
    Ok(())
}

fn validate_world(world: &crate::model::WorldScope) -> Result<()> {
    ensure!(
        world.market == EXPECTED_MARKET
            && world.locale == EXPECTED_LOCALE
            && world.currency == EXPECTED_CURRENCY,
        "dataset market/locale/currency scope drift"
    );
    validate_exact_window(&world.observation_window, "world observation window")?;
    Ok(())
}

fn validate_isolation(isolation: &crate::model::IsolationPolicy) -> Result<()> {
    ensure!(
        isolation.execution_mode == EXECUTION_MODE
            && isolation.partition_visibility == "target_optimizer"
            && isolation.network_policy == "deny_by_default"
            && isolation.private_content_policy == "no_private_provider_content"
            && !isolation.native_execution_allowed
            && !isolation.production_writes_allowed
            && isolation.native_receipt_count == 0
            && isolation.release_decision == RELEASE_DECISION
            && !isolation.contains_customer_data
            && !isolation.contains_credentials
            && !isolation.contains_private_provider_data,
        "dataset isolation policy drift"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_case(
    case: &ReplayCase,
    world_window: &ObservationWindow,
    seen_claim_ids: &mut BTreeSet<String>,
    seen_counterevidence_ids: &mut BTreeSet<String>,
    seen_event_ids: &mut BTreeSet<String>,
    seen_seeds: &mut BTreeSet<String>,
    seen_scope_ids: &mut BTreeSet<String>,
    seen_source_refs: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(
        case.case_version == 1,
        "case {} version drift",
        case.case_id
    );
    ensure!(
        seen_seeds.insert(case.deterministic_seed.clone()),
        "deterministic seed is reused across cases"
    );
    validate_scope(&case.case_id, &case.scope, seen_scope_ids)?;
    ensure!(
        case.observation_window == *world_window,
        "case {} observation window drift",
        case.case_id
    );
    validate_exact_window(
        &case.observation_window,
        &format!("case {} observation window", case.case_id),
    )?;
    validate_goal(&case.goal, &case.case_id)?;
    ensure!(
        case.claims.len() == 4 && case.counterevidence.len() == 4,
        "case {} must have four claims and four counterevidence records",
        case.case_id
    );

    let mut claims_by_id = BTreeMap::new();
    for claim in &case.claims {
        validate_claim(
            claim,
            &case.case_id,
            &case.observation_window,
            seen_claim_ids,
            seen_source_refs,
        )?;
        claims_by_id.insert(claim.claim_id.clone(), claim);
    }

    let mut counterevidence_by_id = BTreeMap::new();
    for counterevidence in &case.counterevidence {
        validate_counterevidence(
            counterevidence,
            &case.case_id,
            &case.observation_window,
            &claims_by_id,
            seen_counterevidence_ids,
            seen_source_refs,
        )?;
        counterevidence_by_id.insert(counterevidence.counterevidence_id.clone(), counterevidence);
    }

    for claim in &case.claims {
        ensure!(
            claim.counterevidence_ids.len() == 1,
            "claim {} must bind exactly one counterevidence record",
            claim.claim_id
        );
        let counter_id = &claim.counterevidence_ids[0];
        let counter = counterevidence_by_id.get(counter_id).with_context(|| {
            format!(
                "claim {} references missing counterevidence",
                claim.claim_id
            )
        })?;
        ensure!(
            counter.claim_id == claim.claim_id,
            "claim {} counterevidence ownership drift",
            claim.claim_id
        );
    }

    validate_timeline(
        &case.case_id,
        &case.observation_window,
        &case.timeline,
        seen_event_ids,
    )?;
    validate_expected(
        &case.case_id,
        &case.expected,
        &claims_by_id,
        &counterevidence_by_id,
    )?;
    Ok(())
}

fn validate_scope(
    case_id: &str,
    scope: &CaseScope,
    seen_scope_ids: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(
        scope.tenant_id == format!("sim-tenant-{case_id}")
            && scope.project_id == format!("sim-project-{case_id}")
            && scope.mission_id == EXPECTED_MISSION_ID
            && scope.market == EXPECTED_MARKET
            && scope.locale == EXPECTED_LOCALE
            && scope.currency == EXPECTED_CURRENCY,
        "case {case_id} tenant/project/mission/market/locale/currency scope drift"
    );
    ensure!(
        seen_scope_ids.insert(scope.tenant_id.clone())
            && seen_scope_ids.insert(scope.project_id.clone()),
        "case {case_id} scope id is reused across cases"
    );
    Ok(())
}

fn validate_goal(goal: &DecisionGoal, case_id: &str) -> Result<()> {
    ensure!(
        goal.mode == "one_off_decision"
            && goal.budget_minor > 0
            && goal.currency == EXPECTED_CURRENCY
            && goal
                .forbidden_channels
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(EXPECTED_FORBIDDEN_CHANNELS),
        "case {case_id} goal mode/budget/currency/forbidden-channel drift"
    );
    validate_public_text(&goal.statement, &format!("case {case_id} goal"))?;
    Ok(())
}

fn validate_claim(
    claim: &Claim,
    case_id: &str,
    window: &ObservationWindow,
    seen_claim_ids: &mut BTreeSet<String>,
    seen_source_refs: &mut BTreeSet<String>,
) -> Result<()> {
    let key = claim_key(&claim.claim_id, case_id, "claim")?;
    let (expected_source, expected_classification, expected_uncertainty) =
        expected_claim_contract(case_id, key)?;
    ensure!(
        claim.source_kind == expected_source
            && claim.classification == expected_classification
            && claim.uncertainty == expected_uncertainty,
        "claim {} source-kind/classification/uncertainty drift",
        claim.claim_id
    );
    ensure!(
        claim.predicate == expected_predicate(key),
        "claim {} predicate drift",
        claim.claim_id
    );
    ensure!(
        claim.subject == format!("sim://{case_id}/product/mxzone-shark-filter"),
        "claim {} subject scope drift",
        claim.claim_id
    );
    ensure!(
        seen_claim_ids.insert(claim.claim_id.clone()),
        "claim id {} is reused across cases",
        claim.claim_id
    );
    validate_source_ref(case_id, &claim.source_ref, seen_source_refs)?;
    validate_public_text(&claim.value, &format!("claim {} value", claim.claim_id))?;
    let observed_at = validate_timestamp_in_window(
        &claim.observed_at,
        window,
        &format!("claim {} observedAt", claim.claim_id),
    )?;
    let valid_from = validate_timestamp_in_window(
        &claim.valid_from,
        window,
        &format!("claim {} validFrom", claim.claim_id),
    )?;
    ensure!(
        valid_from <= observed_at,
        "claim {} validFrom is after observedAt",
        claim.claim_id
    );
    let valid_until = claim
        .valid_until
        .as_deref()
        .with_context(|| format!("claim {} must have validUntil", claim.claim_id))?;
    let valid_until = validate_timestamp_in_window(
        valid_until,
        window,
        &format!("claim {} validUntil", claim.claim_id),
    )?;
    ensure!(
        valid_until >= observed_at,
        "claim {} validUntil is before observedAt",
        claim.claim_id
    );
    Ok(())
}

fn validate_counterevidence(
    counterevidence: &Counterevidence,
    case_id: &str,
    window: &ObservationWindow,
    claims_by_id: &BTreeMap<String, &Claim>,
    seen_counterevidence_ids: &mut BTreeSet<String>,
    seen_source_refs: &mut BTreeSet<String>,
) -> Result<()> {
    let key = claim_key(&counterevidence.counterevidence_id, case_id, "counter")?;
    let (expected_classification, expected_uncertainty) = expected_counter_contract(case_id, key)?;
    ensure!(
        counterevidence.source_kind == SourceKind::SyntheticCounterevidence
            && counterevidence.classification == expected_classification
            && counterevidence.uncertainty == expected_uncertainty,
        "counterevidence {} source-kind/classification/uncertainty drift",
        counterevidence.counterevidence_id
    );
    let claim = claims_by_id
        .get(&counterevidence.claim_id)
        .with_context(|| {
            format!(
                "counterevidence {} references a missing claim",
                counterevidence.counterevidence_id
            )
        })?;
    ensure!(
        counterevidence.subject == claim.subject && counterevidence.predicate == claim.predicate,
        "counterevidence {} claim scope drift",
        counterevidence.counterevidence_id
    );
    ensure!(
        seen_counterevidence_ids.insert(counterevidence.counterevidence_id.clone()),
        "counterevidence id {} is reused across cases",
        counterevidence.counterevidence_id
    );
    validate_source_ref(case_id, &counterevidence.source_ref, seen_source_refs)?;
    validate_public_text(
        &counterevidence.value,
        &format!(
            "counterevidence {} value",
            counterevidence.counterevidence_id
        ),
    )?;
    validate_timestamp_in_window(
        &counterevidence.observed_at,
        window,
        &format!(
            "counterevidence {} observedAt",
            counterevidence.counterevidence_id
        ),
    )?;
    Ok(())
}

fn validate_timeline(
    case_id: &str,
    window: &ObservationWindow,
    timeline: &[TimelineEvent],
    seen_event_ids: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(
        timeline.len() == 3,
        "case {case_id} must have exactly three deterministic timeline events"
    );
    let mut kinds = BTreeSet::new();
    for event in timeline {
        ensure!(
            event.event_id.starts_with(&format!("{case_id}.event.")),
            "timeline event {} crosses case scope",
            event.event_id
        );
        ensure!(
            seen_event_ids.insert(event.event_id.clone()),
            "timeline event {} is reused across cases",
            event.event_id
        );
        ensure!(
            matches!(
                event.kind.as_str(),
                "context_confirmed" | "evidence_collected" | "decision_ready"
            ),
            "timeline event {} has an unsupported kind",
            event.event_id
        );
        ensure!(
            kinds.insert(event.kind.as_str()),
            "timeline event kind is duplicated"
        );
        validate_timestamp_in_window(
            &event.at,
            window,
            &format!("timeline event {} at", event.event_id),
        )?;
    }
    ensure!(
        kinds == BTreeSet::from(["context_confirmed", "evidence_collected", "decision_ready"]),
        "case {case_id} timeline stages drift"
    );
    Ok(())
}

fn validate_expected(
    case_id: &str,
    expected: &ExpectedDecision,
    claims_by_id: &BTreeMap<String, &Claim>,
    counterevidence_by_id: &BTreeMap<String, &Counterevidence>,
) -> Result<()> {
    let claim_ids = expected
        .required_claim_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let counter_ids = expected
        .required_counterevidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        claim_ids == claims_by_id.keys().map(String::as_str).collect(),
        "case {case_id} expected claim scope drift"
    );
    ensure!(
        counter_ids == counterevidence_by_id.keys().map(String::as_str).collect(),
        "case {case_id} expected counterevidence scope drift"
    );
    ensure!(
        expected.separates_classifications.len() == EXPECTED_CLASSIFICATIONS.len()
            && expected
                .separates_classifications
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                == EXPECTED_CLASSIFICATIONS.into_iter().collect(),
        "case {case_id} classification separation contract drift"
    );
    ensure!(
        expected
            .forbidden_effects
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == BTreeSet::from(EXPECTED_FORBIDDEN_EFFECTS),
        "case {case_id} forbidden effect scope drift"
    );
    validate_public_text(
        &expected.decision_basis,
        &format!("case {case_id} decision basis"),
    )?;
    Ok(())
}

fn claim_key<'a>(id: &'a str, case_id: &str, kind: &str) -> Result<&'a str> {
    id.strip_prefix(&format!("{case_id}.{kind}."))
        .with_context(|| format!("{kind} id {id} is outside case {case_id}"))
}

fn expected_predicate(key: &str) -> &str {
    match key {
        "demand" => "estimated_de_demand_index",
        "compatibility" => "compatibility_with_shark_nv360",
        "ai-visibility" => "ai_recommendation_visibility",
        "competitor-gap" => "competitive_gap",
        "compliance" => "launch_compliance_readiness",
        "pilot" => "controlled_pilot_feasibility",
        _ => "",
    }
}

fn expected_claim_contract(
    case_id: &str,
    key: &str,
) -> Result<(SourceKind, ClaimClassification, Uncertainty)> {
    let contract = match key {
        "demand" => (
            SourceKind::MarketplaceEstimate,
            ClaimClassification::ProviderEstimate,
            if case_id == EXPECTED_CASE_IDS[2] {
                Uncertainty::Low
            } else {
                Uncertainty::Medium
            },
        ),
        "compatibility" => (
            SourceKind::PublicSearchSnapshot,
            ClaimClassification::ConfirmedFact,
            Uncertainty::Low,
        ),
        "ai-visibility" => (
            SourceKind::AiGroundTruthSimulator,
            ClaimClassification::Unknown,
            if case_id == EXPECTED_CASE_IDS[2] {
                Uncertainty::Medium
            } else {
                Uncertainty::Unknown
            },
        ),
        "competitor-gap" | "compliance" => (
            SourceKind::CompetitorPublicSnapshot,
            ClaimClassification::AgentInference,
            Uncertainty::High,
        ),
        "pilot" => (
            SourceKind::CompetitorPublicSnapshot,
            ClaimClassification::AgentInference,
            Uncertainty::Medium,
        ),
        _ => return Err(anyhow::anyhow!("unsupported claim key {key}")),
    };
    Ok(contract)
}

fn expected_counter_contract(
    case_id: &str,
    key: &str,
) -> Result<(ClaimClassification, Uncertainty)> {
    let contract = match key {
        "demand" if case_id == EXPECTED_CASE_IDS[0] => {
            (ClaimClassification::ProviderEstimate, Uncertainty::Medium)
        }
        "demand" | "competitor-gap" | "compliance" => {
            (ClaimClassification::ConfirmedFact, Uncertainty::Low)
        }
        "compatibility" if case_id == EXPECTED_CASE_IDS[2] => {
            (ClaimClassification::ConfirmedFact, Uncertainty::Low)
        }
        "compatibility" => (ClaimClassification::Unknown, Uncertainty::High),
        "ai-visibility" if case_id == EXPECTED_CASE_IDS[2] => {
            (ClaimClassification::ProviderEstimate, Uncertainty::Medium)
        }
        "ai-visibility" => (ClaimClassification::ProviderEstimate, Uncertainty::High),
        "pilot" => (ClaimClassification::AgentInference, Uncertainty::Medium),
        _ => return Err(anyhow::anyhow!("unsupported counterevidence key {key}")),
    };
    Ok(contract)
}

fn validate_source_ref(
    case_id: &str,
    source_ref: &str,
    seen_source_refs: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(
        source_ref.starts_with(&format!("sim-source://{case_id}/")),
        "source reference {source_ref} crosses case scope or is not simulator-only"
    );
    ensure!(
        seen_source_refs.insert(source_ref.to_owned()),
        "source reference {source_ref} is reused across cases"
    );
    Ok(())
}

fn validate_exact_window(window: &ObservationWindow, label: &str) -> Result<()> {
    ensure!(
        window.start == EXPECTED_START
            && window.end == EXPECTED_END
            && window.time_zone == EXPECTED_TIME_ZONE,
        "{label} drift"
    );
    let start = parse_timestamp(&window.start, &format!("{label} start"))?;
    let end = parse_timestamp(&window.end, &format!("{label} end"))?;
    ensure!(start < end, "{label} must have a positive duration");
    Ok(())
}

fn validate_timestamp_in_window(
    raw: &str,
    window: &ObservationWindow,
    label: &str,
) -> Result<DateTime<Utc>> {
    let timestamp = parse_timestamp(raw, label)?;
    let start = parse_timestamp(&window.start, &format!("{label} window start"))?;
    let end = parse_timestamp(&window.end, &format!("{label} window end"))?;
    ensure!(
        timestamp >= start && timestamp <= end,
        "{label} is outside the deterministic observation window"
    );
    Ok(timestamp)
}

fn parse_timestamp(raw: &str, label: &str) -> Result<DateTime<Utc>> {
    let parsed =
        DateTime::parse_from_rfc3339(raw).with_context(|| format!("{label} is not RFC3339"))?;
    ensure!(
        parsed.to_rfc3339_opts(SecondsFormat::Secs, true) == raw,
        "{label} must use canonical UTC second precision"
    );
    Ok(parsed.with_timezone(&Utc))
}

fn validate_public_text(value: &str, label: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    for marker in [
        "access_token",
        "refresh_token",
        "password",
        "cookie",
        "credential",
        "secret",
        "http://",
        "https://",
        "@",
    ] {
        ensure!(
            !lower.contains(marker),
            "{label} contains a secret, private-provider or direct-contact marker"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EXPECTED_CASE_IDS, EXPECTED_START, replay_digest, validate_contracts,
        validate_dataset_contract, validate_registry_binding,
    };
    use crate::digest::sha256_hex;
    use crate::model::{ClaimClassification, Dataset, DatasetBinding, parse_strict_json};

    const DATASET_BYTES: &[u8] =
        include_bytes!("../../../../contracts/datasets/gm01-de-market-replay-v1.json");
    const REGISTRY_BYTES: &[u8] = include_bytes!("../../../../contracts/datasets/registry.v1.json");

    fn dataset() -> Dataset {
        parse_strict_json(DATASET_BYTES).expect("fixture dataset")
    }

    fn binding() -> DatasetBinding {
        let registry: crate::model::DatasetRegistryDocument =
            parse_strict_json(REGISTRY_BYTES).expect("fixture registry");
        registry
            .dataset_bindings
            .into_iter()
            .next()
            .expect("binding")
    }

    #[test]
    fn repository_fixture_validates_as_simulator_replay_only() {
        let report = validate_contracts(DATASET_BYTES, REGISTRY_BYTES).expect("valid fixture");
        assert_eq!(report.execution_mode, "SIMULATOR/REPLAY_ONLY");
        assert_eq!(report.native_receipt_count, 0);
        assert_eq!(report.release_decision, "NOT_EVALUATED");
        assert_eq!(report.case_count, EXPECTED_CASE_IDS.len());
        assert_eq!(report.raw_dataset_digest, sha256_hex(DATASET_BYTES));
    }

    #[test]
    fn raw_registry_binding_rejects_dataset_digest_drift() {
        let dataset = dataset();
        let mut binding = binding();
        binding.raw_digest = "00".repeat(32);
        let error = validate_registry_binding(&binding, &dataset, &sha256_hex(DATASET_BYTES))
            .expect_err("digest drift must fail closed");
        assert!(error.to_string().contains("raw digest drift"));
    }

    #[test]
    fn split_mutation_is_rejected() {
        let mut dataset = dataset();
        dataset.split = "V1".to_owned();
        let error = validate_dataset_contract(&dataset).expect_err("split drift must fail closed");
        assert!(error.to_string().contains("partition/split"));
    }

    #[test]
    fn scope_mutation_is_rejected() {
        let mut dataset = dataset();
        dataset.cases[0].scope.market = "US".to_owned();
        let error = validate_dataset_contract(&dataset).expect_err("scope drift must fail closed");
        assert!(error.to_string().contains("scope drift"));
    }

    #[test]
    fn time_mutation_is_rejected() {
        let mut dataset = dataset();
        dataset.cases[0].claims[0].observed_at = "2026-08-01T00:00:00Z".to_owned();
        dataset.cases[0].claims[0].valid_from = EXPECTED_START.to_owned();
        let error = validate_dataset_contract(&dataset).expect_err("time drift must fail closed");
        assert!(error.to_string().contains("observedAt"));
    }

    #[test]
    fn classification_mutation_is_rejected() {
        let mut dataset = dataset();
        dataset.cases[0].claims[0].classification = ClaimClassification::ConfirmedFact;
        let error =
            validate_dataset_contract(&dataset).expect_err("classification drift must fail closed");
        assert!(error.to_string().contains("classification"));
    }

    #[test]
    fn cross_case_claim_id_drift_is_rejected() {
        let mut dataset = dataset();
        dataset.cases[1].claims[0].claim_id = dataset.cases[0].claims[0].claim_id.clone();
        let error = validate_dataset_contract(&dataset)
            .expect_err("cross-case claim leakage must fail closed");
        assert!(error.to_string().contains("outside case"));
    }

    #[test]
    fn key_claim_mutation_changes_replay_digest() {
        let mut mutated = dataset();
        let original = replay_digest(&mutated).expect("original digest");
        mutated.cases[0].claims[0].value = "0.63 synthetic normalized demand index".to_owned();
        let changed = replay_digest(&mutated).expect("mutated digest");
        assert_ne!(original, changed);
    }

    #[test]
    fn counterevidence_mutation_changes_replay_digest() {
        let mut mutated = dataset();
        let original = replay_digest(&mutated).expect("original digest");
        mutated.cases[1].counterevidence[0].value =
            "synthetic category demand is above the decision threshold".to_owned();
        let changed = replay_digest(&mutated).expect("mutated digest");
        assert_ne!(original, changed);
    }
}
