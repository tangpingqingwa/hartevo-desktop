use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::digest::{digest_json, is_lower_hex, sha256_hex};
use crate::model::{
    AdoptionDecision, AdoptionRecord, CapabilityInvocation, ComponentMode, CredentialStatus,
    DurableLog, DurableLogEntry, EffectReceipt, EffectStatus, EffectVerification,
    EvidenceProvenance, InvocationStatus, LogEntryKind, MissionComposition, MissionScope,
    ModelPlugin, Objective, OracleReport, OracleStatus, PluginNativeJourney, ProjectScope,
    ProviderBinding, RecoveryHook, RecoveryReceipt, RecoveryStatus, ResultStatus, RuntimePlugin,
    SelectedResult, ServiceBinding, SessionScope, VerificationStatus,
};

pub const CONTRACT_PATH: &str = "contracts/plugins/plugin-native-journey.v1.json";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.plugin-native-journey/v1";
pub const DOCUMENT_TYPE: &str = "plugin_native_journey";
pub const AUTHORITY: &str = "plugin_native_journey_oracle_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-plugin-native-journey-report/v1";

const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/plugins/plugin-native-journey.v1.json");
const REQUIRED_LOG_KINDS: [LogEntryKind; 4] = [
    LogEntryKind::Objective,
    LogEntryKind::MissionComposition,
    LogEntryKind::Invocation,
    LogEntryKind::Result,
];
const REQUIRED_RECOVERY: [RecoveryHook; 4] = [
    RecoveryHook::Unmount,
    RecoveryHook::Revoke,
    RecoveryHook::Crash,
    RecoveryHook::Relaunch,
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeMaterial<'a> {
    project_id: &'a str,
    project_revision: u64,
    project_scope_digest: &'a str,
    mission_id: &'a str,
    mission_revision: u64,
    mission_scope_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectiveMaterial<'a> {
    id: &'a str,
    text: &'a str,
    constraints_digest: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompositionMaterial<'a> {
    objective_id: &'a str,
    objective_digest: &'a str,
    mission_id: &'a str,
    revision: u64,
    source_commit: &'a str,
    scope: &'a SessionScope,
    capability_set_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeMaterial<'a> {
    id: &'a str,
    revision: u64,
    source_commit: &'a str,
    scope: &'a SessionScope,
    mode: ComponentMode,
    mounted: bool,
    unmounted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModelMaterial<'a> {
    id: &'a str,
    provider: &'a str,
    model: &'a str,
    revision: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
    mode: ComponentMode,
    credentials: CredentialStatus,
    artifact_digest: &'a str,
    output_present: bool,
    output_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderMaterial<'a> {
    id: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
    mode: ComponentMode,
    model_digest: &'a str,
    output_present: bool,
    output_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvocationMaterial<'a> {
    sequence: u64,
    capability: &'a str,
    plugin_id: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
    objective_digest: &'a str,
    composition_digest: &'a str,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogMaterial<'a> {
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    entries: Vec<&'a DurableLogEntry>,
    durable: bool,
    model_visible: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMaterial {
    sequence: u64,
    status: VerificationStatus,
    verified_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectMaterial<'a> {
    sequence: u64,
    effect_id: &'a str,
    capability: &'a str,
    plugin_id: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
    requested_at: DateTime<Utc>,
    receipt_at: DateTime<Utc>,
    status: EffectStatus,
    verification: &'a EffectVerification,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultMaterial<'a> {
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    status: ResultStatus,
    provenance: EvidenceProvenance,
    evidence_root: &'a str,
    selected_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptionMaterial<'a> {
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    decision: AdoptionDecision,
    result_digest: &'a str,
    evidence_root: &'a str,
    adopted_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryMaterial<'a> {
    sequence: u64,
    hook: RecoveryHook,
    status: RecoveryStatus,
    source_commit: &'a str,
    scope: &'a SessionScope,
    occurred_at: DateTime<Utc>,
    old_plugin_accepted: bool,
    old_decision_promotable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultEvidenceMaterial<'a> {
    log_digest: &'a str,
    effect_digests: Vec<&'a str>,
    provider_output_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JourneyEvidenceMaterial<'a> {
    source_commit: &'a str,
    journey_id: &'a str,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    objective: &'a Objective,
    composition: &'a MissionComposition,
    runtime_plugin: &'a RuntimePlugin,
    model_plugin: &'a ModelPlugin,
    service: &'a ServiceBinding,
    provider: &'a ProviderBinding,
    consumer: &'a crate::model::ConsumerBinding,
    invocations: &'a [CapabilityInvocation],
    durable_log: &'a DurableLog,
    effects: &'a [EffectReceipt],
    selected_result: &'a SelectedResult,
    adoption: &'a AdoptionRecord,
    recovery: &'a [RecoveryReceipt],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayMaterial<'a> {
    source_commit: &'a str,
    journey_id: &'a str,
    evidence_root: &'a str,
    oracle_status: OracleStatus,
    native_pass: bool,
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
}

pub fn current_source_commit() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .context("invoke Git for current source commit")?;
    ensure!(
        output.status.success(),
        "Git cannot resolve current source commit"
    );
    let commit = String::from_utf8(output.stdout)
        .context("Git returned non-UTF-8 commit")?
        .trim()
        .to_owned();
    validate_commit(&commit)?;
    Ok(commit)
}

pub fn read_journey(path: impl AsRef<Path>) -> Result<PluginNativeJourney> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("read plugin journey {}", path.display()))?;
    crate::model::parse_strict_json(&bytes)
        .with_context(|| format!("parse strict plugin journey {}", path.display()))
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES)
        .context("plugin journey contract is not strict JSON")?;
    validate_contract_root(&contract)?;
    validate_contract_definitions(&contract)
}

fn validate_contract_root(contract: &Value) -> Result<()> {
    ensure!(
        contract.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
            && contract.get("$id").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION)
            && contract.get("type").and_then(Value::as_str) == Some("object")
            && contract
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false),
        "plugin journey contract root drifted"
    );
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "journeyId",
        "project",
        "mission",
        "objective",
        "composition",
        "runtimePlugin",
        "modelPlugin",
        "service",
        "provider",
        "consumer",
        "invocations",
        "durableLog",
        "effects",
        "selectedResult",
        "adoption",
        "recovery",
        "evidenceRoot",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let required = exact_string_set(contract.get("required").context("journey required")?)?;
    ensure!(required == expected, "journey required set drifted");
    let properties = contract
        .get("properties")
        .and_then(Value::as_object)
        .context("journey properties")?;
    ensure!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "journey property set drifted"
    );
    for (name, constant) in [
        ("schemaVersion", CONTRACT_SCHEMA_VERSION),
        ("documentType", DOCUMENT_TYPE),
        ("authority", AUTHORITY),
        ("releaseDecision", RELEASE_DECISION),
    ] {
        ensure!(
            properties
                .get(name)
                .and_then(|value| value.get("const"))
                .and_then(Value::as_str)
                == Some(constant),
            "journey constant {name} drifted"
        );
    }
    Ok(())
}

fn validate_contract_definitions(contract: &Value) -> Result<()> {
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("journey definitions")?;
    let expected = [
        "adoption",
        "composition",
        "consumer",
        "durableLog",
        "durableLogEntry",
        "effect",
        "effectVerification",
        "invocation",
        "mission",
        "modelPlugin",
        "objective",
        "project",
        "provider",
        "recovery",
        "runtimePlugin",
        "scope",
        "selectedResult",
        "service",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        defs.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "journey definition set drifted"
    );
    for (name, definition) in defs {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "journey definition {name} is not closed"
        );
        let properties = definition
            .get("properties")
            .and_then(Value::as_object)
            .with_context(|| format!("journey definition {name} properties"))?;
        let required = exact_string_set(
            definition
                .get("required")
                .with_context(|| format!("journey definition {name} required"))?,
        )?;
        ensure!(
            required == properties.keys().map(String::as_str).collect(),
            "journey definition {name} required/property set drifted"
        );
    }
    Ok(())
}

pub fn validate_journey(
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<OracleReport> {
    validate_commit(expected_source_commit)?;
    validate_envelope(journey, expected_source_commit)?;
    validate_scope_identity(journey)?;
    validate_objective(&journey.objective, journey, expected_source_commit)?;
    validate_composition(&journey.composition, journey, expected_source_commit)?;
    validate_components(journey, expected_source_commit)?;
    validate_invocations(&journey.invocations, journey, expected_source_commit)?;
    validate_log(&journey.durable_log, journey, expected_source_commit)?;
    validate_effects(
        &journey.effects,
        &journey.invocations,
        journey,
        expected_source_commit,
    )?;
    validate_result_and_adoption(journey, expected_source_commit)?;
    validate_recovery(&journey.recovery, journey, expected_source_commit)?;
    ensure!(
        journey.evidence_root == expected_evidence_root(journey)?,
        "journey evidence root is not derived from all evidence"
    );
    let native_pass = native_candidate(journey);
    let oracle_status = if native_pass {
        OracleStatus::NativePass
    } else if has_blocked_component(journey) {
        OracleStatus::BlockedEnv
    } else {
        OracleStatus::NotEvaluated
    };
    let replay_digest = digest_json(
        "hartevo-plugin-native-journey-replay/v1",
        &ReplayMaterial {
            source_commit: expected_source_commit,
            journey_id: &journey.journey_id,
            evidence_root: &journey.evidence_root,
            oracle_status,
            native_pass,
        },
    )?;
    Ok(OracleReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        oracle_status,
        native_pass,
        source_commit: expected_source_commit.into(),
        journey_id: journey.journey_id.clone(),
        project_id: journey.project.id.clone(),
        mission_id: journey.mission.id.clone(),
        evidence_root: journey.evidence_root.clone(),
        replay_digest,
        invocation_count: journey.invocations.len(),
        effect_count: journey.effects.len(),
        recovery_count: journey.recovery.len(),
        missing_reasons: missing_reasons(journey),
    })
}

fn validate_envelope(journey: &PluginNativeJourney, expected_source_commit: &str) -> Result<()> {
    ensure!(
        journey.schema_version == CONTRACT_SCHEMA_VERSION
            && journey.document_type == DOCUMENT_TYPE
            && journey.authority == AUTHORITY
            && journey.release_decision == RELEASE_DECISION
            && journey.source_commit == expected_source_commit,
        "journey envelope is stale or has invalid constants"
    );
    validate_commit(&journey.source_commit)?;
    validate_identifier(&journey.journey_id, "journey id")?;
    validate_digest(&journey.evidence_root, "journey evidence root")?;
    Ok(())
}

fn validate_scope_identity(journey: &PluginNativeJourney) -> Result<()> {
    validate_identifier(&journey.project.id, "Project id")?;
    validate_identifier(&journey.mission.id, "Mission id")?;
    ensure!(journey.project.revision > 0 && journey.mission.revision > 0);
    validate_digest(&journey.project.scope_digest, "Project scope digest")?;
    validate_digest(&journey.mission.scope_digest, "Mission scope digest")?;
    let expected = expected_scope_digest(journey);
    for scope in all_scopes(journey) {
        ensure!(
            scope.project_id == journey.project.id
                && scope.mission_id == journey.mission.id
                && scope.scope_digest == expected,
            "Project/Mission scope binding drifted"
        );
    }
    Ok(())
}

fn validate_objective(
    objective: &Objective,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&objective.id, "objective id")?;
    ensure!(!objective.text.trim().is_empty());
    ensure!(objective.source_commit == expected_source_commit);
    ensure_scope(&objective.scope, journey)?;
    validate_digest(&objective.constraints_digest, "constraints digest")?;
    validate_digest(&objective.digest, "objective digest")?;
    ensure!(
        objective.digest == expected_objective_digest(objective)?,
        "objective digest is not derived from objective and constraints"
    );
    Ok(())
}

fn validate_composition(
    composition: &MissionComposition,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        composition.objective_id == journey.objective.id
            && composition.mission_id == journey.mission.id
            && composition.revision == journey.mission.revision
            && composition.source_commit == expected_source_commit,
        "Mission composition identity drifted"
    );
    ensure_scope(&composition.scope, journey)?;
    validate_digest(&composition.capability_set_digest, "capability set digest")?;
    validate_digest(&composition.composition_digest, "composition digest")?;
    ensure!(
        composition.composition_digest
            == expected_composition_digest(composition, &journey.objective.digest)?,
        "Mission composition digest is not derived from objective and capability set"
    );
    Ok(())
}

fn validate_components(journey: &PluginNativeJourney, expected_source_commit: &str) -> Result<()> {
    validate_runtime_plugin(&journey.runtime_plugin, journey, expected_source_commit)?;
    validate_model_plugin(&journey.model_plugin, journey, expected_source_commit)?;
    validate_service(&journey.service, journey, expected_source_commit)?;
    validate_provider(&journey.provider, journey, expected_source_commit)?;
    validate_consumer(&journey.consumer, journey, expected_source_commit)?;
    ensure!(
        journey.runtime_plugin.mode == journey.model_plugin.mode
            && journey.model_plugin.mode == journey.service.mode
            && journey.service.mode == journey.provider.mode,
        "runtime/model/service/provider component modes diverge"
    );
    Ok(())
}

fn validate_runtime_plugin(
    runtime: &RuntimePlugin,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&runtime.id, "runtime plugin id")?;
    ensure!(runtime.revision > 0 && runtime.source_commit == expected_source_commit);
    ensure_scope(&runtime.scope, journey)?;
    validate_digest(&runtime.plugin_digest, "runtime plugin digest")?;
    ensure!(
        runtime.plugin_digest == expected_runtime_digest(runtime)?,
        "runtime plugin digest drifted"
    );
    if runtime.mode == ComponentMode::Native {
        ensure!(runtime.mounted && runtime.unmounted);
    }
    Ok(())
}

fn validate_model_plugin(
    model: &ModelPlugin,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    for (value, label) in [
        (&model.id, "model plugin id"),
        (&model.provider, "model provider"),
        (&model.model, "model name"),
        (&model.revision, "model revision"),
    ] {
        validate_identifier(value, label)?;
    }
    ensure!(model.source_commit == expected_source_commit);
    ensure_scope(&model.scope, journey)?;
    validate_digest(&model.model_digest, "model digest")?;
    if !model.artifact_digest.is_empty() {
        validate_digest(&model.artifact_digest, "model artifact digest")?;
    }
    if model.output_present {
        validate_digest(&model.output_digest, "model output digest")?;
    } else {
        ensure!(model.output_digest.is_empty());
    }
    ensure!(
        model.model_digest == expected_model_digest(model)?,
        "model plugin digest drifted"
    );
    if model.mode == ComponentMode::Native {
        ensure!(
            model.credentials == CredentialStatus::Verified
                && model.output_present
                && !model.artifact_digest.is_empty()
        );
    } else {
        ensure!(model.credentials != CredentialStatus::Verified);
    }
    Ok(())
}

fn validate_service(
    service: &ServiceBinding,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&service.id, "service id")?;
    ensure!(service.source_commit == expected_source_commit && service.mounted);
    ensure_scope(&service.scope, journey)?;
    validate_digest(&service.durable_log_digest, "service durable log digest")?;
    ensure!(service.durable_log_digest == journey.durable_log.log_digest);
    Ok(())
}

fn validate_provider(
    provider: &ProviderBinding,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&provider.id, "provider id")?;
    ensure!(provider.source_commit == expected_source_commit);
    ensure_scope(&provider.scope, journey)?;
    ensure!(provider.model_digest == journey.model_plugin.model_digest);
    validate_digest(&provider.provider_digest, "provider digest")?;
    if provider.output_present {
        validate_digest(&provider.output_digest, "provider output digest")?;
    } else {
        ensure!(provider.output_digest.is_empty());
    }
    ensure!(
        provider.provider_digest == expected_provider_digest(provider)?,
        "provider digest drifted"
    );
    if provider.mode == ComponentMode::Native {
        ensure!(provider.output_present && !provider.output_digest.is_empty());
    }
    Ok(())
}

fn validate_consumer(
    consumer: &crate::model::ConsumerBinding,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&consumer.id, "consumer id")?;
    ensure!(consumer.source_commit == expected_source_commit);
    ensure_scope(&consumer.scope, journey)?;
    validate_digest(&consumer.selected_result_digest, "selected result digest")?;
    ensure!(consumer.selected_result_digest == journey.selected_result.result_digest);
    Ok(())
}

fn validate_invocations(
    invocations: &[CapabilityInvocation],
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(!invocations.is_empty());
    let mut capabilities = BTreeSet::new();
    for (index, invocation) in invocations.iter().enumerate() {
        ensure!(
            invocation.sequence == index as u64 + 1
                && invocation.source_commit == expected_source_commit
                && invocation.plugin_id == journey.runtime_plugin.id
                && invocation.status == InvocationStatus::Completed
        );
        validate_identifier(&invocation.capability, "capability id")?;
        ensure!(capabilities.insert(invocation.capability.as_str()));
        ensure_scope(&invocation.scope, journey)?;
        validate_digest(&invocation.request_digest, "invocation request digest")?;
        validate_digest(&invocation.response_digest, "invocation response digest")?;
        if journey.model_plugin.output_present && journey.provider.output_present {
            ensure!(
                invocation.response_digest == journey.model_plugin.output_digest
                    && invocation.response_digest == journey.provider.output_digest,
                "invocation response is not bound to the native provider output"
            );
        }
        ensure!(invocation.started_at <= invocation.completed_at);
        ensure!(
            invocation.request_digest == expected_invocation_request(invocation, journey)?,
            "invocation request is not derived from objective/composition"
        );
    }
    Ok(())
}

fn validate_log(
    log: &DurableLog,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        log.source_commit == expected_source_commit
            && log.revision == journey.mission.revision
            && log.durable
            && log.model_visible
    );
    ensure_scope(&log.scope, journey)?;
    ensure!(log.entries.len() == journey.invocations.len() + 3);
    validate_digest(&log.log_digest, "durable log digest")?;
    ensure!(log.log_digest == expected_log_digest(log)?);
    let mut prior_time = None;
    for (index, entry) in log.entries.iter().enumerate() {
        ensure!(
            entry.sequence == index as u64 + 1 && entry.source_commit == expected_source_commit
        );
        ensure_scope(&entry.scope, journey)?;
        validate_digest(&entry.payload_digest, "durable log payload digest")?;
        if let Some(previous) = prior_time {
            ensure!(entry.occurred_at > previous);
        }
        prior_time = Some(entry.occurred_at);
    }
    ensure!(log.entries[0].kind == REQUIRED_LOG_KINDS[0]);
    ensure!(log.entries[0].payload_digest == journey.objective.digest);
    ensure!(log.entries[1].kind == REQUIRED_LOG_KINDS[1]);
    ensure!(log.entries[1].payload_digest == journey.composition.composition_digest);
    for (offset, invocation) in journey.invocations.iter().enumerate() {
        let entry = &log.entries[offset + 2];
        ensure!(
            entry.kind == REQUIRED_LOG_KINDS[2]
                && entry.payload_digest == invocation.request_digest
                && entry.occurred_at >= invocation.completed_at
        );
    }
    let result_entry = log.entries.last().expect("validated log entries");
    ensure!(
        result_entry.kind == REQUIRED_LOG_KINDS[3]
            && result_entry.payload_digest == journey.selected_result.result_digest
            && result_entry.occurred_at >= journey.selected_result.selected_at
    );
    Ok(())
}

fn validate_effects(
    effects: &[EffectReceipt],
    invocations: &[CapabilityInvocation],
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(effects.len() == invocations.len() && !effects.is_empty());
    let mut effect_ids = BTreeSet::new();
    for (index, (effect, invocation)) in effects.iter().zip(invocations).enumerate() {
        ensure!(
            effect.sequence == index as u64 + 1
                && effect.capability == invocation.capability
                && effect.plugin_id == invocation.plugin_id
                && effect.source_commit == expected_source_commit
                && effect.status == EffectStatus::Applied
        );
        ensure!(effect_ids.insert(effect.effect_id.as_str()));
        validate_identifier(&effect.effect_id, "effect id")?;
        ensure_scope(&effect.scope, journey)?;
        ensure!(
            effect.requested_at >= invocation.completed_at
                && effect.receipt_at >= effect.requested_at
        );
        validate_digest(&effect.receipt_digest, "effect receipt digest")?;
        ensure!(effect.receipt_digest == expected_effect_digest(effect)?);
        ensure!(
            effect.verification.sequence == effect.sequence
                && effect.verification.status == VerificationStatus::Verified
                && effect.verification.verified_at >= effect.receipt_at
        );
        validate_digest(
            &effect.verification.verification_digest,
            "effect verification digest",
        )?;
        ensure!(
            effect.verification.verification_digest
                == expected_verification_digest(&effect.verification)?,
            "effect verification digest drifted"
        );
    }
    Ok(())
}

fn validate_result_and_adoption(
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    let result = &journey.selected_result;
    ensure!(
        result.source_commit == expected_source_commit
            && result.revision == journey.mission.revision
    );
    ensure_scope(&result.scope, journey)?;
    validate_digest(&result.result_digest, "selected result digest")?;
    if result.provenance == EvidenceProvenance::Native {
        ensure!(result.status == ResultStatus::Completed);
        validate_digest(&result.evidence_root, "selected result evidence root")?;
        ensure!(result.evidence_root == expected_result_evidence_root(journey)?);
    } else {
        ensure!(result.status == ResultStatus::NotEvaluated && result.evidence_root.is_empty());
    }
    ensure!(
        result.result_digest == expected_result_digest(result)?,
        "selected result digest drifted"
    );
    ensure!(
        result.selected_at
            >= journey
                .effects
                .last()
                .expect("validated effects")
                .verification
                .verified_at
    );
    let adoption = &journey.adoption;
    ensure!(
        adoption.source_commit == expected_source_commit
            && adoption.revision == result.revision
            && adoption.result_digest == result.result_digest
            && adoption.evidence_root == result.evidence_root
            && adoption.adopted_at >= result.selected_at
    );
    ensure_scope(&adoption.scope, journey)?;
    validate_digest(&adoption.decision_digest, "adoption digest")?;
    ensure!(
        adoption.decision_digest == expected_adoption_digest(adoption)?,
        "adoption digest drifted"
    );
    let expected_decision = if result.provenance == EvidenceProvenance::Native
        && result.status == ResultStatus::Completed
    {
        AdoptionDecision::Adopt
    } else {
        AdoptionDecision::NotEvaluated
    };
    ensure!(adoption.decision == expected_decision);
    ensure!(journey.consumer.adopted == (adoption.decision == AdoptionDecision::Adopt));
    Ok(())
}

fn validate_recovery(
    recovery: &[RecoveryReceipt],
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(recovery.len() == REQUIRED_RECOVERY.len());
    let mut hooks = BTreeSet::new();
    let mut previous = journey.adoption.adopted_at;
    for (index, receipt) in recovery.iter().enumerate() {
        ensure!(
            receipt.sequence == index as u64 + 1
                && receipt.hook == REQUIRED_RECOVERY[index]
                && receipt.status == RecoveryStatus::Recovered
                && receipt.source_commit == expected_source_commit
                && !receipt.old_plugin_accepted
                && !receipt.old_decision_promotable
        );
        ensure!(hooks.insert(receipt.hook));
        ensure_scope(&receipt.scope, journey)?;
        ensure!(receipt.occurred_at > previous);
        previous = receipt.occurred_at;
        validate_digest(&receipt.receipt_digest, "recovery receipt digest")?;
        ensure!(receipt.receipt_digest == expected_recovery_digest(receipt)?);
    }
    ensure!(hooks == REQUIRED_RECOVERY.into_iter().collect());
    ensure!(journey.runtime_plugin.unmounted);
    Ok(())
}

fn native_candidate(journey: &PluginNativeJourney) -> bool {
    journey.runtime_plugin.mode == ComponentMode::Native
        && journey.model_plugin.mode == ComponentMode::Native
        && journey.service.mode == ComponentMode::Native
        && journey.provider.mode == ComponentMode::Native
        && journey.model_plugin.credentials == CredentialStatus::Verified
        && journey.model_plugin.output_present
        && journey.provider.output_present
        && journey.selected_result.status == ResultStatus::Completed
        && journey.selected_result.provenance == EvidenceProvenance::Native
        && journey.adoption.decision == AdoptionDecision::Adopt
        && journey.consumer.adopted
}

fn has_blocked_component(journey: &PluginNativeJourney) -> bool {
    [
        journey.runtime_plugin.mode,
        journey.model_plugin.mode,
        journey.service.mode,
        journey.provider.mode,
    ]
    .into_iter()
    .any(|mode| matches!(mode, ComponentMode::BlockedEnv | ComponentMode::Missing))
        || journey.model_plugin.credentials != CredentialStatus::Verified
}

fn missing_reasons(journey: &PluginNativeJourney) -> Vec<String> {
    let mut reasons = Vec::new();
    if journey.runtime_plugin.mode != ComponentMode::Native {
        reasons.push("runtime_plugin_not_native".into());
    }
    if journey.model_plugin.mode != ComponentMode::Native
        || journey.model_plugin.credentials != CredentialStatus::Verified
    {
        reasons.push("real_model_plugin_not_verified".into());
    }
    if journey.service.mode != ComponentMode::Native {
        reasons.push("service_not_native".into());
    }
    if journey.provider.mode != ComponentMode::Native || !journey.provider.output_present {
        reasons.push("provider_output_not_native".into());
    }
    if journey.selected_result.status != ResultStatus::Completed {
        reasons.push("selected_result_not_completed".into());
    }
    if journey.adoption.decision != AdoptionDecision::Adopt {
        reasons.push("adoption_not_native".into());
    }
    reasons
}

fn all_scopes(journey: &PluginNativeJourney) -> Vec<&SessionScope> {
    let mut scopes = vec![
        &journey.objective.scope,
        &journey.composition.scope,
        &journey.runtime_plugin.scope,
        &journey.model_plugin.scope,
        &journey.service.scope,
        &journey.provider.scope,
        &journey.consumer.scope,
        &journey.durable_log.scope,
        &journey.selected_result.scope,
        &journey.adoption.scope,
    ];
    scopes.extend(journey.invocations.iter().map(|item| &item.scope));
    scopes.extend(journey.durable_log.entries.iter().map(|item| &item.scope));
    scopes.extend(journey.effects.iter().map(|item| &item.scope));
    scopes.extend(journey.recovery.iter().map(|item| &item.scope));
    scopes
}

fn ensure_scope(scope: &SessionScope, journey: &PluginNativeJourney) -> Result<()> {
    ensure!(
        scope.project_id == journey.project.id
            && scope.mission_id == journey.mission.id
            && scope.scope_digest == expected_scope_digest(journey),
        "scope is not bound to Project/Mission"
    );
    Ok(())
}

fn expected_scope_digest(journey: &PluginNativeJourney) -> String {
    digest_json(
        "hartevo-plugin-native-journey-scope/v1",
        &ScopeMaterial {
            project_id: &journey.project.id,
            project_revision: journey.project.revision,
            project_scope_digest: &journey.project.scope_digest,
            mission_id: &journey.mission.id,
            mission_revision: journey.mission.revision,
            mission_scope_digest: &journey.mission.scope_digest,
        },
    )
    .expect("scope material serializes")
}

fn expected_objective_digest(objective: &Objective) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-objective/v1",
        &ObjectiveMaterial {
            id: &objective.id,
            text: &objective.text,
            constraints_digest: &objective.constraints_digest,
            source_commit: &objective.source_commit,
            scope: &objective.scope,
        },
    )
    .context("derive objective digest")
}

fn expected_composition_digest(
    composition: &MissionComposition,
    objective_digest: &str,
) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-composition/v1",
        &CompositionMaterial {
            objective_id: &composition.objective_id,
            objective_digest,
            mission_id: &composition.mission_id,
            revision: composition.revision,
            source_commit: &composition.source_commit,
            scope: &composition.scope,
            capability_set_digest: &composition.capability_set_digest,
        },
    )
    .context("derive composition digest")
}

fn expected_runtime_digest(runtime: &RuntimePlugin) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-runtime-plugin/v1",
        &RuntimeMaterial {
            id: &runtime.id,
            revision: runtime.revision,
            source_commit: &runtime.source_commit,
            scope: &runtime.scope,
            mode: runtime.mode,
            mounted: runtime.mounted,
            unmounted: runtime.unmounted,
        },
    )
    .context("derive runtime plugin digest")
}

fn expected_model_digest(model: &ModelPlugin) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-model-plugin/v1",
        &ModelMaterial {
            id: &model.id,
            provider: &model.provider,
            model: &model.model,
            revision: &model.revision,
            source_commit: &model.source_commit,
            scope: &model.scope,
            mode: model.mode,
            credentials: model.credentials,
            artifact_digest: &model.artifact_digest,
            output_present: model.output_present,
            output_digest: &model.output_digest,
        },
    )
    .context("derive model plugin digest")
}

fn expected_provider_digest(provider: &ProviderBinding) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-provider/v1",
        &ProviderMaterial {
            id: &provider.id,
            source_commit: &provider.source_commit,
            scope: &provider.scope,
            mode: provider.mode,
            model_digest: &provider.model_digest,
            output_present: provider.output_present,
            output_digest: &provider.output_digest,
        },
    )
    .context("derive provider digest")
}

fn expected_invocation_request(
    invocation: &CapabilityInvocation,
    journey: &PluginNativeJourney,
) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-invocation/v1",
        &InvocationMaterial {
            sequence: invocation.sequence,
            capability: &invocation.capability,
            plugin_id: &invocation.plugin_id,
            source_commit: &invocation.source_commit,
            scope: &invocation.scope,
            objective_digest: &journey.objective.digest,
            composition_digest: &journey.composition.composition_digest,
            started_at: invocation.started_at,
            completed_at: invocation.completed_at,
        },
    )
    .context("derive invocation request digest")
}

fn expected_log_digest(log: &DurableLog) -> Result<String> {
    let entries = log
        .entries
        .iter()
        .take(log.entries.len().saturating_sub(1))
        .collect();
    digest_json(
        "hartevo-plugin-native-journey-log/v1",
        &LogMaterial {
            source_commit: &log.source_commit,
            scope: &log.scope,
            revision: log.revision,
            entries,
            durable: log.durable,
            model_visible: log.model_visible,
        },
    )
    .context("derive log digest")
}

fn expected_verification_digest(verification: &EffectVerification) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-effect-verification/v1",
        &VerificationMaterial {
            sequence: verification.sequence,
            status: verification.status,
            verified_at: verification.verified_at,
        },
    )
    .context("derive effect verification digest")
}

fn expected_effect_digest(effect: &EffectReceipt) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-effect/v1",
        &EffectMaterial {
            sequence: effect.sequence,
            effect_id: &effect.effect_id,
            capability: &effect.capability,
            plugin_id: &effect.plugin_id,
            source_commit: &effect.source_commit,
            scope: &effect.scope,
            requested_at: effect.requested_at,
            receipt_at: effect.receipt_at,
            status: effect.status,
            verification: &effect.verification,
        },
    )
    .context("derive effect digest")
}

fn expected_result_digest(result: &SelectedResult) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-result/v1",
        &ResultMaterial {
            source_commit: &result.source_commit,
            scope: &result.scope,
            revision: result.revision,
            status: result.status,
            provenance: result.provenance,
            evidence_root: &result.evidence_root,
            selected_at: result.selected_at,
        },
    )
    .context("derive selected result digest")
}

fn expected_adoption_digest(adoption: &AdoptionRecord) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-adoption/v1",
        &AdoptionMaterial {
            source_commit: &adoption.source_commit,
            scope: &adoption.scope,
            revision: adoption.revision,
            decision: adoption.decision,
            result_digest: &adoption.result_digest,
            evidence_root: &adoption.evidence_root,
            adopted_at: adoption.adopted_at,
        },
    )
    .context("derive adoption digest")
}

fn expected_recovery_digest(receipt: &RecoveryReceipt) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-recovery/v1",
        &RecoveryMaterial {
            sequence: receipt.sequence,
            hook: receipt.hook,
            status: receipt.status,
            source_commit: &receipt.source_commit,
            scope: &receipt.scope,
            occurred_at: receipt.occurred_at,
            old_plugin_accepted: receipt.old_plugin_accepted,
            old_decision_promotable: receipt.old_decision_promotable,
        },
    )
    .context("derive recovery digest")
}

fn expected_result_evidence_root(journey: &PluginNativeJourney) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-result-evidence/v1",
        &ResultEvidenceMaterial {
            log_digest: &journey.durable_log.log_digest,
            effect_digests: journey
                .effects
                .iter()
                .map(|effect| effect.receipt_digest.as_str())
                .collect(),
            provider_output_digest: &journey.provider.output_digest,
        },
    )
    .context("derive result evidence root")
}

fn expected_evidence_root(journey: &PluginNativeJourney) -> Result<String> {
    digest_json(
        "hartevo-plugin-native-journey-evidence/v1",
        &JourneyEvidenceMaterial {
            source_commit: &journey.source_commit,
            journey_id: &journey.journey_id,
            project: &journey.project,
            mission: &journey.mission,
            objective: &journey.objective,
            composition: &journey.composition,
            runtime_plugin: &journey.runtime_plugin,
            model_plugin: &journey.model_plugin,
            service: &journey.service,
            provider: &journey.provider,
            consumer: &journey.consumer,
            invocations: &journey.invocations,
            durable_log: &journey.durable_log,
            effects: &journey.effects,
            selected_result: &journey.selected_result,
            adoption: &journey.adoption,
            recovery: &journey.recovery,
        },
    )
    .context("derive journey evidence root")
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} is required");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte)),
        "{label} contains an unsafe character"
    );
    Ok(())
}

fn validate_commit(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "source commit must be lowercase 40-hex Git commit"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(is_lower_hex(value, 32), "{label} must be lowercase SHA-256");
    Ok(())
}

fn exact_string_set(value: &Value) -> Result<BTreeSet<&str>> {
    let values = value
        .as_array()
        .context("expected JSON string array")?
        .iter()
        .map(|item| item.as_str().context("expected JSON string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "JSON string array contains duplicates"
    );
    Ok(values.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn source_commit() -> String {
        current_source_commit().expect("current Git commit")
    }

    pub(super) fn journey(mode: ComponentMode) -> PluginNativeJourney {
        let source_commit = source_commit();
        let project = ProjectScope {
            id: "project-plugin-journey".into(),
            revision: 1,
            scope_digest: digest('1'),
        };
        let mission = MissionScope {
            id: "mission-market-decision".into(),
            revision: 2,
            scope_digest: digest('2'),
        };
        let project_id = project.id.clone();
        let mission_id = mission.id.clone();
        let scope_digest = digest_json(
            "hartevo-plugin-native-journey-scope/v1",
            &ScopeMaterial {
                project_id: &project.id,
                project_revision: project.revision,
                project_scope_digest: &project.scope_digest,
                mission_id: &mission.id,
                mission_revision: mission.revision,
                mission_scope_digest: &mission.scope_digest,
            },
        )
        .unwrap();
        let scope = || SessionScope {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            scope_digest: scope_digest.clone(),
        };
        let native = mode == ComponentMode::Native;
        let credentials = if native {
            CredentialStatus::Verified
        } else {
            CredentialStatus::BlockedEnv
        };
        let artifact_digest = if native { digest('a') } else { String::new() };
        let output_digest = if native { digest('b') } else { String::new() };
        let mut objective = Objective {
            id: "objective-germany-market".into(),
            text: "Evaluate whether our product should enter the German market".into(),
            constraints_digest: digest('c'),
            source_commit: source_commit.clone(),
            scope: scope(),
            digest: String::new(),
        };
        objective.digest = expected_objective_digest(&objective).unwrap();
        let mut composition = MissionComposition {
            objective_id: objective.id.clone(),
            mission_id: mission.id.clone(),
            revision: mission.revision,
            source_commit: source_commit.clone(),
            scope: scope(),
            capability_set_digest: digest('d'),
            composition_digest: String::new(),
        };
        composition.composition_digest =
            expected_composition_digest(&composition, &objective.digest).unwrap();
        let mut runtime_plugin = RuntimePlugin {
            id: "plugin-native-runtime".into(),
            revision: 3,
            source_commit: source_commit.clone(),
            scope: scope(),
            mode,
            plugin_digest: String::new(),
            mounted: true,
            unmounted: true,
        };
        runtime_plugin.plugin_digest = expected_runtime_digest(&runtime_plugin).unwrap();
        let mut model_plugin = ModelPlugin {
            id: "model-plugin".into(),
            provider: "provider-native".into(),
            model: "model-market-research".into(),
            revision: "2026.08".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            mode,
            credentials,
            model_digest: String::new(),
            artifact_digest,
            output_present: native,
            output_digest: output_digest.clone(),
        };
        model_plugin.model_digest = expected_model_digest(&model_plugin).unwrap();
        let start = Utc::now();
        let mut invocations = Vec::new();
        let capability = "market.research.read";
        let mut invocation = CapabilityInvocation {
            sequence: 1,
            capability: capability.into(),
            plugin_id: runtime_plugin.id.clone(),
            source_commit: source_commit.clone(),
            scope: scope(),
            request_digest: String::new(),
            response_digest: if native {
                output_digest.clone()
            } else {
                digest('e')
            },
            started_at: start + Duration::seconds(3),
            completed_at: start + Duration::seconds(5),
            status: InvocationStatus::Completed,
        };
        invocation.request_digest = expected_invocation_request(
            &invocation,
            &PluginNativeJourney {
                schema_version: CONTRACT_SCHEMA_VERSION.into(),
                document_type: DOCUMENT_TYPE.into(),
                authority: AUTHORITY.into(),
                release_decision: RELEASE_DECISION.into(),
                source_commit: source_commit.clone(),
                journey_id: digest('f'),
                project: project.clone(),
                mission: mission.clone(),
                objective: objective.clone(),
                composition: composition.clone(),
                runtime_plugin: runtime_plugin.clone(),
                model_plugin: model_plugin.clone(),
                service: ServiceBinding {
                    id: "service".into(),
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    mode,
                    mounted: true,
                    durable_log_digest: digest('0'),
                },
                provider: ProviderBinding {
                    id: "provider".into(),
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    mode,
                    model_digest: model_plugin.model_digest.clone(),
                    provider_digest: digest('1'),
                    output_present: native,
                    output_digest: output_digest.clone(),
                },
                consumer: crate::model::ConsumerBinding {
                    id: "consumer".into(),
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    adopted: false,
                    selected_result_digest: digest('2'),
                },
                invocations: Vec::new(),
                durable_log: DurableLog {
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    revision: mission.revision,
                    entries: Vec::new(),
                    durable: true,
                    model_visible: true,
                    log_digest: digest('3'),
                },
                effects: Vec::new(),
                selected_result: SelectedResult {
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    revision: mission.revision,
                    status: ResultStatus::NotEvaluated,
                    provenance: EvidenceProvenance::BlockedEnv,
                    result_digest: digest('4'),
                    evidence_root: String::new(),
                    selected_at: start,
                },
                adoption: AdoptionRecord {
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    revision: mission.revision,
                    decision: AdoptionDecision::NotEvaluated,
                    result_digest: digest('4'),
                    evidence_root: String::new(),
                    decision_digest: digest('5'),
                    adopted_at: start,
                },
                recovery: Vec::new(),
                evidence_root: digest('6'),
            },
        )
        .unwrap();
        invocations.push(invocation);
        let mut log = DurableLog {
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: mission.revision,
            entries: vec![
                DurableLogEntry {
                    sequence: 1,
                    kind: LogEntryKind::Objective,
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    occurred_at: start + Duration::seconds(1),
                    payload_digest: objective.digest.clone(),
                },
                DurableLogEntry {
                    sequence: 2,
                    kind: LogEntryKind::MissionComposition,
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    occurred_at: start + Duration::seconds(2),
                    payload_digest: composition.composition_digest.clone(),
                },
                DurableLogEntry {
                    sequence: 3,
                    kind: LogEntryKind::Invocation,
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    occurred_at: start + Duration::seconds(6),
                    payload_digest: invocations[0].request_digest.clone(),
                },
                DurableLogEntry {
                    sequence: 4,
                    kind: LogEntryKind::Result,
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    occurred_at: start + Duration::seconds(12),
                    payload_digest: digest('7'),
                },
            ],
            durable: true,
            model_visible: true,
            log_digest: String::new(),
        };
        log.log_digest = expected_log_digest(&log).unwrap();
        let service = ServiceBinding {
            id: "service-plugin".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            mode,
            mounted: true,
            durable_log_digest: log.log_digest.clone(),
        };
        let mut provider = ProviderBinding {
            id: "provider-plugin".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            mode,
            model_digest: model_plugin.model_digest.clone(),
            provider_digest: String::new(),
            output_present: native,
            output_digest: output_digest.clone(),
        };
        provider.provider_digest = expected_provider_digest(&provider).unwrap();
        let mut effect = EffectReceipt {
            sequence: 1,
            effect_id: "effect-plugin-1".into(),
            capability: capability.into(),
            plugin_id: runtime_plugin.id.clone(),
            source_commit: source_commit.clone(),
            scope: scope(),
            requested_at: start + Duration::seconds(7),
            receipt_at: start + Duration::seconds(8),
            status: EffectStatus::Applied,
            receipt_digest: String::new(),
            verification: EffectVerification {
                sequence: 1,
                status: VerificationStatus::Verified,
                verified_at: start + Duration::seconds(9),
                verification_digest: String::new(),
            },
        };
        effect.verification.verification_digest =
            expected_verification_digest(&effect.verification).unwrap();
        effect.receipt_digest = expected_effect_digest(&effect).unwrap();
        let evidence_root = if native {
            expected_result_evidence_root(&PluginNativeJourney {
                schema_version: CONTRACT_SCHEMA_VERSION.into(),
                document_type: DOCUMENT_TYPE.into(),
                authority: AUTHORITY.into(),
                release_decision: RELEASE_DECISION.into(),
                source_commit: source_commit.clone(),
                journey_id: digest('f'),
                project: project.clone(),
                mission: mission.clone(),
                objective: objective.clone(),
                composition: composition.clone(),
                runtime_plugin: runtime_plugin.clone(),
                model_plugin: model_plugin.clone(),
                service: service.clone(),
                provider: provider.clone(),
                consumer: crate::model::ConsumerBinding {
                    id: "consumer".into(),
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    adopted: false,
                    selected_result_digest: digest('8'),
                },
                invocations: invocations.clone(),
                durable_log: log.clone(),
                effects: vec![effect.clone()],
                selected_result: SelectedResult {
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    revision: mission.revision,
                    status: ResultStatus::Completed,
                    provenance: EvidenceProvenance::Native,
                    result_digest: digest('9'),
                    evidence_root: String::new(),
                    selected_at: start + Duration::seconds(10),
                },
                adoption: AdoptionRecord {
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    revision: mission.revision,
                    decision: AdoptionDecision::Adopt,
                    result_digest: digest('9'),
                    evidence_root: String::new(),
                    decision_digest: digest('a'),
                    adopted_at: start + Duration::seconds(11),
                },
                recovery: Vec::new(),
                evidence_root: digest('b'),
            })
            .unwrap()
        } else {
            String::new()
        };
        let mut selected_result = SelectedResult {
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: mission.revision,
            status: if native {
                ResultStatus::Completed
            } else {
                ResultStatus::NotEvaluated
            },
            provenance: if native {
                EvidenceProvenance::Native
            } else {
                EvidenceProvenance::BlockedEnv
            },
            result_digest: String::new(),
            evidence_root,
            selected_at: start + Duration::seconds(10),
        };
        selected_result.result_digest = expected_result_digest(&selected_result).unwrap();
        log.entries[3].payload_digest = selected_result.result_digest.clone();
        log.log_digest = expected_log_digest(&log).unwrap();
        let mut adoption = AdoptionRecord {
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: mission.revision,
            decision: if native {
                AdoptionDecision::Adopt
            } else {
                AdoptionDecision::NotEvaluated
            },
            result_digest: selected_result.result_digest.clone(),
            evidence_root: selected_result.evidence_root.clone(),
            decision_digest: String::new(),
            adopted_at: start + Duration::seconds(11),
        };
        adoption.decision_digest = expected_adoption_digest(&adoption).unwrap();
        let consumer = crate::model::ConsumerBinding {
            id: "consumer-plugin".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            adopted: native,
            selected_result_digest: selected_result.result_digest.clone(),
        };
        let mut recovery = Vec::new();
        for (index, hook) in REQUIRED_RECOVERY.into_iter().enumerate() {
            let mut receipt = RecoveryReceipt {
                sequence: index as u64 + 1,
                hook,
                status: RecoveryStatus::Recovered,
                source_commit: source_commit.clone(),
                scope: scope(),
                occurred_at: start + Duration::seconds(index as i64 + 12),
                receipt_digest: String::new(),
                old_plugin_accepted: false,
                old_decision_promotable: false,
            };
            receipt.receipt_digest = expected_recovery_digest(&receipt).unwrap();
            recovery.push(receipt);
        }
        let mut journey = PluginNativeJourney {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            document_type: DOCUMENT_TYPE.into(),
            authority: AUTHORITY.into(),
            release_decision: RELEASE_DECISION.into(),
            source_commit,
            journey_id: digest('f'),
            project,
            mission,
            objective,
            composition,
            runtime_plugin,
            model_plugin,
            service,
            provider,
            consumer,
            invocations,
            durable_log: log,
            effects: vec![effect],
            selected_result,
            adoption,
            recovery,
            evidence_root: String::new(),
        };
        journey.evidence_root = expected_evidence_root(&journey).unwrap();
        journey
    }

    #[test]
    fn checked_in_journey_contract_is_closed() {
        validate_contract().expect("journey contract");
        assert!(is_lower_hex(&contract_digest(), 32));
    }

    #[test]
    fn typed_serializer_matches_checked_in_contract_key_closure() {
        let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES).unwrap();
        let journey = serde_json::to_value(journey(ComponentMode::Native)).unwrap();
        assert_schema_keys(&journey, &contract, None);
        assert_eq!(journey["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert_eq!(journey["documentType"], DOCUMENT_TYPE);
        assert_eq!(journey["authority"], AUTHORITY);
        assert_eq!(journey["releaseDecision"], RELEASE_DECISION);
        for (field, definition) in [("project", "project"), ("mission", "mission")] {
            assert_schema_keys(&journey[field], &contract, Some(definition));
        }
        for (field, definition) in [
            ("objective", "objective"),
            ("composition", "composition"),
            ("runtimePlugin", "runtimePlugin"),
            ("modelPlugin", "modelPlugin"),
            ("service", "service"),
            ("provider", "provider"),
            ("consumer", "consumer"),
            ("durableLog", "durableLog"),
            ("selectedResult", "selectedResult"),
            ("adoption", "adoption"),
        ] {
            assert_schema_keys(&journey[field], &contract, Some(definition));
            assert_schema_keys(&journey[field]["scope"], &contract, Some("scope"));
        }
        for invocation in journey["invocations"].as_array().unwrap() {
            assert_schema_keys(invocation, &contract, Some("invocation"));
            assert_schema_keys(&invocation["scope"], &contract, Some("scope"));
        }
        for entry in journey["durableLog"]["entries"].as_array().unwrap() {
            assert_schema_keys(entry, &contract, Some("durableLogEntry"));
            assert_schema_keys(&entry["scope"], &contract, Some("scope"));
        }
        for effect in journey["effects"].as_array().unwrap() {
            assert_schema_keys(effect, &contract, Some("effect"));
            assert_schema_keys(&effect["scope"], &contract, Some("scope"));
            assert_schema_keys(
                &effect["verification"],
                &contract,
                Some("effectVerification"),
            );
        }
        for receipt in journey["recovery"].as_array().unwrap() {
            assert_schema_keys(receipt, &contract, Some("recovery"));
            assert_schema_keys(&receipt["scope"], &contract, Some("scope"));
        }
    }

    fn assert_schema_keys(actual: &Value, contract: &Value, definition: Option<&str>) {
        let schema = definition
            .map(|name| &contract["$defs"][name])
            .unwrap_or(contract);
        let expected = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<BTreeSet<_>>();
        let observed = actual.as_object().unwrap().keys().collect::<BTreeSet<_>>();
        assert_eq!(
            observed, expected,
            "typed serializer drifted for {definition:?}"
        );
    }

    #[test]
    fn native_journey_replays_to_same_current_commit_conclusion() {
        let journey = journey(ComponentMode::Native);
        let commit = source_commit();
        let first = validate_journey(&journey, &commit).expect("native journey");
        let replay = validate_journey(&journey, &commit).expect("replay");
        assert_eq!(first, replay);
        assert_eq!(first.oracle_status, OracleStatus::NativePass);
        assert!(first.native_pass);
    }

    #[test]
    fn sequence_scope_and_digest_tampering_are_rejected() {
        let commit = source_commit();
        let mut gap = journey(ComponentMode::Native);
        gap.invocations[0].sequence = 4;
        assert!(validate_journey(&gap, &commit).is_err());

        let mut cross = journey(ComponentMode::Native);
        cross.effects[0].scope.mission_id = "other-mission".into();
        assert!(validate_journey(&cross, &commit).is_err());

        let mut drift = journey(ComponentMode::Native);
        let replacement = if drift.provider.provider_digest.starts_with('0') {
            "1"
        } else {
            "0"
        };
        drift
            .provider
            .provider_digest
            .replace_range(..1, replacement);
        assert!(validate_journey(&drift, &commit).is_err());
    }

    #[test]
    fn recovery_and_terminal_evidence_mutations_are_rejected() {
        let commit = source_commit();
        let mut duplicate = journey(ComponentMode::Native);
        duplicate.recovery[2].hook = RecoveryHook::Revoke;
        assert!(validate_journey(&duplicate, &commit).is_err());

        let mut result = journey(ComponentMode::Native);
        result.durable_log.entries.pop();
        assert!(validate_journey(&result, &commit).is_err());
    }

    #[test]
    fn fixture_and_blocked_components_never_become_native_pass() {
        let mut fixture = journey(ComponentMode::Fixture);
        fixture.model_plugin.credentials = CredentialStatus::BlockedEnv;
        fixture.selected_result.status = ResultStatus::NotEvaluated;
        fixture.selected_result.provenance = EvidenceProvenance::Fixture;
        assert!(validate_journey(&fixture, &source_commit()).is_err());
    }

    #[test]
    fn valid_non_native_journey_is_blocked_and_nonzero() {
        let simulator = journey(ComponentMode::Simulator);
        let report = validate_journey(&simulator, &source_commit()).expect("simulator report");
        assert_eq!(report.oracle_status, OracleStatus::BlockedEnv);
        assert!(!report.native_pass);
        assert!(
            report
                .missing_reasons
                .iter()
                .any(|reason| { reason == "real_model_plugin_not_verified" })
        );
    }

    #[test]
    fn stale_commit_cannot_replay_as_current_journey() {
        let journey = journey(ComponentMode::Native);
        let stale_commit = "0".repeat(40);
        assert!(validate_journey(&journey, &stale_commit).is_err());
    }

    #[test]
    fn strict_json_rejects_unknown_and_duplicate_fields() {
        let value = serde_json::to_value(journey(ComponentMode::Native)).unwrap();
        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("forgedPass".into(), json!(true));
        assert!(
            crate::model::parse_strict_json::<PluginNativeJourney>(
                &serde_json::to_vec(&unknown).unwrap()
            )
            .is_err()
        );
        assert!(
            crate::model::parse_strict_json::<PluginNativeJourney>(
                br#"{"schemaVersion":"x","schemaVersion":"y"}"#
            )
            .is_err()
        );
    }
}
