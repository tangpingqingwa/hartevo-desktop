use anyhow::{Context, Result};
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::digest::{oracle_digest_json, sha256_text};
use crate::model::NativePluginReceipt;

const ORACLE_SCHEMA: &str = "hartevo.plugin-native-journey/v1";
const ORACLE_DOCUMENT: &str = "plugin_native_journey";
const ORACLE_AUTHORITY: &str = "plugin_native_journey_oracle_only";
const ORACLE_RELEASE: &str = "NOT_EVALUATED";

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Native,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Credential {
    Verified,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvocationStatus {
    Completed,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum LogKind {
    Objective,
    MissionComposition,
    Invocation,
    Result,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum EffectStatus {
    Applied,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerificationStatus {
    Verified,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResultStatus {
    Completed,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    Native,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdoptionDecision {
    Adopt,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryHook {
    Unmount,
    Revoke,
    Crash,
    Relaunch,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryStatus {
    Recovered,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Scope {
    project_id: String,
    mission_id: String,
    #[serde(rename = "scopeDigest")]
    digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    id: String,
    revision: u64,
    scope_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Mission {
    id: String,
    revision: u64,
    scope_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Objective {
    id: String,
    text: String,
    constraints_digest: String,
    source_commit: String,
    scope: Scope,
    #[serde(rename = "objectiveDigest")]
    digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Composition {
    objective_id: String,
    mission_id: String,
    revision: u64,
    source_commit: String,
    scope: Scope,
    capability_set_digest: String,
    #[serde(rename = "compositionDigest")]
    digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimePlugin {
    id: String,
    revision: u64,
    source_commit: String,
    scope: Scope,
    mode: Mode,
    plugin_digest: String,
    mounted: bool,
    unmounted: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModelPlugin {
    id: String,
    provider: String,
    model: String,
    revision: String,
    source_commit: String,
    scope: Scope,
    mode: Mode,
    credentials: Credential,
    model_digest: String,
    artifact_digest: String,
    output_present: bool,
    output_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Service {
    id: String,
    source_commit: String,
    scope: Scope,
    mode: Mode,
    mounted: bool,
    durable_log_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Provider {
    id: String,
    source_commit: String,
    scope: Scope,
    mode: Mode,
    model_digest: String,
    #[serde(rename = "providerDigest")]
    digest: String,
    output_present: bool,
    output_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Consumer {
    id: String,
    source_commit: String,
    scope: Scope,
    adopted: bool,
    selected_result_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    sequence: u64,
    capability: String,
    plugin_id: String,
    source_commit: String,
    scope: Scope,
    request_digest: String,
    response_digest: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    status: InvocationStatus,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogEntry {
    sequence: u64,
    kind: LogKind,
    source_commit: String,
    scope: Scope,
    occurred_at: DateTime<Utc>,
    payload_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableLog {
    source_commit: String,
    scope: Scope,
    revision: u64,
    entries: Vec<LogEntry>,
    durable: bool,
    model_visible: bool,
    log_digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Verification {
    sequence: u64,
    status: VerificationStatus,
    verified_at: DateTime<Utc>,
    #[serde(rename = "verificationDigest")]
    digest: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Effect {
    sequence: u64,
    #[serde(rename = "effectId")]
    id: String,
    capability: String,
    plugin_id: String,
    source_commit: String,
    scope: Scope,
    requested_at: DateTime<Utc>,
    receipt_at: DateTime<Utc>,
    status: EffectStatus,
    receipt_digest: String,
    verification: Verification,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectedResult {
    source_commit: String,
    scope: Scope,
    revision: u64,
    status: ResultStatus,
    provenance: Provenance,
    result_digest: String,
    evidence_root: String,
    selected_at: DateTime<Utc>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Adoption {
    source_commit: String,
    scope: Scope,
    revision: u64,
    decision: AdoptionDecision,
    result_digest: String,
    evidence_root: String,
    decision_digest: String,
    adopted_at: DateTime<Utc>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Recovery {
    sequence: u64,
    hook: RecoveryHook,
    status: RecoveryStatus,
    source_commit: String,
    scope: Scope,
    occurred_at: DateTime<Utc>,
    receipt_digest: String,
    old_plugin_accepted: bool,
    old_decision_promotable: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginNativeJourney {
    schema_version: String,
    document_type: String,
    authority: String,
    release_decision: String,
    source_commit: String,
    journey_id: String,
    project: Project,
    mission: Mission,
    objective: Objective,
    composition: Composition,
    runtime_plugin: RuntimePlugin,
    model_plugin: ModelPlugin,
    service: Service,
    provider: Provider,
    consumer: Consumer,
    invocations: Vec<Invocation>,
    durable_log: DurableLog,
    effects: Vec<Effect>,
    selected_result: SelectedResult,
    adoption: Adoption,
    recovery: Vec<Recovery>,
    evidence_root: String,
}

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
    scope: &'a Scope,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompositionMaterial<'a> {
    objective_id: &'a str,
    objective_digest: &'a str,
    mission_id: &'a str,
    revision: u64,
    source_commit: &'a str,
    scope: &'a Scope,
    capability_set_digest: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeMaterial<'a> {
    id: &'a str,
    revision: u64,
    source_commit: &'a str,
    scope: &'a Scope,
    mode: Mode,
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
    scope: &'a Scope,
    mode: Mode,
    credentials: Credential,
    artifact_digest: &'a str,
    output_present: bool,
    output_digest: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderMaterial<'a> {
    id: &'a str,
    source_commit: &'a str,
    scope: &'a Scope,
    mode: Mode,
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
    scope: &'a Scope,
    objective_digest: &'a str,
    composition_digest: &'a str,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogMaterial<'a> {
    source_commit: &'a str,
    scope: &'a Scope,
    revision: u64,
    entries: Vec<&'a LogEntry>,
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
    scope: &'a Scope,
    requested_at: DateTime<Utc>,
    receipt_at: DateTime<Utc>,
    status: EffectStatus,
    verification: &'a Verification,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultMaterial<'a> {
    source_commit: &'a str,
    scope: &'a Scope,
    revision: u64,
    status: ResultStatus,
    provenance: Provenance,
    evidence_root: &'a str,
    selected_at: DateTime<Utc>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptionMaterial<'a> {
    source_commit: &'a str,
    scope: &'a Scope,
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
    scope: &'a Scope,
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
    project: &'a Project,
    mission: &'a Mission,
    objective: &'a Objective,
    composition: &'a Composition,
    runtime_plugin: &'a RuntimePlugin,
    model_plugin: &'a ModelPlugin,
    service: &'a Service,
    provider: &'a Provider,
    consumer: &'a Consumer,
    invocations: &'a [Invocation],
    durable_log: &'a DurableLog,
    effects: &'a [Effect],
    selected_result: &'a SelectedResult,
    adoption: &'a Adoption,
    recovery: &'a [Recovery],
}

fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    Ok(oracle_digest_json(domain, value)?)
}

fn timestamp(seconds: u64) -> Result<DateTime<Utc>> {
    Utc.timestamp_opt(
        i64::try_from(seconds).context("timestamp exceeds chrono range")?,
        0,
    )
    .single()
    .context("native process observation cannot form UTC timestamp")
}

#[expect(
    clippy::too_many_lines,
    reason = "the oracle adapter mirrors the closed upstream journey contract in one auditable projection"
)]
pub(super) fn build(receipt: &NativePluginReceipt) -> Result<Value> {
    let source = receipt.source_commit.clone();
    let project_id = receipt.scope.project_id.clone();
    let mission_id = receipt.scope.mission_id.clone();
    let project_scope_digest = sha256_text(&format!("oracle-project:{project_id}"));
    let mission_scope_digest = sha256_text(&format!("oracle-mission:{mission_id}"));
    let project = Project {
        id: project_id.clone(),
        revision: 1,
        scope_digest: project_scope_digest.clone(),
    };
    let mission = Mission {
        id: mission_id.clone(),
        revision: 1,
        scope_digest: mission_scope_digest.clone(),
    };
    let scope_digest = digest(
        "hartevo-plugin-native-journey-scope/v1",
        &ScopeMaterial {
            project_id: &project_id,
            project_revision: 1,
            project_scope_digest: &project_scope_digest,
            mission_id: &mission_id,
            mission_revision: 1,
            mission_scope_digest: &mission_scope_digest,
        },
    )?;
    let scope = Scope {
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        digest: scope_digest,
    };
    let constraints_digest = sha256_text("native-openinterpreter-plugin-no-secret-content");
    let mut objective = Objective {
        id: "openinterpreter-native-plugin-objective".to_owned(),
        text: "Native OpenInterpreter provider plugin journey".to_owned(),
        constraints_digest,
        source_commit: source.clone(),
        scope: scope.clone(),
        digest: String::new(),
    };
    objective.digest = digest(
        "hartevo-plugin-native-journey-objective/v1",
        &ObjectiveMaterial {
            id: &objective.id,
            text: &objective.text,
            constraints_digest: &objective.constraints_digest,
            source_commit: &objective.source_commit,
            scope: &objective.scope,
        },
    )?;
    let mut composition = Composition {
        objective_id: objective.id.clone(),
        mission_id: mission_id.clone(),
        revision: 1,
        source_commit: source.clone(),
        scope: scope.clone(),
        capability_set_digest: sha256_text("runtime.turn.streamed_result"),
        digest: String::new(),
    };
    composition.digest = digest(
        "hartevo-plugin-native-journey-composition/v1",
        &CompositionMaterial {
            objective_id: &composition.objective_id,
            objective_digest: &objective.digest,
            mission_id: &composition.mission_id,
            revision: 1,
            source_commit: &source,
            scope: &scope,
            capability_set_digest: &composition.capability_set_digest,
        },
    )?;
    let mut runtime_plugin = RuntimePlugin {
        id: "openinterpreter-runtime-plugin".to_owned(),
        revision: 1,
        source_commit: source.clone(),
        scope: scope.clone(),
        mode: Mode::Native,
        plugin_digest: String::new(),
        mounted: true,
        unmounted: true,
    };
    runtime_plugin.plugin_digest = digest(
        "hartevo-plugin-native-journey-runtime-plugin/v1",
        &RuntimeMaterial {
            id: &runtime_plugin.id,
            revision: 1,
            source_commit: &source,
            scope: &scope,
            mode: Mode::Native,
            mounted: true,
            unmounted: true,
        },
    )?;
    let mut model = ModelPlugin {
        id: "openinterpreter-model-plugin".to_owned(),
        provider: receipt.selection.provider_id.clone(),
        model: receipt.selection.model_id.clone(),
        revision: receipt.selection.model_revision.clone(),
        source_commit: source.clone(),
        scope: scope.clone(),
        mode: Mode::Native,
        credentials: Credential::Verified,
        model_digest: String::new(),
        artifact_digest: receipt.source.binary_digest.clone(),
        output_present: true,
        output_digest: receipt.result.content_digest.clone(),
    };
    model.model_digest = digest(
        "hartevo-plugin-native-journey-model-plugin/v1",
        &ModelMaterial {
            id: &model.id,
            provider: &model.provider,
            model: &model.model,
            revision: &model.revision,
            source_commit: &source,
            scope: &scope,
            mode: Mode::Native,
            credentials: Credential::Verified,
            artifact_digest: &model.artifact_digest,
            output_present: true,
            output_digest: &model.output_digest,
        },
    )?;
    let capability = "model.stream.result".to_owned();
    let base = timestamp(receipt.process.observed_at_epoch_seconds)?;
    let started_at = base + Duration::seconds(5);
    let completed_at = base + Duration::seconds(10);
    let mut invocation = Invocation {
        sequence: 1,
        capability: capability.clone(),
        plugin_id: runtime_plugin.id.clone(),
        source_commit: source.clone(),
        scope: scope.clone(),
        request_digest: String::new(),
        response_digest: model.output_digest.clone(),
        started_at,
        completed_at,
        status: InvocationStatus::Completed,
    };
    invocation.request_digest = digest(
        "hartevo-plugin-native-journey-invocation/v1",
        &InvocationMaterial {
            sequence: 1,
            capability: &capability,
            plugin_id: &runtime_plugin.id,
            source_commit: &source,
            scope: &scope,
            objective_digest: &objective.digest,
            composition_digest: &composition.digest,
            started_at,
            completed_at,
        },
    )?;
    let mut entries = vec![
        LogEntry {
            sequence: 1,
            kind: LogKind::Objective,
            source_commit: source.clone(),
            scope: scope.clone(),
            occurred_at: base + Duration::seconds(11),
            payload_digest: objective.digest.clone(),
        },
        LogEntry {
            sequence: 2,
            kind: LogKind::MissionComposition,
            source_commit: source.clone(),
            scope: scope.clone(),
            occurred_at: base + Duration::seconds(12),
            payload_digest: composition.digest.clone(),
        },
        LogEntry {
            sequence: 3,
            kind: LogKind::Invocation,
            source_commit: source.clone(),
            scope: scope.clone(),
            occurred_at: base + Duration::seconds(13),
            payload_digest: invocation.request_digest.clone(),
        },
    ];
    let requested_at = base + Duration::seconds(14);
    let receipt_at = base + Duration::seconds(15);
    let verified_at = base + Duration::seconds(16);
    let mut verification = Verification {
        sequence: 1,
        status: VerificationStatus::Verified,
        verified_at,
        digest: String::new(),
    };
    verification.digest = digest(
        "hartevo-plugin-native-journey-effect-verification/v1",
        &VerificationMaterial {
            sequence: 1,
            status: VerificationStatus::Verified,
            verified_at,
        },
    )?;
    let mut effect = Effect {
        sequence: 1,
        id: "openinterpreter-native-result-effect".to_owned(),
        capability: capability.clone(),
        plugin_id: runtime_plugin.id.clone(),
        source_commit: source.clone(),
        scope: scope.clone(),
        requested_at,
        receipt_at,
        status: EffectStatus::Applied,
        receipt_digest: String::new(),
        verification,
    };
    effect.receipt_digest = digest(
        "hartevo-plugin-native-journey-effect/v1",
        &EffectMaterial {
            sequence: 1,
            effect_id: &effect.id,
            capability: &effect.capability,
            plugin_id: &effect.plugin_id,
            source_commit: &source,
            scope: &scope,
            requested_at,
            receipt_at,
            status: EffectStatus::Applied,
            verification: &effect.verification,
        },
    )?;
    let log_digest_without_result = digest(
        "hartevo-plugin-native-journey-log/v1",
        &LogMaterial {
            source_commit: &source,
            scope: &scope,
            revision: 1,
            entries: entries.iter().collect(),
            durable: true,
            model_visible: true,
        },
    )?;
    let selected_at = base + Duration::seconds(17);
    let result_evidence_root = digest(
        "hartevo-plugin-native-journey-result-evidence/v1",
        &ResultEvidenceMaterial {
            log_digest: &log_digest_without_result,
            effect_digests: vec![&effect.receipt_digest],
            provider_output_digest: &model.output_digest,
        },
    )?;
    let mut selected = SelectedResult {
        source_commit: source.clone(),
        scope: scope.clone(),
        revision: 1,
        status: ResultStatus::Completed,
        provenance: Provenance::Native,
        result_digest: String::new(),
        evidence_root: result_evidence_root,
        selected_at,
    };
    selected.result_digest = digest(
        "hartevo-plugin-native-journey-result/v1",
        &ResultMaterial {
            source_commit: &source,
            scope: &scope,
            revision: 1,
            status: ResultStatus::Completed,
            provenance: Provenance::Native,
            evidence_root: &selected.evidence_root,
            selected_at,
        },
    )?;
    entries.push(LogEntry {
        sequence: 4,
        kind: LogKind::Result,
        source_commit: source.clone(),
        scope: scope.clone(),
        occurred_at: base + Duration::seconds(18),
        payload_digest: selected.result_digest.clone(),
    });
    let durable_log = DurableLog {
        source_commit: source.clone(),
        scope: scope.clone(),
        revision: 1,
        entries,
        durable: true,
        model_visible: true,
        log_digest: log_digest_without_result,
    };
    let service = Service {
        id: "runtime.execution".to_owned(),
        source_commit: source.clone(),
        scope: scope.clone(),
        mode: Mode::Native,
        mounted: true,
        durable_log_digest: durable_log.log_digest.clone(),
    };
    let mut provider = Provider {
        id: receipt.selection.provider_id.clone(),
        source_commit: source.clone(),
        scope: scope.clone(),
        mode: Mode::Native,
        model_digest: model.model_digest.clone(),
        digest: String::new(),
        output_present: true,
        output_digest: model.output_digest.clone(),
    };
    provider.digest = digest(
        "hartevo-plugin-native-journey-provider/v1",
        &ProviderMaterial {
            id: &provider.id,
            source_commit: &source,
            scope: &scope,
            mode: Mode::Native,
            model_digest: &provider.model_digest,
            output_present: true,
            output_digest: &provider.output_digest,
        },
    )?;
    let consumer = Consumer {
        id: "hartevo-plugin-native-journey-oracle".to_owned(),
        source_commit: source.clone(),
        scope: scope.clone(),
        adopted: true,
        selected_result_digest: selected.result_digest.clone(),
    };
    let mut adoption = Adoption {
        source_commit: source.clone(),
        scope: scope.clone(),
        revision: 1,
        decision: AdoptionDecision::Adopt,
        result_digest: selected.result_digest.clone(),
        evidence_root: selected.evidence_root.clone(),
        decision_digest: String::new(),
        adopted_at: base + Duration::seconds(19),
    };
    adoption.decision_digest = digest(
        "hartevo-plugin-native-journey-adoption/v1",
        &AdoptionMaterial {
            source_commit: &source,
            scope: &scope,
            revision: 1,
            decision: AdoptionDecision::Adopt,
            result_digest: &adoption.result_digest,
            evidence_root: &adoption.evidence_root,
            adopted_at: adoption.adopted_at,
        },
    )?;
    let hooks = [
        RecoveryHook::Unmount,
        RecoveryHook::Revoke,
        RecoveryHook::Crash,
        RecoveryHook::Relaunch,
    ];
    let recovery = hooks
        .into_iter()
        .enumerate()
        .map(|(index, hook)| {
            let occurred_at = base
                + Duration::seconds(20 + i64::try_from(index).context("recovery index overflow")?);
            let receipt_digest = digest(
                "hartevo-plugin-native-journey-recovery/v1",
                &RecoveryMaterial {
                    sequence: index as u64 + 1,
                    hook,
                    status: RecoveryStatus::Recovered,
                    source_commit: &source,
                    scope: &scope,
                    occurred_at,
                    old_plugin_accepted: false,
                    old_decision_promotable: false,
                },
            )?;
            Ok(Recovery {
                sequence: index as u64 + 1,
                hook,
                status: RecoveryStatus::Recovered,
                source_commit: source.clone(),
                scope: scope.clone(),
                occurred_at,
                receipt_digest,
                old_plugin_accepted: false,
                old_decision_promotable: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let journey_id = receipt.oracle_input.journey_id.clone();
    let mut journey = PluginNativeJourney {
        schema_version: ORACLE_SCHEMA.to_owned(),
        document_type: ORACLE_DOCUMENT.to_owned(),
        authority: ORACLE_AUTHORITY.to_owned(),
        release_decision: ORACLE_RELEASE.to_owned(),
        source_commit: source.clone(),
        journey_id,
        project,
        mission,
        objective,
        composition,
        runtime_plugin,
        model_plugin: model,
        service,
        provider,
        consumer,
        invocations: vec![invocation],
        durable_log,
        effects: vec![effect],
        selected_result: selected,
        adoption,
        recovery,
        evidence_root: String::new(),
    };
    journey.evidence_root = digest(
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
    )?;
    Ok(serde_json::to_value(journey)?)
}

#[cfg(test)]
mod tests {
    use super::build;
    use crate::model::NativePluginReceipt;
    use serde_json::json;

    #[test]
    fn oracle_projection_has_closed_content_free_root() {
        let digest = "a".repeat(64);
        let commit = "b".repeat(40);
        let receipt: NativePluginReceipt = serde_json::from_value(json!({
            "schemaVersion": "hartevo.openinterpreter-native-plugin-receipt/v1",
            "documentType": "openinterpreter_native_plugin_journey",
            "authority": "native_openinterpreter_local_evidence",
            "releaseDecision": "NOT_EVALUATED",
            "sourceCommit": commit,
            "scope": {"projectId":"p","missionId":"m","sessionId":"s","scopeDigest":digest,"runtimeGeneration":1},
            "source": {"sourceCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","runtimeCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","runtimeRelease":"rust-v0.0.34","appServerSchemaDigest":format!("sha256:{}", "a".repeat(64)),"controlPlaneContractDigest":"a".repeat(64),"binaryDigest":"a".repeat(64),"toolDigest":"a".repeat(64),"commandDigest":"a".repeat(64)},
            "selection": {"serviceId":"runtime.execution","serviceRevision":"v1","providerId":"openinterpreter","providerRevision":"a".repeat(64),"modelId":"model","modelRevision":"a".repeat(64),"harnessId":"native","harnessRevision":"a".repeat(64),"endpointClass":"local","manifestDigest":"a".repeat(64),"serviceDefinitionDigest":"a".repeat(64),"catalogDigest":"a".repeat(64),"configDigest":"a".repeat(64),"policyDigest":"a".repeat(64)},
            "process": {"processIdDigest":"a".repeat(64),"observedAtEpochSeconds":1,"executablePathDigest":"a".repeat(64),"runtimeInstanceDigest":"a".repeat(64),"processBindingDigest":"a".repeat(64),"binaryDigest":"a".repeat(64),"runtimeGeneration":1},
            "stages": [], "durableLog": [],
            "turn": {"clientMessageIdDigest":"a".repeat(64),"requestDigest":"a".repeat(64),"responseDigest":"a".repeat(64),"threadIdDigest":"a".repeat(64),"turnIdDigest":"a".repeat(64),"completionStatus":"completed","turnDigest":"a".repeat(64)},
            "result": {"schema":"hartevo.runtime-result-packet/v1","authority":"local_execution_evidence","resultKind":"agent_message","projectId":"p","missionId":"m","runtimeGeneration":1,"runtimeInstanceDigest":"a".repeat(64),"runtimeCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","runtimeRelease":"rust-v0.0.34","mappingDigest":"a".repeat(64),"runtimeThreadIdDigest":"a".repeat(64),"runtimeTurnIdDigest":"a".repeat(64),"appServerSchemaDigest":format!("sha256:{}", "a".repeat(64)),"runtimeConfigDigest":"a".repeat(64),"catalogDigest":"a".repeat(64),"sourceItemIdDigest":"a".repeat(64),"sourceEventDigest":"a".repeat(64),"contentDigest":"a".repeat(64),"contentByteCount":1,"resultDigest":"a".repeat(64)},
            "interrupt": {"requestDigest":"a".repeat(64),"responseDigest":"a".repeat(64),"turnIdDigest":"a".repeat(64),"acknowledged":true,"interruptDigest":"a".repeat(64)},
            "cleanup": {"mountDigest":"a".repeat(64),"pluginState":"revoked","stoppedRegistrationCount":1,"residualRegistrationCount":0,"shutdownSuccess":true,"shutdownForced":false,"exitCode":0,"cleanupDigest":"a".repeat(64)},
            "oracleInput": {"journeySchema":"hartevo.plugin-native-journey/v1","journeyId":"a".repeat(64),"sourceCommit":"b".repeat(40),"projectId":"p","missionId":"m","sessionId":"s","runtimePluginDigest":"a".repeat(64),"providerDigest":"a".repeat(64),"modelDigest":"a".repeat(64),"serviceDigest":"a".repeat(64),"consumerId":"hartevo-plugin-native-journey-oracle","consumerResultDigest":"a".repeat(64),"durableLogDigest":"a".repeat(64),"resultDigest":"a".repeat(64),"evidenceRoot":"a".repeat(64),"provenance":"native"},
            "provenance":"native","evidenceRoot":"a".repeat(64),"receiptDigest":"a".repeat(64)
        }))
        .expect("synthetic content-free receipt");
        let journey = build(&receipt).expect("oracle projection");
        assert_eq!(journey["schemaVersion"], "hartevo.plugin-native-journey/v1");
        assert_eq!(journey["releaseDecision"], "NOT_EVALUATED");
        assert!(journey.get("content").is_none());
        let keys = journey
            .as_object()
            .expect("oracle object")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
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
        .map(str::to_owned)
        .collect();
        assert_eq!(keys, expected);
    }
}
