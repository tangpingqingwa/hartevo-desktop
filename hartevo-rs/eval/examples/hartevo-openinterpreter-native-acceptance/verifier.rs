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
    AdoptionDecision, CredentialStatus, DispatchRecord, DispatchStatus, DurableStreamLog,
    EffectReceipt, EffectStatus, EffectVerification, LogEntry, LogEntryKind, MissionScope,
    ModelIdentity, OpenInterpreterAcceptance, ProjectScope, ProviderIdentity, ProviderMode,
    RecoveryHook, RecoveryReceipt, RecoveryStatus, ResultProvenance, ResultStatus,
    SecretScanStatus, SessionScope, TerminalResult, ToolCallRecord, ToolCallStatus,
    ValidationReport, ValidatorStatus,
};

pub const CONTRACT_PATH: &str = "contracts/openinterpreter/native-acceptance.v1.json";
pub const APP_SERVER_CONTRACT_PATH: &str = "contracts/openinterpreter/app-server-v2.methods.json";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.openinterpreter-native-acceptance/v1";
pub const DOCUMENT_TYPE: &str = "openinterpreter_native_acceptance";
pub const AUTHORITY: &str = "openinterpreter_native_acceptance_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-openinterpreter-native-acceptance-report/v1";

const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/openinterpreter/native-acceptance.v1.json");
const APP_SERVER_CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/openinterpreter/app-server-v2.methods.json");
const REQUIRED_LOG_KINDS: [LogEntryKind; 4] = [
    LogEntryKind::Dispatch,
    LogEntryKind::ModelVisibleDelta,
    LogEntryKind::ToolCall,
    LogEntryKind::Terminal,
];
const REQUIRED_RECOVERY_HOOKS: [RecoveryHook; 4] = [
    RecoveryHook::Stop,
    RecoveryHook::Revoke,
    RecoveryHook::Crash,
    RecoveryHook::Relaunch,
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeDigestMaterial<'a> {
    project_id: &'a str,
    project_revision: u64,
    project_scope_digest: &'a str,
    mission_id: &'a str,
    mission_revision: u64,
    mission_scope_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunIdMaterial<'a> {
    source_commit: &'a str,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    model_identity_digest: &'a str,
    provider_identity_digest: &'a str,
    dispatch_request_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModelIdentityMaterial<'a> {
    id: &'a str,
    provider: &'a str,
    model: &'a str,
    revision: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
    artifact_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderIdentityMaterial<'a> {
    id: &'a str,
    mode: ProviderMode,
    runner_id: &'a str,
    runner_digest: &'a str,
    protocol_schema_digest: &'a str,
    credentials: CredentialStatus,
    output_present: bool,
    output_digest: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogMaterial<'a> {
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    entries: &'a [LogEntry],
    first_model_visible_sequence: u64,
    durable: bool,
    model_visible: bool,
    secret_scan: &'a crate::model::SecretScan,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMaterial {
    sequence: u64,
    status: crate::model::VerificationStatus,
    verified_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectMaterial<'a> {
    sequence: u64,
    effect_id: &'a str,
    capability: &'a str,
    source_commit: &'a str,
    scope: &'a SessionScope,
    requested_at: DateTime<Utc>,
    receipt_at: DateTime<Utc>,
    status: EffectStatus,
    verification: &'a EffectVerification,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalMaterial<'a> {
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    status: ResultStatus,
    provenance: ResultProvenance,
    evidence_root: &'a str,
    completed_at: DateTime<Utc>,
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
    decided_at: DateTime<Utc>,
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
    old_evaluator_accepted: bool,
    old_decision_promotable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleRootMaterial<'a> {
    schema_version: &'a str,
    document_type: &'a str,
    authority: &'a str,
    release_decision: &'a str,
    source_commit: &'a str,
    run_id: &'a str,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    model: &'a ModelIdentity,
    provider: &'a ProviderIdentity,
    dispatch: &'a DispatchRecord,
    durable_log: &'a DurableStreamLog,
    tool_calls: &'a [ToolCallRecord],
    effects: &'a [EffectReceipt],
    terminal_result: &'a TerminalResult,
    adoption: &'a crate::model::AdoptionRecord,
    recovery: &'a [RecoveryReceipt],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayMaterial<'a> {
    source_commit: &'a str,
    run_id: &'a str,
    bundle_root: &'a str,
    validator_status: ValidatorStatus,
    native_pass: bool,
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
}

pub fn app_server_contract_digest() -> String {
    sha256_hex(APP_SERVER_CONTRACT_BYTES)
}

pub fn current_source_commit() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("invoke Git for the current source commit")?;
    ensure!(
        output.status.success(),
        "Git cannot resolve the current source commit"
    );
    let commit = String::from_utf8(output.stdout)
        .context("Git returned a non-UTF-8 source commit")?
        .trim()
        .to_owned();
    validate_commit(&commit)?;
    Ok(commit)
}

pub fn read_capture(path: impl AsRef<Path>) -> Result<OpenInterpreterAcceptance> {
    let path = path.as_ref();
    let bytes = fs::read(path)
        .with_context(|| format!("read OpenInterpreter capture {}", path.display()))?;
    crate::model::parse_strict_json(&bytes)
        .with_context(|| format!("parse strict OpenInterpreter capture {}", path.display()))
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES)
        .context("OpenInterpreter acceptance contract is not strict JSON")?;
    validate_contract_root(&contract)?;
    validate_contract_definitions(&contract)?;
    validate_app_server_contract()
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
        "OpenInterpreter acceptance contract root drifted"
    );
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "runId",
        "project",
        "mission",
        "model",
        "provider",
        "dispatch",
        "durableLog",
        "toolCalls",
        "effects",
        "terminalResult",
        "adoption",
        "recovery",
        "bundleRoot",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let required = exact_string_set(contract.get("required").context("contract required")?)?;
    ensure!(
        required == expected,
        "OpenInterpreter root required set drifted"
    );
    let properties = contract
        .get("properties")
        .and_then(Value::as_object)
        .context("OpenInterpreter contract properties")?;
    ensure!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "OpenInterpreter root property set drifted"
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
            "OpenInterpreter contract constant {name} drifted"
        );
    }
    Ok(())
}

fn validate_contract_definitions(contract: &Value) -> Result<()> {
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("OpenInterpreter contract definitions")?;
    let expected_defs = [
        "adoption",
        "dispatch",
        "durableLog",
        "effect",
        "effectVerification",
        "logEntry",
        "model",
        "mission",
        "project",
        "provider",
        "recovery",
        "scope",
        "secretScan",
        "terminalResult",
        "toolCall",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        defs.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_defs,
        "OpenInterpreter contract definition set drifted"
    );
    for (name, definition) in defs {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "OpenInterpreter definition {name} is not closed"
        );
        let properties = definition
            .get("properties")
            .and_then(Value::as_object)
            .with_context(|| format!("definition {name} properties"))?;
        let required = exact_string_set(
            definition
                .get("required")
                .with_context(|| format!("definition {name} required"))?,
        )?;
        ensure!(
            required == properties.keys().map(String::as_str).collect(),
            "definition {name} required/property set drifted"
        );
    }
    Ok(())
}

fn validate_app_server_contract() -> Result<()> {
    let value: Value = crate::model::parse_strict_json(APP_SERVER_CONTRACT_BYTES)
        .context("OpenInterpreter app-server contract is not strict JSON")?;
    let object = value.as_object().context("app-server contract object")?;
    let expected_keys = [
        "schema",
        "stableMethods",
        "stableServerRequests",
        "stableNotifications",
        "experimentalApi",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_keys,
        "app-server contract key set drifted"
    );
    ensure!(
        object.get("schema").and_then(Value::as_str) == Some("hartevo.openinterpreter-contract/v1")
            && object.get("experimentalApi").and_then(Value::as_bool) == Some(false),
        "app-server contract identity or experimental API policy drifted"
    );
    ensure!(
        string_array(object.get("stableMethods").context("stable methods")?)?
            == vec![
                "initialize",
                "thread/start",
                "thread/resume",
                "turn/start",
                "turn/interrupt"
            ],
        "app-server stable method set drifted"
    );
    ensure!(
        string_array(
            object
                .get("stableServerRequests")
                .context("stable server requests")?
        )? == vec![
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
        ],
        "app-server stable request set drifted"
    );
    ensure!(
        string_array(
            object
                .get("stableNotifications")
                .context("stable notifications")?
        )? == vec![
            "thread/started",
            "turn/started",
            "item/started",
            "item/agentMessage/delta",
            "item/completed",
            "turn/completed",
        ],
        "app-server stable notification set drifted"
    );
    Ok(())
}

pub fn validate_bundle(
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<ValidationReport> {
    validate_commit(expected_source_commit)?;
    validate_envelope(bundle, expected_source_commit)?;
    validate_scope_binding(bundle)?;
    validate_model(&bundle.model, bundle, expected_source_commit)?;
    validate_provider(&bundle.provider, bundle, expected_source_commit)?;
    validate_dispatch(&bundle.dispatch, bundle, expected_source_commit)?;
    validate_log(&bundle.durable_log, bundle, expected_source_commit)?;
    validate_tool_calls(&bundle.tool_calls, bundle, expected_source_commit)?;
    validate_effects(
        &bundle.effects,
        &bundle.tool_calls,
        bundle,
        expected_source_commit,
    )?;
    validate_terminal_result(&bundle.terminal_result, bundle, expected_source_commit)?;
    validate_adoption(&bundle.adoption, bundle, expected_source_commit)?;
    validate_recovery(&bundle.recovery, bundle, expected_source_commit)?;
    ensure!(
        bundle.run_id == expected_run_id(bundle)?,
        "OpenInterpreter run id is not derived from current commit and scoped dispatch"
    );
    ensure!(
        bundle.bundle_root == expected_bundle_root(bundle)?,
        "OpenInterpreter evidence bundle root is not derived from the complete capture"
    );
    let native_pass = native_candidate(bundle);
    let validator_status = if native_pass {
        ValidatorStatus::NativePass
    } else if matches!(
        bundle.provider.mode,
        ProviderMode::BlockedEnv | ProviderMode::Missing
    ) || matches!(
        bundle.provider.credentials,
        CredentialStatus::BlockedEnv | CredentialStatus::Missing
    ) {
        ValidatorStatus::BlockedEnv
    } else {
        ValidatorStatus::NotEvaluated
    };
    let replay_digest = digest_json(
        "hartevo-openinterpreter-native-acceptance-replay/v1",
        &ReplayMaterial {
            source_commit: expected_source_commit,
            run_id: &bundle.run_id,
            bundle_root: &bundle.bundle_root,
            validator_status,
            native_pass,
        },
    )?;
    Ok(ValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status,
        native_pass,
        source_commit: expected_source_commit.into(),
        contract_digest: contract_digest(),
        app_server_contract_digest: app_server_contract_digest(),
        run_id: bundle.run_id.clone(),
        project_id: bundle.project.id.clone(),
        mission_id: bundle.mission.id.clone(),
        model_digest: bundle.model.identity_digest.clone(),
        provider_digest: bundle.provider.identity_digest.clone(),
        bundle_root: bundle.bundle_root.clone(),
        replay_digest,
        missing_reasons: missing_reasons(bundle),
    })
}

fn validate_envelope(
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        bundle.schema_version == CONTRACT_SCHEMA_VERSION
            && bundle.document_type == DOCUMENT_TYPE
            && bundle.authority == AUTHORITY
            && bundle.release_decision == RELEASE_DECISION
            && bundle.source_commit == expected_source_commit,
        "OpenInterpreter acceptance envelope is stale or has invalid constants"
    );
    validate_commit(&bundle.source_commit)?;
    validate_digest(&bundle.run_id, "run id")?;
    validate_digest(&bundle.bundle_root, "bundle root")?;
    Ok(())
}

fn validate_scope_binding(bundle: &OpenInterpreterAcceptance) -> Result<()> {
    validate_identifier(&bundle.project.id, "Project id")?;
    validate_identifier(&bundle.mission.id, "Mission id")?;
    ensure!(bundle.project.revision > 0 && bundle.mission.revision > 0);
    validate_digest(&bundle.project.scope_digest, "Project scope digest")?;
    validate_digest(&bundle.mission.scope_digest, "Mission scope digest")?;
    let expected = expected_scope_digest(bundle);
    for scope in all_scopes(bundle) {
        ensure!(
            scope.project_id == bundle.project.id
                && scope.mission_id == bundle.mission.id
                && scope.scope_digest == expected,
            "Project/Mission scope binding drifted"
        );
    }
    Ok(())
}

fn validate_model(
    model: &ModelIdentity,
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    for (value, label) in [
        (&model.id, "model id"),
        (&model.provider, "model provider"),
        (&model.model, "model name"),
        (&model.revision, "model revision"),
    ] {
        validate_identifier(value, label)?;
    }
    ensure!(model.source_commit == expected_source_commit);
    ensure_scope(&model.scope, bundle)?;
    if !model.artifact_digest.is_empty() {
        validate_digest(&model.artifact_digest, "model artifact digest")?;
    }
    validate_digest(&model.identity_digest, "model identity digest")?;
    ensure!(
        model.identity_digest == expected_model_identity_digest(model)?,
        "model identity digest is not derived from its current identity"
    );
    Ok(())
}

fn validate_provider(
    provider: &ProviderIdentity,
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&provider.id, "provider id")?;
    if !provider.runner_id.is_empty() {
        validate_identifier(&provider.runner_id, "runner id")?;
    }
    ensure!(provider.source_commit == expected_source_commit);
    ensure_scope(&provider.scope, bundle)?;
    ensure!(provider.protocol_schema_digest == app_server_contract_digest());
    if !provider.runner_digest.is_empty() {
        validate_digest(&provider.runner_digest, "runner digest")?;
    }
    if provider.output_present {
        validate_digest(&provider.output_digest, "provider output digest")?;
    } else {
        ensure!(provider.output_digest.is_empty());
    }
    validate_digest(&provider.identity_digest, "provider identity digest")?;
    ensure!(
        provider.identity_digest == expected_provider_identity_digest(provider)?,
        "provider identity digest is not derived from its current identity"
    );
    if provider.mode == ProviderMode::Native {
        ensure!(provider.credentials == CredentialStatus::Verified);
        ensure!(!provider.runner_id.is_empty() && !provider.runner_digest.is_empty());
        ensure!(provider.output_present);
    } else {
        ensure!(provider.credentials != CredentialStatus::Verified);
    }
    Ok(())
}

fn validate_dispatch(
    dispatch: &DispatchRecord,
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(dispatch.sequence == 1 && dispatch.status == DispatchStatus::Dispatched);
    ensure!(dispatch.source_commit == expected_source_commit);
    validate_identifier(&dispatch.capability, "dispatch capability")?;
    validate_digest(&dispatch.request_digest, "dispatch request digest")?;
    ensure_scope(&dispatch.scope, bundle)?;
    Ok(())
}

fn validate_log(
    log: &DurableStreamLog,
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(log.source_commit == expected_source_commit);
    ensure!(log.revision == bundle.mission.revision && log.durable && log.model_visible);
    ensure_scope(&log.scope, bundle)?;
    ensure!(log.entries.len() >= REQUIRED_LOG_KINDS.len());
    ensure!(log.secret_scan.status == SecretScanStatus::Clean);
    ensure!(log.secret_scan.secret_count == 0);
    ensure!(log.secret_scan.scanned_event_count >= log.entries.len() as u64);
    validate_digest(&log.secret_scan.redaction_digest, "secret scan digest")?;
    validate_digest(&log.log_digest, "durable log digest")?;
    ensure!(log.log_digest == expected_log_digest(log)?);
    let mut saw_delta = false;
    let mut saw_tool_call = false;
    let mut saw_terminal = false;
    let mut prior_time = None;
    for (index, entry) in log.entries.iter().enumerate() {
        ensure!(
            entry.sequence == index as u64 + 1 && entry.source_commit == expected_source_commit
        );
        validate_digest(&entry.payload_digest, "stream payload digest")?;
        if let Some(previous) = prior_time {
            ensure!(entry.occurred_at > previous);
        }
        prior_time = Some(entry.occurred_at);
        saw_delta |= entry.kind == LogEntryKind::ModelVisibleDelta;
        saw_tool_call |= entry.kind == LogEntryKind::ToolCall;
        saw_terminal |= entry.kind == LogEntryKind::Terminal;
    }
    ensure!(log.entries[0].kind == REQUIRED_LOG_KINDS[0]);
    ensure!(
        log.entries[0].payload_digest == bundle.dispatch.request_digest,
        "durable log does not bind the dispatch request"
    );
    ensure!(saw_delta && saw_tool_call && saw_terminal);
    let first_delta = log
        .entries
        .iter()
        .find(|entry| entry.kind == LogEntryKind::ModelVisibleDelta)
        .context("model-visible stream delta")?;
    ensure!(log.first_model_visible_sequence == first_delta.sequence);
    ensure!(
        log.entries[0].occurred_at >= bundle.dispatch.dispatched_at,
        "durable model-visible log precedes dispatch authority"
    );
    Ok(())
}

fn validate_tool_calls(
    calls: &[ToolCallRecord],
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(!calls.is_empty());
    let mut call_ids = BTreeSet::new();
    for (index, call) in calls.iter().enumerate() {
        ensure!(call.sequence == index as u64 + 1 && call.source_commit == expected_source_commit);
        validate_identifier(&call.call_id, "tool call id")?;
        ensure!(call_ids.insert(call.call_id.as_str()));
        validate_identifier(&call.capability, "tool capability")?;
        validate_digest(&call.request_digest, "tool request digest")?;
        validate_digest(&call.response_digest, "tool response digest")?;
        ensure_scope(&call.scope, bundle)?;
        ensure!(call.started_at <= call.completed_at);
        ensure!(call.status == ToolCallStatus::Completed);
    }
    let tool_entries = bundle
        .durable_log
        .entries
        .iter()
        .filter(|entry| entry.kind == LogEntryKind::ToolCall)
        .count();
    ensure!(tool_entries >= calls.len());
    Ok(())
}

fn validate_effects(
    effects: &[EffectReceipt],
    calls: &[ToolCallRecord],
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(effects.len() == calls.len() && !effects.is_empty());
    let mut effect_ids = BTreeSet::new();
    for (index, (effect, call)) in effects.iter().zip(calls).enumerate() {
        ensure!(effect.sequence == index as u64 + 1);
        validate_identifier(&effect.effect_id, "effect id")?;
        ensure!(effect_ids.insert(effect.effect_id.as_str()));
        ensure!(effect.capability == call.capability);
        ensure!(effect.source_commit == expected_source_commit);
        ensure_scope(&effect.scope, bundle)?;
        ensure!(
            effect.requested_at >= call.completed_at && effect.receipt_at >= effect.requested_at
        );
        ensure!(effect.status == EffectStatus::Applied);
        validate_digest(&effect.receipt_digest, "effect receipt digest")?;
        ensure!(effect.receipt_digest == expected_effect_digest(effect)?);
        ensure!(effect.verification.sequence == effect.sequence);
        ensure!(effect.verification.status == crate::model::VerificationStatus::Verified);
        ensure!(effect.verification.verified_at >= effect.receipt_at);
        validate_digest(
            &effect.verification.verification_digest,
            "effect verification digest",
        )?;
        ensure!(
            effect.verification.verification_digest
                == expected_verification_digest(&effect.verification)?,
            "effect verification digest is not derived from the receipt"
        );
    }
    Ok(())
}

fn validate_terminal_result(
    result: &TerminalResult,
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(result.source_commit == expected_source_commit);
    ensure!(result.revision == bundle.mission.revision);
    ensure_scope(&result.scope, bundle)?;
    validate_digest(&result.result_digest, "terminal result digest")?;
    if result.provenance == ResultProvenance::NativeProvider {
        ensure!(result.status == ResultStatus::Completed);
        validate_digest(&result.evidence_root, "native evidence root")?;
    } else {
        ensure!(result.status == ResultStatus::NotEvaluated);
        ensure!(result.evidence_root.is_empty());
    }
    ensure!(
        result.result_digest == expected_terminal_digest(result)?,
        "terminal result digest is not derived from the typed result"
    );
    ensure!(result.completed_at >= bundle.effects.last().expect("validated effects").receipt_at);
    Ok(())
}

fn validate_adoption(
    adoption: &crate::model::AdoptionRecord,
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(adoption.source_commit == expected_source_commit);
    ensure!(adoption.revision == bundle.mission.revision);
    ensure_scope(&adoption.scope, bundle)?;
    ensure!(adoption.result_digest == bundle.terminal_result.result_digest);
    ensure!(adoption.evidence_root == bundle.terminal_result.evidence_root);
    ensure!(adoption.decided_at >= bundle.terminal_result.completed_at);
    validate_digest(&adoption.decision_digest, "adoption decision digest")?;
    ensure!(
        adoption.decision_digest == expected_adoption_digest(adoption)?,
        "adoption decision digest is not derived from the typed decision"
    );
    let expected = match (
        bundle.terminal_result.provenance,
        bundle.terminal_result.status,
    ) {
        (ResultProvenance::NativeProvider, ResultStatus::Completed) => AdoptionDecision::Adopt,
        (ResultProvenance::NativeProvider, ResultStatus::Failed) => AdoptionDecision::Reject,
        (_, ResultStatus::NotEvaluated) => AdoptionDecision::NotEvaluated,
        _ => anyhow::bail!("terminal result/adoption combination is not fail-closed"),
    };
    ensure!(adoption.decision == expected);
    Ok(())
}

fn validate_recovery(
    recovery: &[RecoveryReceipt],
    bundle: &OpenInterpreterAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(recovery.len() == REQUIRED_RECOVERY_HOOKS.len());
    let mut hooks = BTreeSet::new();
    let mut prior_time = bundle.adoption.decided_at;
    for (index, receipt) in recovery.iter().enumerate() {
        ensure!(receipt.sequence == index as u64 + 1);
        ensure!(hooks.insert(receipt.hook));
        ensure!(REQUIRED_RECOVERY_HOOKS.contains(&receipt.hook));
        ensure!(receipt.status == RecoveryStatus::Recovered);
        ensure!(receipt.source_commit == expected_source_commit);
        ensure_scope(&receipt.scope, bundle)?;
        ensure!(!receipt.old_evaluator_accepted && !receipt.old_decision_promotable);
        ensure!(receipt.occurred_at > prior_time);
        prior_time = receipt.occurred_at;
        validate_digest(&receipt.receipt_digest, "recovery receipt digest")?;
        ensure!(receipt.receipt_digest == expected_recovery_digest(receipt)?);
    }
    ensure!(hooks == REQUIRED_RECOVERY_HOOKS.into_iter().collect());
    Ok(())
}

fn native_candidate(bundle: &OpenInterpreterAcceptance) -> bool {
    bundle.provider.mode == ProviderMode::Native
        && bundle.provider.credentials == CredentialStatus::Verified
        && bundle.provider.output_present
        && bundle.model.artifact_digest.len() == 64
        && bundle.provider.runner_digest.len() == 64
        && bundle.provider.output_digest.len() == 64
        && bundle.terminal_result.status == ResultStatus::Completed
        && bundle.terminal_result.provenance == ResultProvenance::NativeProvider
        && bundle.adoption.decision == AdoptionDecision::Adopt
        && bundle.durable_log.secret_scan.status == SecretScanStatus::Clean
        && bundle.durable_log.secret_scan.secret_count == 0
        && bundle
            .effects
            .iter()
            .all(|effect| effect.status == EffectStatus::Applied)
}

fn missing_reasons(bundle: &OpenInterpreterAcceptance) -> Vec<String> {
    let mut reasons = Vec::new();
    if bundle.provider.mode != ProviderMode::Native {
        reasons.push("provider_provenance_is_not_native".into());
    }
    if bundle.provider.credentials != CredentialStatus::Verified {
        reasons.push("real_model_credentials_not_verified".into());
    }
    if !bundle.provider.output_present {
        reasons.push("real_model_output_missing".into());
    }
    if bundle.terminal_result.provenance != ResultProvenance::NativeProvider {
        reasons.push("terminal_result_is_not_native_provider".into());
    }
    if bundle.terminal_result.status != ResultStatus::Completed {
        reasons.push("terminal_result_is_not_completed".into());
    }
    if bundle.adoption.decision != AdoptionDecision::Adopt {
        reasons.push("adoption_is_not_adopt".into());
    }
    if bundle.durable_log.secret_scan.status != SecretScanStatus::Clean
        || bundle.durable_log.secret_scan.secret_count != 0
    {
        reasons.push("secret_scan_not_clean".into());
    }
    reasons
}

fn ensure_scope(scope: &SessionScope, bundle: &OpenInterpreterAcceptance) -> Result<()> {
    ensure!(
        scope.project_id == bundle.project.id
            && scope.mission_id == bundle.mission.id
            && scope.scope_digest == expected_scope_digest(bundle),
        "Project/Mission scope is not bound to this acceptance"
    );
    Ok(())
}

fn all_scopes(bundle: &OpenInterpreterAcceptance) -> Vec<&SessionScope> {
    let mut scopes = vec![
        &bundle.model.scope,
        &bundle.provider.scope,
        &bundle.dispatch.scope,
        &bundle.durable_log.scope,
        &bundle.terminal_result.scope,
        &bundle.adoption.scope,
    ];
    scopes.extend(bundle.tool_calls.iter().map(|call| &call.scope));
    scopes.extend(bundle.effects.iter().map(|effect| &effect.scope));
    scopes.extend(bundle.recovery.iter().map(|receipt| &receipt.scope));
    scopes
}

fn expected_scope_digest(bundle: &OpenInterpreterAcceptance) -> String {
    digest_json(
        "hartevo-openinterpreter-native-acceptance-scope/v1",
        &ScopeDigestMaterial {
            project_id: &bundle.project.id,
            project_revision: bundle.project.revision,
            project_scope_digest: &bundle.project.scope_digest,
            mission_id: &bundle.mission.id,
            mission_revision: bundle.mission.revision,
            mission_scope_digest: &bundle.mission.scope_digest,
        },
    )
    .expect("scope digest material serializes")
}

fn expected_run_id(bundle: &OpenInterpreterAcceptance) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-native-acceptance-run/v1",
        &RunIdMaterial {
            source_commit: &bundle.source_commit,
            project: &bundle.project,
            mission: &bundle.mission,
            model_identity_digest: &bundle.model.identity_digest,
            provider_identity_digest: &bundle.provider.identity_digest,
            dispatch_request_digest: &bundle.dispatch.request_digest,
        },
    )
    .context("derive OpenInterpreter run id")
}

fn expected_model_identity_digest(model: &ModelIdentity) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-model-identity/v1",
        &ModelIdentityMaterial {
            id: &model.id,
            provider: &model.provider,
            model: &model.model,
            revision: &model.revision,
            source_commit: &model.source_commit,
            scope: &model.scope,
            artifact_digest: &model.artifact_digest,
        },
    )
    .context("derive model identity digest")
}

fn expected_provider_identity_digest(provider: &ProviderIdentity) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-provider-identity/v1",
        &ProviderIdentityMaterial {
            id: &provider.id,
            mode: provider.mode,
            runner_id: &provider.runner_id,
            runner_digest: &provider.runner_digest,
            protocol_schema_digest: &provider.protocol_schema_digest,
            credentials: provider.credentials,
            output_present: provider.output_present,
            output_digest: &provider.output_digest,
            source_commit: &provider.source_commit,
            scope: &provider.scope,
        },
    )
    .context("derive provider identity digest")
}

fn expected_log_digest(log: &DurableStreamLog) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-durable-stream-log/v1",
        &LogMaterial {
            source_commit: &log.source_commit,
            scope: &log.scope,
            revision: log.revision,
            entries: &log.entries,
            first_model_visible_sequence: log.first_model_visible_sequence,
            durable: log.durable,
            model_visible: log.model_visible,
            secret_scan: &log.secret_scan,
        },
    )
    .context("derive durable stream log digest")
}

fn expected_verification_digest(verification: &EffectVerification) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-effect-verification/v1",
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
        "hartevo-openinterpreter-effect-receipt/v1",
        &EffectMaterial {
            sequence: effect.sequence,
            effect_id: &effect.effect_id,
            capability: &effect.capability,
            source_commit: &effect.source_commit,
            scope: &effect.scope,
            requested_at: effect.requested_at,
            receipt_at: effect.receipt_at,
            status: effect.status,
            verification: &effect.verification,
        },
    )
    .context("derive effect receipt digest")
}

fn expected_terminal_digest(result: &TerminalResult) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-terminal-result/v1",
        &TerminalMaterial {
            source_commit: &result.source_commit,
            scope: &result.scope,
            revision: result.revision,
            status: result.status,
            provenance: result.provenance,
            evidence_root: &result.evidence_root,
            completed_at: result.completed_at,
        },
    )
    .context("derive terminal result digest")
}

fn expected_adoption_digest(adoption: &crate::model::AdoptionRecord) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-adoption/v1",
        &AdoptionMaterial {
            source_commit: &adoption.source_commit,
            scope: &adoption.scope,
            revision: adoption.revision,
            decision: adoption.decision,
            result_digest: &adoption.result_digest,
            evidence_root: &adoption.evidence_root,
            decided_at: adoption.decided_at,
        },
    )
    .context("derive adoption digest")
}

fn expected_recovery_digest(receipt: &RecoveryReceipt) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-recovery-receipt/v1",
        &RecoveryMaterial {
            sequence: receipt.sequence,
            hook: receipt.hook,
            status: receipt.status,
            source_commit: &receipt.source_commit,
            scope: &receipt.scope,
            occurred_at: receipt.occurred_at,
            old_evaluator_accepted: receipt.old_evaluator_accepted,
            old_decision_promotable: receipt.old_decision_promotable,
        },
    )
    .context("derive recovery receipt digest")
}

fn expected_bundle_root(bundle: &OpenInterpreterAcceptance) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-native-acceptance-bundle/v1",
        &BundleRootMaterial {
            schema_version: &bundle.schema_version,
            document_type: &bundle.document_type,
            authority: &bundle.authority,
            release_decision: &bundle.release_decision,
            source_commit: &bundle.source_commit,
            run_id: &bundle.run_id,
            project: &bundle.project,
            mission: &bundle.mission,
            model: &bundle.model,
            provider: &bundle.provider,
            dispatch: &bundle.dispatch,
            durable_log: &bundle.durable_log,
            tool_calls: &bundle.tool_calls,
            effects: &bundle.effects,
            terminal_result: &bundle.terminal_result,
            adoption: &bundle.adoption,
            recovery: &bundle.recovery,
        },
    )
    .context("derive OpenInterpreter bundle root")
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
        .context("expected a JSON string array")?
        .iter()
        .map(|item| item.as_str().context("expected a JSON string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "JSON string array contains duplicates"
    );
    Ok(values.into_iter().collect())
}

fn string_array(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .context("expected JSON array")?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).context("expected string"))
        .collect::<Result<Vec<_>>>()
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

    fn bundle(mode: ProviderMode) -> OpenInterpreterAcceptance {
        let source_commit = source_commit();
        let project = ProjectScope {
            id: "project-oi-native".into(),
            revision: 1,
            scope_digest: digest('1'),
        };
        let mission = MissionScope {
            id: "mission-germany".into(),
            revision: 2,
            scope_digest: digest('2'),
        };
        let project_id = project.id.clone();
        let mission_id = mission.id.clone();
        let scope_digest = digest_json(
            "hartevo-openinterpreter-native-acceptance-scope/v1",
            &ScopeDigestMaterial {
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
        let native = mode == ProviderMode::Native;
        let credentials = if native {
            CredentialStatus::Verified
        } else {
            CredentialStatus::BlockedEnv
        };
        let artifact_digest = if native { digest('a') } else { String::new() };
        let runner_digest = if native { digest('b') } else { String::new() };
        let output_digest = if native { digest('c') } else { String::new() };
        let mut model = ModelIdentity {
            id: "model-oi".into(),
            provider: "openinterpreter".into(),
            model: "gpt-native".into(),
            revision: "2026-08".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            identity_digest: String::new(),
            artifact_digest,
        };
        model.identity_digest = expected_model_identity_digest(&model).unwrap();
        let mut provider = ProviderIdentity {
            id: "provider-oi".into(),
            mode,
            runner_id: if native {
                "runner-oi".into()
            } else {
                String::new()
            },
            runner_digest,
            protocol_schema_digest: app_server_contract_digest(),
            credentials,
            output_present: native,
            output_digest,
            source_commit: source_commit.clone(),
            scope: scope(),
            identity_digest: String::new(),
        };
        provider.identity_digest = expected_provider_identity_digest(&provider).unwrap();
        let start = Utc::now();
        let dispatch = DispatchRecord {
            sequence: 1,
            source_commit: source_commit.clone(),
            scope: scope(),
            capability: "research.read".into(),
            request_digest: digest('d'),
            status: DispatchStatus::Dispatched,
            dispatched_at: start,
        };
        let entries = vec![
            LogEntry {
                sequence: 1,
                kind: LogEntryKind::Dispatch,
                source_commit: source_commit.clone(),
                occurred_at: start + Duration::seconds(1),
                payload_digest: dispatch.request_digest.clone(),
            },
            LogEntry {
                sequence: 2,
                kind: LogEntryKind::ModelVisibleDelta,
                source_commit: source_commit.clone(),
                occurred_at: start + Duration::seconds(2),
                payload_digest: digest('e'),
            },
            LogEntry {
                sequence: 3,
                kind: LogEntryKind::ToolCall,
                source_commit: source_commit.clone(),
                occurred_at: start + Duration::seconds(3),
                payload_digest: digest('f'),
            },
            LogEntry {
                sequence: 4,
                kind: LogEntryKind::Terminal,
                source_commit: source_commit.clone(),
                occurred_at: start + Duration::seconds(4),
                payload_digest: digest('0'),
            },
        ];
        let secret_scan = crate::model::SecretScan {
            status: SecretScanStatus::Clean,
            scanned_event_count: 4,
            secret_count: 0,
            redaction_digest: digest('1'),
        };
        let mut durable_log = DurableStreamLog {
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: mission.revision,
            entries,
            first_model_visible_sequence: 2,
            durable: true,
            model_visible: true,
            secret_scan,
            log_digest: String::new(),
        };
        durable_log.log_digest = expected_log_digest(&durable_log).unwrap();
        let mut call = ToolCallRecord {
            sequence: 1,
            call_id: "call-1".into(),
            capability: "research.read".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            request_digest: digest('2'),
            response_digest: digest('3'),
            started_at: start + Duration::seconds(3),
            completed_at: start + Duration::seconds(5),
            status: ToolCallStatus::Completed,
        };
        let _ = &mut call;
        let mut verification = EffectVerification {
            sequence: 1,
            status: crate::model::VerificationStatus::Verified,
            verified_at: start + Duration::seconds(8),
            verification_digest: String::new(),
        };
        verification.verification_digest = expected_verification_digest(&verification).unwrap();
        let mut effect = EffectReceipt {
            sequence: 1,
            effect_id: "effect-1".into(),
            capability: "research.read".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            requested_at: start + Duration::seconds(6),
            receipt_at: start + Duration::seconds(7),
            status: EffectStatus::Applied,
            receipt_digest: String::new(),
            verification,
        };
        effect.receipt_digest = expected_effect_digest(&effect).unwrap();
        let result_provenance = if native {
            ResultProvenance::NativeProvider
        } else {
            ResultProvenance::BlockedEnv
        };
        let result_status = if native {
            ResultStatus::Completed
        } else {
            ResultStatus::NotEvaluated
        };
        let evidence_root = if native { digest('4') } else { String::new() };
        let mut terminal_result = TerminalResult {
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: mission.revision,
            status: result_status,
            provenance: result_provenance,
            result_digest: String::new(),
            evidence_root,
            completed_at: start + Duration::seconds(9),
        };
        terminal_result.result_digest = expected_terminal_digest(&terminal_result).unwrap();
        let adoption_decision = if native {
            AdoptionDecision::Adopt
        } else {
            AdoptionDecision::NotEvaluated
        };
        let mut adoption = crate::model::AdoptionRecord {
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: mission.revision,
            decision: adoption_decision,
            result_digest: terminal_result.result_digest.clone(),
            evidence_root: terminal_result.evidence_root.clone(),
            decision_digest: String::new(),
            decided_at: start + Duration::seconds(10),
        };
        adoption.decision_digest = expected_adoption_digest(&adoption).unwrap();
        let mut recovery = Vec::new();
        for (index, hook) in REQUIRED_RECOVERY_HOOKS.into_iter().enumerate() {
            let mut receipt = RecoveryReceipt {
                sequence: index as u64 + 1,
                hook,
                status: RecoveryStatus::Recovered,
                source_commit: source_commit.clone(),
                scope: scope(),
                occurred_at: start + Duration::seconds(index as i64 + 11),
                receipt_digest: String::new(),
                old_evaluator_accepted: false,
                old_decision_promotable: false,
            };
            receipt.receipt_digest = expected_recovery_digest(&receipt).unwrap();
            recovery.push(receipt);
        }
        let mut bundle = OpenInterpreterAcceptance {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            document_type: DOCUMENT_TYPE.into(),
            authority: AUTHORITY.into(),
            release_decision: RELEASE_DECISION.into(),
            source_commit,
            run_id: String::new(),
            project,
            mission,
            model,
            provider,
            dispatch,
            durable_log,
            tool_calls: vec![call],
            effects: vec![effect],
            terminal_result,
            adoption,
            recovery,
            bundle_root: String::new(),
        };
        bundle.run_id = expected_run_id(&bundle).unwrap();
        bundle.bundle_root = expected_bundle_root(&bundle).unwrap();
        bundle
    }

    #[test]
    fn checked_in_contract_and_app_server_protocol_are_closed() {
        validate_contract().expect("OI acceptance contract");
        assert!(is_lower_hex(&contract_digest(), 32));
        assert!(is_lower_hex(&app_server_contract_digest(), 32));
    }

    #[test]
    fn native_capture_replays_to_same_current_commit_conclusion() {
        let bundle = bundle(ProviderMode::Native);
        let commit = source_commit();
        let first = validate_bundle(&bundle, &commit).expect("native OI capture");
        let replay = validate_bundle(&bundle, &commit).expect("replayed OI capture");
        assert_eq!(first, replay);
        assert_eq!(first.validator_status, ValidatorStatus::NativePass);
        assert!(first.native_pass);
    }

    #[test]
    fn simulator_fixture_and_blocked_env_never_pass_native() {
        for mode in [
            ProviderMode::Simulator,
            ProviderMode::Fixture,
            ProviderMode::BlockedEnv,
        ] {
            let report = validate_bundle(&bundle(mode), &source_commit()).unwrap();
            assert!(!report.native_pass);
            assert_ne!(report.validator_status, ValidatorStatus::NativePass);
        }
    }

    #[test]
    fn tamper_cross_mission_and_recovery_mutations_are_rejected() {
        let commit = source_commit();
        let mut tampered = bundle(ProviderMode::Native);
        let replacement = if tampered.bundle_root.starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered.bundle_root.replace_range(..1, replacement);
        assert!(validate_bundle(&tampered, &commit).is_err());

        let mut cross_mission = bundle(ProviderMode::Native);
        cross_mission.dispatch.scope.mission_id = "other-mission".into();
        assert!(validate_bundle(&cross_mission, &commit).is_err());

        let mut recovery = bundle(ProviderMode::Native);
        recovery.recovery[0].old_decision_promotable = true;
        assert!(validate_bundle(&recovery, &commit).is_err());
    }

    #[test]
    fn stale_commit_and_missing_final_recovery_are_rejected() {
        let bundle = bundle(ProviderMode::Native);
        assert!(validate_bundle(&bundle, &"0".repeat(40)).is_err());
        let mut value = serde_json::to_value(bundle).unwrap();
        value.as_object_mut().unwrap().remove("recovery");
        assert!(
            crate::model::parse_strict_json::<OpenInterpreterAcceptance>(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn secret_and_effect_verification_mutations_fail_closed() {
        let commit = source_commit();
        let mut secret = bundle(ProviderMode::Native);
        secret.durable_log.secret_scan.secret_count = 1;
        assert!(validate_bundle(&secret, &commit).is_err());

        let mut verification = bundle(ProviderMode::Native);
        verification.effects[0].verification.status = crate::model::VerificationStatus::Failed;
        assert!(validate_bundle(&verification, &commit).is_err());
    }

    #[test]
    fn strict_capture_json_rejects_unknown_and_duplicate_fields() {
        let value = serde_json::to_value(bundle(ProviderMode::Native)).unwrap();
        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("forgedPass".into(), json!(true));
        assert!(
            crate::model::parse_strict_json::<OpenInterpreterAcceptance>(
                &serde_json::to_vec(&unknown).unwrap()
            )
            .is_err()
        );
        assert!(
            crate::model::parse_strict_json::<OpenInterpreterAcceptance>(
                br#"{"schemaVersion":"x","schemaVersion":"y"}"#
            )
            .is_err()
        );
    }
}
