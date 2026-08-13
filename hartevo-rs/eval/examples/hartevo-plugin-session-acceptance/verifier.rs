use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::Value;

use crate::digest::{digest_json, is_lower_hex, sha256_hex};
use crate::model::{
    AdoptionDecision, AdoptionRecord, DurableLogRecord, EvidenceProvenance, InvokeRecord,
    LogStatus, MountRecord, MountStatus, PluginSessionAcceptance, ProviderMode, RecoveryHook,
    ResultRecord, ResultStatus, SessionScope,
};

pub const CONTRACT_PATH: &str = "contracts/plugins/plugin-session-acceptance.v1.json";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-plugin-session-acceptance/v1";
pub const DOCUMENT_TYPE: &str = "plugin_session_acceptance";
pub const AUTHORITY: &str = "plugin_session_acceptance_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-plugin-session-acceptance-report/v1";

const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/plugins/plugin-session-acceptance.v1.json");
const REQUIRED_EVENT_TYPES: [&str; 5] = [
    "mount",
    "model_visible_durable_log",
    "invoke",
    "result",
    "adopt",
];
const REQUIRED_RECOVERY_HOOKS: [RecoveryHook; 3] = [
    RecoveryHook::Unmount,
    RecoveryHook::Revoke,
    RecoveryHook::Crash,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidatorStatus {
    NativePass,
    NotEvaluated,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub release_decision: &'static str,
    pub validator_status: ValidatorStatus,
    pub native_pass: bool,
    pub source_commit: String,
    pub contract_digest: String,
    pub project_id: String,
    pub mission_id: String,
    pub revision: u64,
    pub evidence_root: String,
    pub provider_mode: String,
    pub missing_reasons: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultDigestMaterial<'a> {
    status: ResultStatus,
    provenance: EvidenceProvenance,
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    evidence_root: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptionDigestMaterial<'a> {
    decision: AdoptionDecision,
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    result_digest: &'a str,
    evidence_root: &'a str,
}

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

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
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

pub fn read_session(path: impl AsRef<Path>) -> Result<PluginSessionAcceptance> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("read acceptance input {}", path.display()))?;
    crate::model::parse_strict_json(&bytes)
        .with_context(|| format!("parse strict acceptance input {}", path.display()))
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES)
        .context("plugin session acceptance contract is not strict JSON")?;
    validate_contract_root(&contract)?;
    validate_contract_definitions(&contract)
}

fn validate_contract_root(contract: &Value) -> Result<()> {
    ensure!(
        contract.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema"),
        "acceptance contract must declare JSON Schema 2020-12"
    );
    ensure!(
        contract.get("type").and_then(Value::as_str) == Some("object")
            && contract
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false),
        "acceptance contract root must be a closed object"
    );
    ensure!(
        contract.get("$id").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION),
        "acceptance contract id drifted"
    );
    let required = exact_string_set(
        contract
            .get("required")
            .context("acceptance contract required list")?,
    )?;
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "project",
        "mission",
        "service",
        "provider",
        "consumer",
        "mount",
        "durableLog",
        "invoke",
        "result",
        "adoption",
        "recoveryHooks",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        required == expected,
        "acceptance contract root required set drifted"
    );
    let properties = contract
        .get("properties")
        .and_then(Value::as_object)
        .context("acceptance contract root properties")?;
    let property_names = properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        property_names == expected.iter().copied().collect::<BTreeSet<_>>(),
        "acceptance contract root property set drifted"
    );
    for (property, expected_const) in [
        ("schemaVersion", CONTRACT_SCHEMA_VERSION),
        ("documentType", DOCUMENT_TYPE),
        ("authority", AUTHORITY),
        ("releaseDecision", RELEASE_DECISION),
    ] {
        ensure!(
            properties
                .get(property)
                .and_then(|value| value.get("const"))
                .and_then(Value::as_str)
                == Some(expected_const),
            "acceptance contract {property} constant drifted"
        );
    }
    Ok(())
}

fn validate_contract_definitions(contract: &Value) -> Result<()> {
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("acceptance contract definitions")?;
    let expected_defs = [
        "adoption",
        "consumer",
        "durableLog",
        "invoke",
        "mission",
        "mount",
        "project",
        "provider",
        "recovery",
        "result",
        "scope",
        "service",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let definition_names = defs.keys().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        definition_names == expected_defs.iter().copied().collect::<BTreeSet<_>>(),
        "acceptance contract definition set drifted"
    );
    for definition in defs.values() {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "acceptance contract nested definition must be closed"
        );
    }
    Ok(())
}

pub fn validate_session(
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<ValidationReport> {
    validate_commit(expected_source_commit)?;
    ensure!(
        session.schema_version == CONTRACT_SCHEMA_VERSION
            && session.document_type == DOCUMENT_TYPE
            && session.authority == AUTHORITY
            && session.release_decision == RELEASE_DECISION,
        "acceptance envelope schema, document type, authority or Release decision drifted"
    );
    ensure!(
        session.source_commit == expected_source_commit,
        "acceptance envelope is stale for the current source commit"
    );
    validate_scope_identity(session, expected_source_commit)?;
    validate_roles(session, expected_source_commit)?;
    validate_mount(&session.mount, session, expected_source_commit)?;
    validate_durable_log(&session.durable_log, session, expected_source_commit)?;
    validate_invoke(&session.invoke, session, expected_source_commit)?;
    let native_candidate = validate_result_and_adoption(session, expected_source_commit)?;
    validate_recovery(session, expected_source_commit)?;

    let mut missing_reasons = Vec::new();
    if !native_candidate {
        if !session.provider.output_present {
            missing_reasons.push("real_provider_output_missing".into());
        }
        if session.provider.mode != ProviderMode::Native {
            missing_reasons.push("provider_provenance_is_not_native".into());
        }
        if session.result.provenance != EvidenceProvenance::NativeProvider {
            missing_reasons.push("result_provenance_is_not_native_provider".into());
        }
    }
    let (validator_status, native_pass) = if native_candidate {
        (ValidatorStatus::NativePass, true)
    } else {
        (ValidatorStatus::NotEvaluated, false)
    };
    Ok(ValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status,
        native_pass,
        source_commit: expected_source_commit.into(),
        contract_digest: contract_digest(),
        project_id: session.project.id.clone(),
        mission_id: session.mission.id.clone(),
        revision: session.mount.revision,
        evidence_root: session.result.evidence_root.clone(),
        provider_mode: format_provider_mode(session.provider.mode),
        missing_reasons,
    })
}

fn validate_scope_identity(
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&session.project.id, "Project id")?;
    validate_identifier(&session.mission.id, "Mission id")?;
    ensure!(
        session.project.revision > 0,
        "Project revision must be positive"
    );
    ensure!(
        session.mission.revision > 0,
        "Mission revision must be positive"
    );
    validate_digest(&session.project.scope_digest, "Project scope digest")?;
    validate_digest(&session.mission.scope_digest, "Mission scope digest")?;
    let expected_scope = expected_scope_digest(session);
    for scope in session_scopes(session) {
        ensure!(
            scope.project_id == session.project.id
                && scope.mission_id == session.mission.id
                && scope.scope_digest == expected_scope,
            "Project/Mission scope binding drifted"
        );
    }
    ensure!(
        session.source_commit == expected_source_commit,
        "top-level source commit drifted"
    );
    Ok(())
}

fn validate_roles(session: &PluginSessionAcceptance, expected_source_commit: &str) -> Result<()> {
    validate_identifier(&session.service.id, "service id")?;
    validate_identifier(&session.provider.id, "provider id")?;
    validate_identifier(&session.consumer.id, "consumer id")?;
    for source_commit in [
        &session.service.source_commit,
        &session.provider.source_commit,
        &session.consumer.source_commit,
    ] {
        ensure!(
            source_commit == expected_source_commit,
            "service/provider/consumer source commit drifted"
        );
    }
    ensure!(session.service.mounted, "service is not mounted");
    let provider_output_digest_valid = if session.provider.output_present {
        validate_digest(&session.provider.output_digest, "provider output digest")?;
        true
    } else {
        ensure!(
            session.provider.output_digest.is_empty(),
            "provider output digest must be empty when output is absent"
        );
        false
    };
    if session.provider.mode == ProviderMode::Native {
        ensure!(
            session.provider.output_present == provider_output_digest_valid,
            "native provider output must be present with a valid digest"
        );
    }
    Ok(())
}

fn validate_mount(
    mount: &MountRecord,
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        mount.status == MountStatus::Mounted,
        "mount did not complete"
    );
    ensure!(
        mount.source_commit == expected_source_commit,
        "mount commit drifted"
    );
    validate_identifier(&mount.evaluator_id, "evaluator id")?;
    ensure!(mount.revision > 0, "mount revision must be positive");
    validate_digest(&mount.evidence_root, "mount evidence root")?;
    ensure!(
        mount.scope.project_id == session.project.id
            && mount.scope.mission_id == session.mission.id,
        "mount scope is not bound to the Project/Mission"
    );
    Ok(())
}

fn validate_durable_log(
    log: &DurableLogRecord,
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        log.status == LogStatus::ModelVisibleDurable
            && log.model_visible
            && log.durable
            && log.event_count >= REQUIRED_EVENT_TYPES.len() as u64,
        "durable model-visible log proof is incomplete"
    );
    ensure!(
        log.source_commit == expected_source_commit,
        "durable log commit drifted"
    );
    validate_digest(&log.log_digest, "durable log digest")?;
    ensure!(
        log.event_types == REQUIRED_EVENT_TYPES,
        "durable log event sequence is not the exact acceptance sequence"
    );
    ensure_scope(&log.scope, session)?;
    Ok(())
}

fn validate_invoke(
    invoke: &InvokeRecord,
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        invoke.status == crate::model::InvokeStatus::Completed
            && invoke.sequence == 1
            && invoke.executor_once,
        "invoke proof must be completed exactly once"
    );
    ensure!(
        invoke.source_commit == expected_source_commit,
        "invoke commit drifted"
    );
    validate_digest(&invoke.request_digest, "invoke request digest")?;
    ensure_scope(&invoke.scope, session)?;
    Ok(())
}

fn validate_result_and_adoption(
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<bool> {
    let result = &session.result;
    ensure!(
        result.source_commit == expected_source_commit,
        "result commit drifted"
    );
    ensure!(
        result.revision == session.mount.revision,
        "result revision drifted"
    );
    ensure_scope(&result.scope, session)?;
    ensure_scope(&session.adoption.scope, session)?;
    ensure!(
        session.adoption.source_commit == expected_source_commit
            && session.adoption.revision == result.revision
            && session.adoption.result_digest == result.result_digest
            && session.adoption.evidence_root == result.evidence_root,
        "adoption is not bound to the exact result envelope"
    );
    ensure!(
        session.adoption.decision_digest == expected_adoption_digest(&session.adoption)?,
        "adoption decision digest is not derived from its typed fields"
    );
    validate_digest(
        &session.adoption.decision_digest,
        "adoption decision digest",
    )?;
    let provider_is_native = session.provider.mode == ProviderMode::Native
        && session.provider.output_present
        && validate_digest(&session.provider.output_digest, "provider output digest").is_ok();
    let result_is_native = result.provenance == EvidenceProvenance::NativeProvider;
    if result_is_native {
        ensure!(
            provider_is_native,
            "native result lacks a real native provider output"
        );
        ensure!(
            result.evidence_root == session.provider.output_digest,
            "native result evidence root does not match provider output"
        );
        validate_digest(&result.result_digest, "native result digest")?;
        validate_digest(&result.evidence_root, "native result evidence root")?;
        ensure!(
            result.result_digest == expected_result_digest(result)?,
            "native result digest is not derived from its typed fields"
        );
        ensure!(
            result.evidence_root == session.mount.evidence_root,
            "native result evidence root is not the mounted evidence root"
        );
    } else {
        ensure!(
            result.status == ResultStatus::NotEvaluated,
            "fixture, simulator, ignored or BLOCKED_ENV evidence cannot claim completion"
        );
        ensure!(
            result.provenance != EvidenceProvenance::NativeProvider,
            "missing native provider output must use non-native provenance"
        );
        ensure!(
            result.result_digest.is_empty() && result.evidence_root.is_empty(),
            "non-native NOT_EVALUATED result cannot carry native evidence roots"
        );
    }
    let expected_decision = match (result.provenance, result.status) {
        (EvidenceProvenance::NativeProvider, ResultStatus::Completed) if provider_is_native => {
            AdoptionDecision::Adopt
        }
        (EvidenceProvenance::NativeProvider, ResultStatus::Failed) if provider_is_native => {
            AdoptionDecision::Reject
        }
        (_, ResultStatus::NotEvaluated) => AdoptionDecision::NotEvaluated,
        _ => bail!("result/adoption combination is not fail-closed"),
    };
    ensure!(
        session.adoption.decision == expected_decision,
        "adoption decision does not match the verified result"
    );
    ensure!(
        session.consumer.adopted == (expected_decision == AdoptionDecision::Adopt),
        "consumer adoption state is not derived from the selected decision"
    );
    Ok(expected_decision == AdoptionDecision::Adopt)
}

fn validate_recovery(
    session: &PluginSessionAcceptance,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        session.recovery_hooks.len() == REQUIRED_RECOVERY_HOOKS.len(),
        "acceptance requires unmount, revoke and crash recovery proofs"
    );
    let mut hooks = BTreeSet::new();
    for recovery in &session.recovery_hooks {
        ensure!(hooks.insert(recovery.hook), "duplicate recovery hook proof");
        ensure!(
            REQUIRED_RECOVERY_HOOKS.contains(&recovery.hook),
            "unknown recovery hook proof"
        );
        ensure!(
            recovery.source_commit == expected_source_commit,
            "recovery commit drifted"
        );
        ensure!(
            recovery.revision == session.mount.revision,
            "recovery revision drifted"
        );
        ensure!(
            !recovery.old_evaluator_accepted && !recovery.old_decision_promotable,
            "old evaluator/decision remains usable after recovery"
        );
        ensure!(
            recovery.evidence_root == session.mount.evidence_root,
            "recovery proof is not bound to the mounted evidence root"
        );
        ensure_scope(&recovery.scope, session)?;
    }
    ensure!(
        hooks == REQUIRED_RECOVERY_HOOKS.into_iter().collect(),
        "recovery hook set is incomplete"
    );
    Ok(())
}

fn ensure_scope(scope: &SessionScope, session: &PluginSessionAcceptance) -> Result<()> {
    let expected = expected_scope_digest(session);
    ensure!(
        scope.project_id == session.project.id
            && scope.mission_id == session.mission.id
            && scope.scope_digest == expected,
        "Project/Mission scope binding drifted"
    );
    Ok(())
}

fn session_scopes(session: &PluginSessionAcceptance) -> Vec<&SessionScope> {
    vec![
        &session.service.scope,
        &session.provider.scope,
        &session.consumer.scope,
        &session.mount.scope,
        &session.durable_log.scope,
        &session.invoke.scope,
        &session.result.scope,
        &session.adoption.scope,
    ]
}

fn expected_scope_digest(session: &PluginSessionAcceptance) -> String {
    digest_json(
        "hartevo-plugin-session-scope/v1",
        &ScopeDigestMaterial {
            project_id: &session.project.id,
            project_revision: session.project.revision,
            project_scope_digest: &session.project.scope_digest,
            mission_id: &session.mission.id,
            mission_revision: session.mission.revision,
            mission_scope_digest: &session.mission.scope_digest,
        },
    )
    .expect("scope digest material is serializable")
}

fn expected_result_digest(result: &ResultRecord) -> Result<String> {
    digest_json(
        "hartevo-plugin-session-acceptance-result/v1",
        &ResultDigestMaterial {
            status: result.status,
            provenance: result.provenance,
            source_commit: &result.source_commit,
            scope: &result.scope,
            revision: result.revision,
            evidence_root: &result.evidence_root,
        },
    )
    .context("derive typed result digest")
}

fn expected_adoption_digest(adoption: &AdoptionRecord) -> Result<String> {
    digest_json(
        "hartevo-plugin-session-acceptance-adoption/v1",
        &AdoptionDigestMaterial {
            decision: adoption.decision,
            source_commit: &adoption.source_commit,
            scope: &adoption.scope,
            revision: adoption.revision,
            result_digest: &adoption.result_digest,
            evidence_root: &adoption.evidence_root,
        },
    )
    .context("derive typed adoption digest")
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} is required");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)),
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
        "source commit must be a lowercase 40-hex Git commit"
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

fn format_provider_mode(mode: ProviderMode) -> String {
    match mode {
        ProviderMode::Native => "native".into(),
        ProviderMode::Simulator => "simulator".into(),
        ProviderMode::Fixture => "fixture".into(),
        ProviderMode::Ignored => "ignored".into(),
        ProviderMode::BlockedEnv => "blocked_env".into(),
        ProviderMode::Missing => "missing".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AdoptionRecord, ConsumerBinding, DurableLogRecord, EvidenceProvenance, InvokeRecord,
        InvokeStatus, LogStatus, MissionScope, MountRecord, MountStatus, ProjectScope,
        ProviderBinding, RecoveryRecord, ResultRecord, ServiceBinding,
    };

    fn source_commit() -> String {
        current_source_commit().expect("Git source commit")
    }

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn session(
        provider_mode: ProviderMode,
        output_present: bool,
        provenance: EvidenceProvenance,
        result_status: ResultStatus,
        adoption: AdoptionDecision,
    ) -> PluginSessionAcceptance {
        let source_commit = source_commit();
        let project = ProjectScope {
            id: "project-native".into(),
            revision: 1,
            scope_digest: digest('1'),
        };
        let mission = MissionScope {
            id: "mission-market".into(),
            revision: 1,
            scope_digest: digest('2'),
        };
        let project_id = project.id.clone();
        let mission_id = mission.id.clone();
        let scope_digest = digest_json(
            "hartevo-plugin-session-scope/v1",
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
        let output_digest = if output_present {
            digest('a')
        } else {
            String::new()
        };
        let evidence_root = if provenance == EvidenceProvenance::NativeProvider {
            output_digest.clone()
        } else {
            String::new()
        };
        let mount_root = if provenance == EvidenceProvenance::NativeProvider {
            output_digest.clone()
        } else {
            digest('c')
        };
        let mut value = PluginSessionAcceptance {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            document_type: DOCUMENT_TYPE.into(),
            authority: AUTHORITY.into(),
            release_decision: RELEASE_DECISION.into(),
            source_commit: source_commit.clone(),
            project,
            mission,
            service: ServiceBinding {
                id: "service".into(),
                source_commit: source_commit.clone(),
                scope: scope(),
                mounted: true,
            },
            provider: ProviderBinding {
                id: "provider".into(),
                source_commit: source_commit.clone(),
                scope: scope(),
                mode: provider_mode,
                output_present,
                output_digest,
            },
            consumer: ConsumerBinding {
                id: "consumer".into(),
                source_commit: source_commit.clone(),
                scope: scope(),
                adopted: adoption == AdoptionDecision::Adopt,
            },
            mount: MountRecord {
                status: MountStatus::Mounted,
                source_commit: source_commit.clone(),
                scope: scope(),
                revision: 7,
                evaluator_id: "evaluator".into(),
                evidence_root: mount_root.clone(),
            },
            durable_log: DurableLogRecord {
                status: LogStatus::ModelVisibleDurable,
                source_commit: source_commit.clone(),
                scope: scope(),
                event_count: 5,
                event_types: REQUIRED_EVENT_TYPES
                    .iter()
                    .map(|event| (*event).into())
                    .collect(),
                model_visible: true,
                durable: true,
                log_digest: digest('e'),
            },
            invoke: InvokeRecord {
                status: InvokeStatus::Completed,
                source_commit: source_commit.clone(),
                scope: scope(),
                sequence: 1,
                request_digest: digest('f'),
                executor_once: true,
            },
            result: ResultRecord {
                status: result_status,
                provenance,
                source_commit: source_commit.clone(),
                scope: scope(),
                revision: 7,
                result_digest: String::new(),
                evidence_root,
            },
            adoption: AdoptionRecord {
                decision: adoption,
                source_commit: source_commit.clone(),
                scope: scope(),
                revision: 7,
                result_digest: String::new(),
                evidence_root: String::new(),
                decision_digest: String::new(),
            },
            recovery_hooks: REQUIRED_RECOVERY_HOOKS
                .iter()
                .map(|hook| RecoveryRecord {
                    hook: *hook,
                    source_commit: source_commit.clone(),
                    scope: scope(),
                    revision: 7,
                    evidence_root: mount_root.clone(),
                    old_evaluator_accepted: false,
                    old_decision_promotable: false,
                })
                .collect(),
        };
        if provenance == EvidenceProvenance::NativeProvider {
            value.result.result_digest = expected_result_digest(&value.result).unwrap();
        }
        value.adoption.result_digest = value.result.result_digest.clone();
        value.adoption.evidence_root = value.result.evidence_root.clone();
        value.adoption.decision_digest = expected_adoption_digest(&value.adoption).unwrap();
        value
    }

    #[test]
    fn checked_in_contract_is_closed_and_current() {
        validate_contract().expect("acceptance contract");
        assert!(is_lower_hex(&contract_digest(), 32));
    }

    #[test]
    fn native_provider_current_commit_session_passes_acceptance_only() {
        let commit = source_commit();
        let value = session(
            ProviderMode::Native,
            true,
            EvidenceProvenance::NativeProvider,
            ResultStatus::Completed,
            AdoptionDecision::Adopt,
        );
        let report = validate_session(&value, &commit).expect("native acceptance");
        assert_eq!(report.validator_status, ValidatorStatus::NativePass);
        assert!(report.native_pass);
        assert_eq!(report.release_decision, RELEASE_DECISION);
    }

    #[test]
    fn missing_real_provider_output_is_typed_not_evaluated() {
        let commit = source_commit();
        let value = session(
            ProviderMode::Missing,
            false,
            EvidenceProvenance::Missing,
            ResultStatus::NotEvaluated,
            AdoptionDecision::NotEvaluated,
        );
        let report = validate_session(&value, &commit).expect("typed missing output");
        assert_eq!(report.validator_status, ValidatorStatus::NotEvaluated);
        assert!(!report.native_pass);
        assert!(
            report
                .missing_reasons
                .contains(&"real_provider_output_missing".into())
        );
    }

    #[test]
    fn fixture_simulator_ignored_and_blocked_env_cannot_pass_native() {
        for (mode, provenance) in [
            (ProviderMode::Simulator, EvidenceProvenance::Simulator),
            (ProviderMode::Fixture, EvidenceProvenance::Fixture),
            (ProviderMode::Ignored, EvidenceProvenance::Ignored),
            (ProviderMode::BlockedEnv, EvidenceProvenance::BlockedEnv),
        ] {
            let commit = source_commit();
            let value = session(
                mode,
                false,
                provenance,
                ResultStatus::NotEvaluated,
                AdoptionDecision::NotEvaluated,
            );
            let report = validate_session(&value, &commit).expect("non-native evidence");
            assert_eq!(report.validator_status, ValidatorStatus::NotEvaluated);
            assert!(!report.native_pass);
        }
    }

    #[test]
    fn service_provider_consumer_missing_fails_closed() {
        let mut value = serde_json::to_value(session(
            ProviderMode::Native,
            true,
            EvidenceProvenance::NativeProvider,
            ResultStatus::Completed,
            AdoptionDecision::Adopt,
        ))
        .unwrap();
        value.as_object_mut().unwrap().remove("provider");
        assert!(
            crate::model::parse_strict_json::<PluginSessionAcceptance>(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn stale_commit_and_recovery_reuse_are_rejected() {
        let commit = source_commit();
        let mut value = session(
            ProviderMode::Native,
            true,
            EvidenceProvenance::NativeProvider,
            ResultStatus::Completed,
            AdoptionDecision::Adopt,
        );
        value.result.source_commit = "0".repeat(40);
        assert!(validate_session(&value, &commit).is_err());

        let mut value = session(
            ProviderMode::Native,
            true,
            EvidenceProvenance::NativeProvider,
            ResultStatus::Completed,
            AdoptionDecision::Adopt,
        );
        value.recovery_hooks[0].old_evaluator_accepted = true;
        assert!(validate_session(&value, &commit).is_err());
    }

    #[test]
    fn result_and_adoption_digest_tampering_is_rejected() {
        let commit = source_commit();
        let mut value = session(
            ProviderMode::Native,
            true,
            EvidenceProvenance::NativeProvider,
            ResultStatus::Completed,
            AdoptionDecision::Adopt,
        );
        value.result.result_digest.replace_range(..1, "0");
        assert!(validate_session(&value, &commit).is_err());

        let mut value = session(
            ProviderMode::Native,
            true,
            EvidenceProvenance::NativeProvider,
            ResultStatus::Completed,
            AdoptionDecision::Adopt,
        );
        value.adoption.decision_digest.replace_range(..1, "0");
        assert!(validate_session(&value, &commit).is_err());
    }
}
