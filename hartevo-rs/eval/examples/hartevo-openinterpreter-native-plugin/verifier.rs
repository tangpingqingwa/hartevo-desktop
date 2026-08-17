use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use hartevo_runtime_adapter::{
    APP_SERVER_SCHEMA_SHA256, CONTROL_PLANE_CONTRACT_SHA256, OPENINTERPRETER_COMMIT,
    OPENINTERPRETER_RELEASE, RuntimePluginScope,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::digest::{domain_digest, is_lower_sha256, sha256_json};
use crate::model::{
    AUTHORITY, DOCUMENT_TYPE, DurableEventKind, EvidenceStatus, NativePluginReceipt, OracleInput,
    Provenance, RELEASE_DECISION, SCHEMA_VERSION, StageName, VerificationReport,
};

pub const CONTRACT_RELATIVE_PATH: &str =
    "contracts/openinterpreter/openinterpreter-native-plugin-receipt.v1.json";
pub const VALIDATION_SCHEMA: &str = "hartevo.openinterpreter-native-plugin-validation/v1";
const MODEL_VISIBLE_EVENT_SCHEMA: &str = "hartevo.runtime-model-visible-event/v1";
const EXPECTED_STAGE_COUNT: usize = 11;
const EXPECTED_ORACLE_CONSUMER: &str = "hartevo-plugin-native-journey-oracle";
const MAX_PROVIDER_ID_BYTES: usize = 1_024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventDigestMaterial<'a> {
    schema: &'static str,
    sequence: u64,
    scope_digest: &'a str,
    provider_manifest_digest: &'a str,
    runtime_config_digest: &'a str,
    catalog_digest: &'a str,
    policy_digest: &'a str,
    kind: DurableEventKind,
    source_item_id_digest: &'a str,
    source_event_digest: &'a str,
    content_digest: &'a str,
    content_byte_count: u64,
}

fn result_digest(receipt: &crate::model::ResultEvidence) -> Result<String> {
    let mut value = receipt.clone();
    value.result_digest.clear();
    sha256_json(&value).context("hash result evidence")
}

pub fn result_digest_for_receipt(receipt: &crate::model::ResultEvidence) -> Result<String> {
    result_digest(receipt)
}

fn cleanup_digest(receipt: &crate::model::CleanupEvidence) -> Result<String> {
    let mut value = receipt.clone();
    value.cleanup_digest.clear();
    sha256_json(&value).context("hash cleanup evidence")
}

pub fn cleanup_digest_for_receipt(receipt: &crate::model::CleanupEvidence) -> Result<String> {
    cleanup_digest(receipt)
}

fn durable_log_digest(receipt: &NativePluginReceipt) -> Result<String> {
    sha256_json(&receipt.durable_log).context("hash durable log")
}

fn evidence_root(receipt: &NativePluginReceipt) -> Result<String> {
    Ok(domain_digest(
        "hartevo.openinterpreter-native-plugin-evidence-root/v1",
        &[
            &receipt.source_commit,
            &receipt.scope.scope_digest,
            &sha256_json(&receipt.selection)?,
            &sha256_json(&receipt.process)?,
            &durable_log_digest(receipt)?,
            &receipt.result.result_digest,
            &receipt.cleanup.cleanup_digest,
        ],
    ))
}

pub fn receipt_digest(receipt: &NativePluginReceipt) -> Result<String> {
    let mut value = receipt.clone();
    value.receipt_digest.clear();
    sha256_json(&value).context("hash native receipt")
}

pub fn stage_digest(
    sequence: u64,
    stage: StageName,
    scope_digest: &str,
    source_commit: &str,
) -> String {
    domain_digest(
        "hartevo.openinterpreter-native-plugin-stage/v1",
        &[
            &sequence.to_string(),
            &serde_json::to_string(&stage).unwrap_or_default(),
            scope_digest,
            source_commit,
        ],
    )
}

pub fn validate_contract_bytes(bytes: &[u8]) -> Result<Value> {
    let value = crate::model::parse_strict_json::<Value>(bytes).context("strict contract JSON")?;
    let object = value
        .as_object()
        .context("receipt schema must be an object")?;
    ensure!(
        object.get("$schema").and_then(Value::as_str).is_some(),
        "receipt schema must declare $schema"
    );
    ensure!(object.get("type").and_then(Value::as_str) == Some("object"));
    ensure!(
        object.get("additionalProperties") == Some(&Value::Bool(false)),
        "root schema must close additional properties"
    );
    let required = exact_object_keys(&value, "required")?;
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .context("receipt schema properties missing")?;
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "scope",
        "source",
        "selection",
        "process",
        "stages",
        "durableLog",
        "turn",
        "result",
        "interrupt",
        "cleanup",
        "oracleInput",
        "provenance",
        "evidenceRoot",
        "receiptDigest",
    ];
    let expected_keys = expected
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    ensure!(required == expected_keys, "root required key drift");
    ensure!(
        properties.keys().cloned().collect::<BTreeSet<_>>()
            == expected.iter().map(|key| (*key).to_owned()).collect(),
        "root property key drift"
    );
    Ok(value)
}

fn exact_object_keys(value: &Value, field: &str) -> Result<BTreeSet<String>> {
    let array = value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("schema {field} must be an array"))?;
    array
        .iter()
        .map(|entry| {
            Ok(entry
                .as_str()
                .context("schema key must be a string")?
                .to_owned())
        })
        .collect()
}

pub fn current_source_commit(repository_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-C",
            repository_root.to_string_lossy().as_ref(),
            "rev-parse",
            "HEAD",
        ])
        .output()
        .context("read current source commit")?;
    ensure!(output.status.success(), "git rev-parse failed");
    let commit = String::from_utf8(output.stdout)
        .context("git commit output is not UTF-8")?
        .trim()
        .to_owned();
    ensure!(commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
    Ok(commit)
}

pub fn validate_receipt_bytes(bytes: &[u8], expected_commit: &str) -> Result<VerificationReport> {
    let raw = crate::model::parse_strict_json::<Value>(bytes).context("strict receipt JSON")?;
    reject_content_fields(&raw)?;
    let receipt = crate::model::parse_strict_json::<NativePluginReceipt>(bytes)
        .context("typed native receipt")?;
    validate_receipt(&receipt, expected_commit)
}

fn reject_content_fields(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                ensure!(
                    !matches!(key.as_str(), "content" | "prompt" | "secret" | "text"),
                    "content or secret material is forbidden in native evidence"
                );
                reject_content_fields(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_content_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_receipt(
    receipt: &NativePluginReceipt,
    expected_commit: &str,
) -> Result<VerificationReport> {
    ensure!(
        receipt.schema_version == SCHEMA_VERSION,
        "receipt schema drift"
    );
    ensure!(
        receipt.document_type == DOCUMENT_TYPE,
        "receipt document type drift"
    );
    ensure!(receipt.authority == AUTHORITY, "receipt authority drift");
    ensure!(
        receipt.release_decision == RELEASE_DECISION,
        "release decision must remain false"
    );
    ensure!(
        receipt.source_commit == expected_commit,
        "stale or cross-commit receipt"
    );
    ensure!(receipt.source.source_commit == receipt.source_commit);
    ensure!(receipt.source.runtime_commit == OPENINTERPRETER_COMMIT);
    ensure!(receipt.source.runtime_release == OPENINTERPRETER_RELEASE);
    ensure!(
        receipt.source.app_server_schema_digest == format!("sha256:{APP_SERVER_SCHEMA_SHA256}")
    );
    ensure!(receipt.source.control_plane_contract_digest == CONTROL_PLANE_CONTRACT_SHA256);
    ensure!(
        receipt.source_commit.len() == 40
            && receipt
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "source commit is not lower-case 40-hex"
    );
    for digest in [
        receipt.source.binary_digest.as_str(),
        receipt.source.tool_digest.as_str(),
        receipt.source.command_digest.as_str(),
        receipt
            .source
            .app_server_schema_digest
            .trim_start_matches("sha256:"),
        receipt.source.control_plane_contract_digest.as_str(),
    ] {
        ensure!(
            is_lower_sha256(digest),
            "source digest is not lower-case sha256"
        );
    }
    validate_scope(receipt)?;
    validate_selection(receipt)?;
    validate_process(receipt)?;
    validate_stages(receipt)?;
    validate_log(receipt)?;
    validate_turn(receipt)?;
    validate_result(receipt)?;
    validate_interrupt(receipt)?;
    validate_cleanup(receipt)?;
    validate_oracle_input(receipt)?;
    ensure!(receipt.evidence_root == evidence_root(receipt)?);
    ensure!(receipt.receipt_digest == receipt_digest(receipt)?);

    if receipt.provenance != Provenance::Native {
        let status = match receipt.provenance {
            Provenance::BlockedEnv => EvidenceStatus::BlockedEnv,
            Provenance::Fixture | Provenance::Simulator | Provenance::Ignored => {
                EvidenceStatus::NotEvaluated
            }
            Provenance::Native => unreachable!(),
        };
        return Ok(report(
            receipt,
            status,
            false,
            false,
            "non-native provenance",
        ));
    }
    ensure!(receipt.oracle_input.provenance == Provenance::Native);
    Ok(report(
        receipt,
        EvidenceStatus::NativePass,
        true,
        true,
        "native journey evidence validated; release authority remains NOT_EVALUATED",
    ))
}

fn report(
    receipt: &NativePluginReceipt,
    status: EvidenceStatus,
    native_pass: bool,
    oracle_consumable: bool,
    reason: &str,
) -> VerificationReport {
    VerificationReport {
        status,
        native_pass,
        oracle_consumable,
        release_decision: RELEASE_DECISION.to_owned(),
        source_commit: receipt.source_commit.clone(),
        receipt_digest: receipt.receipt_digest.clone(),
        evidence_root: receipt.evidence_root.clone(),
        reason: reason.to_owned(),
    }
}

fn validate_scope(receipt: &NativePluginReceipt) -> Result<()> {
    let scope = RuntimePluginScope::new(
        receipt.scope.project_id.clone(),
        receipt.scope.mission_id.clone(),
        receipt.scope.session_id.clone(),
    )?;
    ensure!(scope.scope_digest == receipt.scope.scope_digest);
    ensure!(receipt.scope.runtime_generation > 0);
    ensure!(receipt.result.project_id == receipt.scope.project_id);
    ensure!(receipt.result.mission_id == receipt.scope.mission_id);
    ensure!(receipt.result.runtime_generation == receipt.scope.runtime_generation);
    Ok(())
}

fn validate_selection(receipt: &NativePluginReceipt) -> Result<()> {
    for digest in [
        receipt.selection.provider_revision.as_str(),
        receipt.selection.model_revision.as_str(),
        receipt.selection.harness_revision.as_str(),
        receipt.selection.manifest_digest.as_str(),
        receipt.selection.service_definition_digest.as_str(),
        receipt.selection.catalog_digest.as_str(),
        receipt.selection.config_digest.as_str(),
        receipt.selection.policy_digest.as_str(),
    ] {
        ensure!(
            is_lower_sha256(digest),
            "selection digest or revision invalid"
        );
    }
    ensure!(receipt.selection.service_id == "runtime.execution");
    ensure!(receipt.selection.service_revision == "v1");
    ensure!(valid_provider_id(&receipt.selection.provider_id));
    ensure!(receipt.result.runtime_config_digest == receipt.selection.config_digest);
    ensure!(receipt.result.catalog_digest == receipt.selection.catalog_digest);
    Ok(())
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn validate_process(receipt: &NativePluginReceipt) -> Result<()> {
    ensure!(receipt.process.runtime_generation == receipt.scope.runtime_generation);
    ensure!(receipt.process.process_id_digest == receipt.process.runtime_instance_digest);
    ensure!(receipt.process.observed_at_epoch_seconds > 0);
    for digest in [
        receipt.process.process_id_digest.as_str(),
        receipt.process.executable_path_digest.as_str(),
        receipt.process.runtime_instance_digest.as_str(),
        receipt.process.process_binding_digest.as_str(),
        receipt.process.binary_digest.as_str(),
    ] {
        ensure!(is_lower_sha256(digest), "process identity digest invalid");
    }
    ensure!(receipt.process.binary_digest == receipt.source.binary_digest);
    ensure!(
        receipt.process.process_binding_digest
            == domain_digest(
                "hartevo.openinterpreter-native-plugin-process/v1",
                &[
                    &receipt.process.runtime_instance_digest,
                    &receipt.source.command_digest,
                    &receipt.source.binary_digest,
                ],
            )
    );
    ensure!(receipt.process.runtime_instance_digest == receipt.result.runtime_instance_digest);
    Ok(())
}

fn validate_stages(receipt: &NativePluginReceipt) -> Result<()> {
    ensure!(receipt.stages.len() == EXPECTED_STAGE_COUNT);
    for (index, stage) in receipt.stages.iter().enumerate() {
        ensure!(stage.sequence == (index + 1) as u64);
        ensure!(stage.name == StageName::ALL[index]);
        ensure!(
            stage.evidence_digest
                == stage_digest(
                    stage.sequence,
                    stage.name,
                    &receipt.scope.scope_digest,
                    &receipt.source_commit,
                )
        );
    }
    Ok(())
}

fn validate_log(receipt: &NativePluginReceipt) -> Result<()> {
    ensure!(
        receipt.durable_log.len() >= 3,
        "input, delta, and result are required"
    );
    let mut sequences = BTreeSet::new();
    let mut saw_delta = false;
    let mut saw_result = false;
    for (index, event) in receipt.durable_log.iter().enumerate() {
        ensure!(event.sequence == (index + 1) as u64);
        ensure!(
            sequences.insert(event.sequence),
            "duplicate durable sequence"
        );
        ensure!(event.scope_digest == receipt.scope.scope_digest);
        ensure!(event.provider_manifest_digest == receipt.selection.manifest_digest);
        ensure!(event.config_digest == receipt.selection.config_digest);
        ensure!(event.catalog_digest == receipt.selection.catalog_digest);
        ensure!(event.policy_digest == receipt.selection.policy_digest);
        for digest in [
            event.source_item_id_digest.as_str(),
            event.source_event_digest.as_str(),
            event.content_digest.as_str(),
            event.event_digest.as_str(),
        ] {
            ensure!(is_lower_sha256(digest), "durable event digest invalid");
        }
        let expected = sha256_json(&EventDigestMaterial {
            schema: MODEL_VISIBLE_EVENT_SCHEMA,
            sequence: event.sequence,
            scope_digest: &event.scope_digest,
            provider_manifest_digest: &event.provider_manifest_digest,
            runtime_config_digest: &event.config_digest,
            catalog_digest: &event.catalog_digest,
            policy_digest: &event.policy_digest,
            kind: event.kind,
            source_item_id_digest: &event.source_item_id_digest,
            source_event_digest: &event.source_event_digest,
            content_digest: &event.content_digest,
            content_byte_count: event.content_byte_count,
        })?;
        ensure!(event.event_digest == expected, "durable event tampered");
        match event.kind {
            DurableEventKind::Input => ensure!(event.sequence == 1),
            DurableEventKind::AssistantDelta => saw_delta = true,
            DurableEventKind::AssistantResult => {
                saw_result = true;
                ensure!(event.source_event_digest == receipt.result.source_event_digest);
                ensure!(event.content_digest == receipt.result.content_digest);
            }
        }
    }
    ensure!(saw_delta, "streamed assistant delta is missing");
    ensure!(saw_result, "typed assistant result is missing");
    ensure!(
        receipt
            .durable_log
            .first()
            .is_some_and(|event| event.kind == DurableEventKind::Input)
    );
    ensure!(
        receipt
            .durable_log
            .last()
            .is_some_and(|event| event.kind == DurableEventKind::AssistantResult)
    );
    Ok(())
}

fn validate_turn(receipt: &NativePluginReceipt) -> Result<()> {
    for digest in [
        receipt.turn.client_message_id_digest.as_str(),
        receipt.turn.request_digest.as_str(),
        receipt.turn.response_digest.as_str(),
        receipt.turn.thread_id_digest.as_str(),
        receipt.turn.turn_id_digest.as_str(),
        receipt.turn.turn_digest.as_str(),
    ] {
        ensure!(is_lower_sha256(digest), "turn digest invalid");
    }
    ensure!(matches!(
        receipt.turn.completion_status.as_str(),
        "completed" | "interrupted"
    ));
    ensure!(receipt.turn.turn_id_digest == receipt.result.runtime_turn_id_digest);
    Ok(())
}

fn validate_result(receipt: &NativePluginReceipt) -> Result<()> {
    ensure!(receipt.result.schema == "hartevo.runtime-result-packet/v1");
    ensure!(receipt.result.authority == "local_execution_evidence");
    ensure!(receipt.result.result_kind == "agent_message");
    ensure!(receipt.result.runtime_commit == OPENINTERPRETER_COMMIT);
    ensure!(receipt.result.runtime_release == OPENINTERPRETER_RELEASE);
    ensure!(
        receipt.result.app_server_schema_digest == format!("sha256:{APP_SERVER_SCHEMA_SHA256}")
    );
    ensure!(receipt.result.content_byte_count > 0);
    ensure!(receipt.result.result_digest == result_digest(&receipt.result)?);
    for digest in [
        receipt.result.runtime_instance_digest.as_str(),
        receipt.result.mapping_digest.as_str(),
        receipt.result.runtime_thread_id_digest.as_str(),
        receipt.result.runtime_turn_id_digest.as_str(),
        receipt
            .result
            .app_server_schema_digest
            .trim_start_matches("sha256:"),
        receipt.result.runtime_config_digest.as_str(),
        receipt.result.catalog_digest.as_str(),
        receipt.result.source_item_id_digest.as_str(),
        receipt.result.source_event_digest.as_str(),
        receipt.result.content_digest.as_str(),
        receipt.result.result_digest.as_str(),
    ] {
        ensure!(is_lower_sha256(digest), "result digest invalid");
    }
    Ok(())
}

fn validate_interrupt(receipt: &NativePluginReceipt) -> Result<()> {
    ensure!(receipt.interrupt.acknowledged);
    ensure!(receipt.interrupt.turn_id_digest == receipt.turn.turn_id_digest);
    ensure!(
        receipt.interrupt.interrupt_digest
            == domain_digest(
                "hartevo.openinterpreter-native-plugin-interrupt/v1",
                &[
                    receipt.interrupt.request_digest.as_str(),
                    receipt.interrupt.response_digest.as_str(),
                    receipt.interrupt.turn_id_digest.as_str(),
                ],
            )
    );
    for digest in [
        receipt.interrupt.request_digest.as_str(),
        receipt.interrupt.response_digest.as_str(),
        receipt.interrupt.turn_id_digest.as_str(),
        receipt.interrupt.interrupt_digest.as_str(),
    ] {
        ensure!(is_lower_sha256(digest), "interrupt digest invalid");
    }
    Ok(())
}

fn validate_cleanup(receipt: &NativePluginReceipt) -> Result<()> {
    ensure!(matches!(
        receipt.cleanup.plugin_state,
        crate::model::CleanupState::Revoked | crate::model::CleanupState::Unmounted
    ));
    ensure!(receipt.cleanup.shutdown_success);
    ensure!(!receipt.cleanup.shutdown_forced);
    ensure!(receipt.cleanup.residual_registration_count == 0);
    ensure!(receipt.cleanup.exit_code == 0);
    ensure!(is_lower_sha256(&receipt.cleanup.mount_digest));
    ensure!(receipt.cleanup.cleanup_digest == cleanup_digest(&receipt.cleanup)?);
    Ok(())
}

fn validate_oracle_input(receipt: &NativePluginReceipt) -> Result<()> {
    let oracle: &OracleInput = &receipt.oracle_input;
    ensure!(oracle.journey_schema == crate::model::ORACLE_JOURNEY_SCHEMA);
    ensure!(oracle.source_commit == receipt.source_commit);
    ensure!(oracle.project_id == receipt.scope.project_id);
    ensure!(oracle.mission_id == receipt.scope.mission_id);
    ensure!(oracle.session_id == receipt.scope.session_id);
    ensure!(oracle.consumer_id == EXPECTED_ORACLE_CONSUMER);
    ensure!(oracle.provenance == Provenance::Native);
    ensure!(oracle.result_digest == receipt.result.result_digest);
    ensure!(oracle.durable_log_digest == durable_log_digest(receipt)?);
    ensure!(oracle.consumer_result_digest == receipt.result.result_digest);
    ensure!(
        oracle.runtime_plugin_digest == receipt.selection.manifest_digest
            && oracle.service_digest == receipt.selection.service_definition_digest
            && oracle.provider_digest
                == crate::digest::sha256_text(&format!(
                    "{}@{}",
                    receipt.selection.provider_id, receipt.selection.provider_revision
                ))
            && oracle.model_digest
                == crate::digest::sha256_text(&format!(
                    "{}@{}",
                    receipt.selection.model_id, receipt.selection.model_revision
                ))
    );
    for digest in [
        oracle.journey_id.as_str(),
        oracle.runtime_plugin_digest.as_str(),
        oracle.provider_digest.as_str(),
        oracle.model_digest.as_str(),
        oracle.service_digest.as_str(),
        oracle.consumer_result_digest.as_str(),
        oracle.durable_log_digest.as_str(),
        oracle.result_digest.as_str(),
        oracle.evidence_root.as_str(),
    ] {
        ensure!(is_lower_sha256(digest), "oracle digest invalid");
    }
    ensure!(oracle.evidence_root == receipt.evidence_root);
    Ok(())
}

pub fn blocked_env_report(missing: &[String]) -> Value {
    json!({
        "validationSchema": VALIDATION_SCHEMA,
        "status": EvidenceStatus::BlockedEnv,
        "nativePass": false,
        "oracleConsumable": false,
        "releaseDecision": RELEASE_DECISION,
        "missing": missing,
        "reason": "credentialed native OpenInterpreter environment is unavailable",
    })
}

pub fn not_evaluated_report(reason: &str) -> Value {
    json!({
        "validationSchema": VALIDATION_SCHEMA,
        "status": EvidenceStatus::NotEvaluated,
        "nativePass": false,
        "oracleConsumable": false,
        "releaseDecision": RELEASE_DECISION,
        "reason": reason,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_env_report, not_evaluated_report, stage_digest, valid_provider_id,
        validate_contract_bytes, validate_receipt_bytes,
    };
    use crate::model::StageName;

    #[test]
    fn contract_rejects_unknown_root_key_and_receipts_never_accept_content() {
        let root = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["schemaVersion"],
            "properties": {"schemaVersion": {"const": "x"}},
            "unexpected": true
        });
        assert!(validate_contract_bytes(&serde_json::to_vec(&root).expect("json")).is_err());
        let content = serde_json::json!({"content": "secret"});
        assert!(
            validate_receipt_bytes(
                &serde_json::to_vec(&content).expect("json"),
                "a".repeat(40).as_str()
            )
            .is_err()
        );
    }

    #[test]
    fn blocked_and_non_native_reports_are_never_native_pass() {
        let blocked = blocked_env_report(&["HARTEVO_OPENINTERPRETER_BIN".to_owned()]);
        assert_eq!(blocked["status"], "BLOCKED_ENV");
        assert_eq!(blocked["nativePass"], false);
        let missing = not_evaluated_report("fixture evidence is not native");
        assert_eq!(missing["status"], "NOT_EVALUATED");
        assert_eq!(missing["nativePass"], false);
    }

    #[test]
    fn stage_binding_is_mutation_sensitive() {
        let scope = "a".repeat(64);
        let commit = "b".repeat(40);
        assert_ne!(
            stage_digest(1, StageName::Initialize, &scope, &commit),
            stage_digest(1, StageName::Stream, &scope, &commit)
        );
        assert_ne!(
            stage_digest(1, StageName::Initialize, &scope, &commit),
            stage_digest(2, StageName::Initialize, &scope, &commit)
        );
    }

    #[test]
    fn provider_identity_accepts_observed_local_ids_without_allowing_spoofed_shapes() {
        assert!(valid_provider_id("ollama"));
        assert!(valid_provider_id("local-compatible.provider_v1"));
        assert!(!valid_provider_id("OpenAI"));
        assert!(!valid_provider_id("openai/provider"));
        assert!(!valid_provider_id(""));
    }
}
