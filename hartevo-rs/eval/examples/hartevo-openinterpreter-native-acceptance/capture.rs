use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::{digest_json, is_lower_hex, sha256_hex};
use crate::model::{OpenInterpreterAcceptance, SessionScope, ValidatorStatus};
use crate::verifier;

pub const CONTRACT_PATH: &str =
    "contracts/openinterpreter/native-capture-replay-acceptance.v1.json";
pub const CONTRACT_SCHEMA_VERSION: &str =
    "hartevo.openinterpreter-native-capture-replay-acceptance/v1";
pub const DOCUMENT_TYPE: &str = "openinterpreter_native_capture_replay";
pub const AUTHORITY: &str = "openinterpreter_native_capture_replay_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-openinterpreter-native-capture-replay-report/v1";

const CONTRACT_BYTES: &[u8] = include_bytes!(
    "../../../../contracts/openinterpreter/native-capture-replay-acceptance.v1.json"
);
const REQUIRED_RECEIPTS: [CaptureReceiptKind; 10] = [
    CaptureReceiptKind::Stream,
    CaptureReceiptKind::ToolCall,
    CaptureReceiptKind::Effect,
    CaptureReceiptKind::EffectVerification,
    CaptureReceiptKind::Result,
    CaptureReceiptKind::Adoption,
    CaptureReceiptKind::Stop,
    CaptureReceiptKind::Revoke,
    CaptureReceiptKind::Crash,
    CaptureReceiptKind::Relaunch,
];
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReceiptKind {
    Stream,
    ToolCall,
    Effect,
    EffectVerification,
    Result,
    Adoption,
    Stop,
    Revoke,
    Crash,
    Relaunch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureTerminalKind {
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureValidatorStatus {
    NativePass,
    NotEvaluated,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureReceipt {
    pub kind: CaptureReceiptKind,
    pub sequence: u64,
    pub source_commit: String,
    pub scope: SessionScope,
    pub model_digest: String,
    pub provider_digest: String,
    pub occurred_at: DateTime<Utc>,
    pub payload_digest: String,
    pub receipt_digest: String,
    pub exit_code: i32,
    pub old_evaluator_accepted: bool,
    pub old_decision_promotable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureTerminalReceipt {
    pub kind: CaptureTerminalKind,
    pub sequence: u64,
    pub source_commit: String,
    pub scope: SessionScope,
    pub model_digest: String,
    pub provider_digest: String,
    pub occurred_at: DateTime<Utc>,
    pub exit_code: i32,
    pub recovery_closed: bool,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureBundle {
    pub schema_version: String,
    pub document_type: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub capture_id: String,
    pub session: OpenInterpreterAcceptance,
    pub receipts: Vec<CaptureReceipt>,
    pub terminal_receipt: CaptureTerminalReceipt,
    pub bundle_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureValidationReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub release_decision: &'static str,
    pub validator_status: CaptureValidatorStatus,
    pub native_pass: bool,
    pub source_commit: String,
    pub capture_id: String,
    pub bundle_root: String,
    pub replay_digest: String,
    pub session_run_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub receipt_count: usize,
    pub terminal_sequence: u64,
    pub model_digest: String,
    pub provider_digest: String,
    pub missing_reasons: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDigestMaterial<'a> {
    kind: CaptureReceiptKind,
    sequence: u64,
    source_commit: &'a str,
    scope: &'a SessionScope,
    model_digest: &'a str,
    provider_digest: &'a str,
    occurred_at: DateTime<Utc>,
    payload_digest: &'a str,
    exit_code: i32,
    old_evaluator_accepted: bool,
    old_decision_promotable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalDigestMaterial<'a> {
    kind: CaptureTerminalKind,
    sequence: u64,
    source_commit: &'a str,
    scope: &'a SessionScope,
    model_digest: &'a str,
    provider_digest: &'a str,
    occurred_at: DateTime<Utc>,
    exit_code: i32,
    recovery_closed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RootMaterial<'a> {
    schema_version: &'a str,
    document_type: &'a str,
    authority: &'a str,
    release_decision: &'a str,
    source_commit: &'a str,
    capture_id: &'a str,
    session: &'a OpenInterpreterAcceptance,
    receipt_digests: Vec<&'a str>,
    terminal_receipt_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayMaterial<'a> {
    source_commit: &'a str,
    capture_id: &'a str,
    bundle_root: &'a str,
    validator_status: CaptureValidatorStatus,
    native_pass: bool,
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
}

pub fn read_capture(path: impl AsRef<Path>) -> Result<CaptureBundle> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("read capture/replay bundle {}", path.display()))?;
    crate::model::parse_strict_json(&bytes)
        .with_context(|| format!("parse strict capture/replay bundle {}", path.display()))
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES)
        .context("capture/replay contract is not strict JSON")?;
    ensure!(
        contract.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
            && contract.get("$id").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION)
            && contract.get("type").and_then(Value::as_str) == Some("object")
            && contract
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false),
        "capture/replay contract root drifted"
    );
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "captureId",
        "session",
        "receipts",
        "terminalReceipt",
        "bundleRoot",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let required = exact_string_set(contract.get("required").context("capture required")?)?;
    ensure!(required == expected, "capture required set drifted");
    let properties = contract
        .get("properties")
        .and_then(Value::as_object)
        .context("capture properties")?;
    ensure!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "capture property set drifted"
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
            "capture contract constant {name} drifted"
        );
    }
    ensure!(
        properties
            .get("session")
            .and_then(|value| value.get("$ref"))
            .and_then(Value::as_str)
            == Some("native-acceptance.v1.json"),
        "capture contract must reference the native acceptance contract"
    );
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("capture definitions")?;
    let expected_defs = ["captureReceipt", "terminalReceipt"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    ensure!(
        defs.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_defs,
        "capture definition set drifted"
    );
    for definition in defs.values() {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "capture nested definitions must be closed"
        );
        let properties = definition
            .get("properties")
            .and_then(Value::as_object)
            .context("capture definition properties")?;
        let required = exact_string_set(
            definition
                .get("required")
                .context("capture definition required")?,
        )?;
        ensure!(
            required == properties.keys().map(String::as_str).collect(),
            "capture definition required/property set drifted"
        );
    }
    Ok(())
}

pub fn validate_capture(
    bundle: &CaptureBundle,
    expected_source_commit: &str,
) -> Result<CaptureValidationReport> {
    validate_commit(expected_source_commit)?;
    validate_envelope(bundle, expected_source_commit)?;
    let session_report = verifier::validate_bundle(&bundle.session, expected_source_commit)?;
    validate_receipts(bundle, expected_source_commit)?;
    validate_terminal_receipt(bundle, expected_source_commit)?;
    ensure!(
        bundle.bundle_root == expected_bundle_root(bundle)?,
        "capture bundle root is not derived from complete runtime evidence"
    );
    let native_pass = session_report.native_pass;
    let validator_status = if native_pass {
        CaptureValidatorStatus::NativePass
    } else if session_report.validator_status == ValidatorStatus::BlockedEnv {
        CaptureValidatorStatus::BlockedEnv
    } else {
        CaptureValidatorStatus::NotEvaluated
    };
    let replay_digest = digest_json(
        "hartevo-openinterpreter-native-capture-replay/v1",
        &ReplayMaterial {
            source_commit: expected_source_commit,
            capture_id: &bundle.capture_id,
            bundle_root: &bundle.bundle_root,
            validator_status,
            native_pass,
        },
    )?;
    let mut missing_reasons = session_report.missing_reasons;
    if !native_pass {
        missing_reasons.push("capture_replay_native_pass_unavailable".into());
    }
    Ok(CaptureValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status,
        native_pass,
        source_commit: expected_source_commit.into(),
        capture_id: bundle.capture_id.clone(),
        bundle_root: bundle.bundle_root.clone(),
        replay_digest,
        session_run_id: bundle.session.run_id.clone(),
        project_id: bundle.session.project.id.clone(),
        mission_id: bundle.session.mission.id.clone(),
        receipt_count: bundle.receipts.len(),
        terminal_sequence: bundle.terminal_receipt.sequence,
        model_digest: bundle.session.model.identity_digest.clone(),
        provider_digest: bundle.session.provider.identity_digest.clone(),
        missing_reasons,
    })
}

fn validate_envelope(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    ensure!(
        bundle.schema_version == CONTRACT_SCHEMA_VERSION
            && bundle.document_type == DOCUMENT_TYPE
            && bundle.authority == AUTHORITY
            && bundle.release_decision == RELEASE_DECISION
            && bundle.source_commit == expected_source_commit
            && bundle.session.source_commit == expected_source_commit,
        "capture envelope is stale or has invalid constants"
    );
    validate_commit(&bundle.source_commit)?;
    validate_digest(&bundle.capture_id, "capture id")?;
    validate_digest(&bundle.bundle_root, "capture bundle root")?;
    Ok(())
}

fn validate_receipts(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    ensure!(
        bundle.receipts.len() == REQUIRED_RECEIPTS.len(),
        "capture must contain the exact ten runtime receipts"
    );
    let scope = &bundle.session.dispatch.scope;
    let model_digest = &bundle.session.model.identity_digest;
    let provider_digest = &bundle.session.provider.identity_digest;
    let mut prior_time = None;
    for (index, receipt) in bundle.receipts.iter().enumerate() {
        ensure!(
            receipt.kind == REQUIRED_RECEIPTS[index] && receipt.sequence == index as u64 + 1,
            "capture receipt sequence has a gap or unexpected kind"
        );
        ensure!(
            receipt.source_commit == expected_source_commit
                && receipt.scope == *scope
                && receipt.model_digest == *model_digest
                && receipt.provider_digest == *provider_digest
                && receipt.exit_code == 0
                && !receipt.old_evaluator_accepted
                && !receipt.old_decision_promotable,
            "capture receipt identity or recovery flags drifted"
        );
        validate_digest(&receipt.payload_digest, "capture payload digest")?;
        validate_digest(&receipt.receipt_digest, "capture receipt digest")?;
        ensure!(
            receipt.receipt_digest == expected_receipt_digest(receipt)?,
            "capture receipt digest is not derived from typed fields"
        );
        if let Some(previous) = prior_time {
            ensure!(
                receipt.occurred_at > previous,
                "capture receipt timestamps must be strictly increasing"
            );
        }
        prior_time = Some(receipt.occurred_at);
        ensure!(
            receipt.payload_digest == expected_payload_digest(receipt.kind, &bundle.session)?,
            "capture receipt payload does not bind the corresponding runtime evidence"
        );
        ensure!(
            receipt.occurred_at == expected_receipt_time(receipt.kind, &bundle.session)?,
            "capture receipt timestamp does not bind the corresponding runtime evidence"
        );
    }
    Ok(())
}

fn validate_terminal_receipt(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    let terminal = &bundle.terminal_receipt;
    ensure!(
        terminal.kind == CaptureTerminalKind::Terminal
            && terminal.sequence == REQUIRED_RECEIPTS.len() as u64 + 1
            && terminal.source_commit == expected_source_commit
            && terminal.scope == bundle.session.dispatch.scope
            && terminal.model_digest == bundle.session.model.identity_digest
            && terminal.provider_digest == bundle.session.provider.identity_digest
            && terminal.exit_code == 0
            && terminal.recovery_closed
            && terminal.occurred_at
                > bundle
                    .receipts
                    .last()
                    .expect("validated runtime receipts")
                    .occurred_at,
        "capture terminal receipt is missing, stale, or incomplete"
    );
    validate_digest(&terminal.receipt_digest, "capture terminal receipt digest")?;
    ensure!(
        terminal.receipt_digest == expected_terminal_receipt_digest(terminal)?,
        "capture terminal receipt digest is not derived from typed fields"
    );
    Ok(())
}

fn expected_payload_digest(
    kind: CaptureReceiptKind,
    session: &OpenInterpreterAcceptance,
) -> Result<String> {
    match kind {
        CaptureReceiptKind::Stream => Ok(session.durable_log.log_digest.clone()),
        CaptureReceiptKind::ToolCall => digest_json(
            "hartevo-openinterpreter-capture-tool-calls/v1",
            &session.tool_calls,
        )
        .context("derive tool-call capture payload"),
        CaptureReceiptKind::Effect => digest_json(
            "hartevo-openinterpreter-capture-effects/v1",
            &session.effects,
        )
        .context("derive effect capture payload"),
        CaptureReceiptKind::EffectVerification => {
            let verification = session
                .effects
                .iter()
                .map(|effect| &effect.verification)
                .collect::<Vec<_>>();
            digest_json(
                "hartevo-openinterpreter-capture-effect-verifications/v1",
                &verification,
            )
            .context("derive effect-verification capture payload")
        }
        CaptureReceiptKind::Result => Ok(session.terminal_result.result_digest.clone()),
        CaptureReceiptKind::Adoption => Ok(session.adoption.decision_digest.clone()),
        CaptureReceiptKind::Stop => Ok(session.recovery[0].receipt_digest.clone()),
        CaptureReceiptKind::Revoke => Ok(session.recovery[1].receipt_digest.clone()),
        CaptureReceiptKind::Crash => Ok(session.recovery[2].receipt_digest.clone()),
        CaptureReceiptKind::Relaunch => Ok(session.recovery[3].receipt_digest.clone()),
    }
}

fn expected_receipt_time(
    kind: CaptureReceiptKind,
    session: &OpenInterpreterAcceptance,
) -> Result<DateTime<Utc>> {
    match kind {
        CaptureReceiptKind::Stream => Ok(session
            .durable_log
            .entries
            .last()
            .context("runtime stream entries")?
            .occurred_at),
        CaptureReceiptKind::ToolCall => Ok(session
            .tool_calls
            .last()
            .context("runtime tool calls")?
            .completed_at),
        CaptureReceiptKind::Effect => Ok(session
            .effects
            .last()
            .context("runtime effects")?
            .receipt_at),
        CaptureReceiptKind::EffectVerification => Ok(session
            .effects
            .last()
            .context("runtime effect verification")?
            .verification
            .verified_at),
        CaptureReceiptKind::Result => Ok(session.terminal_result.completed_at),
        CaptureReceiptKind::Adoption => Ok(session.adoption.decided_at),
        CaptureReceiptKind::Stop => Ok(session.recovery[0].occurred_at),
        CaptureReceiptKind::Revoke => Ok(session.recovery[1].occurred_at),
        CaptureReceiptKind::Crash => Ok(session.recovery[2].occurred_at),
        CaptureReceiptKind::Relaunch => Ok(session.recovery[3].occurred_at),
    }
}

fn expected_receipt_digest(receipt: &CaptureReceipt) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-capture-receipt/v1",
        &ReceiptDigestMaterial {
            kind: receipt.kind,
            sequence: receipt.sequence,
            source_commit: &receipt.source_commit,
            scope: &receipt.scope,
            model_digest: &receipt.model_digest,
            provider_digest: &receipt.provider_digest,
            occurred_at: receipt.occurred_at,
            payload_digest: &receipt.payload_digest,
            exit_code: receipt.exit_code,
            old_evaluator_accepted: receipt.old_evaluator_accepted,
            old_decision_promotable: receipt.old_decision_promotable,
        },
    )
    .context("derive capture receipt digest")
}

fn expected_terminal_receipt_digest(terminal: &CaptureTerminalReceipt) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-capture-terminal/v1",
        &TerminalDigestMaterial {
            kind: terminal.kind,
            sequence: terminal.sequence,
            source_commit: &terminal.source_commit,
            scope: &terminal.scope,
            model_digest: &terminal.model_digest,
            provider_digest: &terminal.provider_digest,
            occurred_at: terminal.occurred_at,
            exit_code: terminal.exit_code,
            recovery_closed: terminal.recovery_closed,
        },
    )
    .context("derive capture terminal receipt digest")
}

fn expected_bundle_root(bundle: &CaptureBundle) -> Result<String> {
    digest_json(
        "hartevo-openinterpreter-native-capture-bundle/v1",
        &RootMaterial {
            schema_version: &bundle.schema_version,
            document_type: &bundle.document_type,
            authority: &bundle.authority,
            release_decision: &bundle.release_decision,
            source_commit: &bundle.source_commit,
            capture_id: &bundle.capture_id,
            session: &bundle.session,
            receipt_digests: bundle
                .receipts
                .iter()
                .map(|receipt| receipt.receipt_digest.as_str())
                .collect(),
            terminal_receipt_digest: &bundle.terminal_receipt.receipt_digest,
        },
    )
    .context("derive capture bundle root")
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
    use crate::model::ProviderMode;
    use crate::verifier::current_source_commit;
    use chrono::Duration;
    use serde_json::json;

    fn source_commit() -> String {
        current_source_commit().expect("current Git commit")
    }

    fn capture() -> CaptureBundle {
        let session = crate::verifier::test_native_acceptance();
        let source_commit = session.source_commit.clone();
        let scope = session.dispatch.scope.clone();
        let model_digest = session.model.identity_digest.clone();
        let provider_digest = session.provider.identity_digest.clone();
        let mut receipts = Vec::new();
        for (index, kind) in REQUIRED_RECEIPTS.into_iter().enumerate() {
            let mut receipt = CaptureReceipt {
                kind,
                sequence: index as u64 + 1,
                source_commit: source_commit.clone(),
                scope: scope.clone(),
                model_digest: model_digest.clone(),
                provider_digest: provider_digest.clone(),
                occurred_at: expected_receipt_time(kind, &session).unwrap(),
                payload_digest: expected_payload_digest(kind, &session).unwrap(),
                receipt_digest: String::new(),
                exit_code: 0,
                old_evaluator_accepted: false,
                old_decision_promotable: false,
            };
            receipt.receipt_digest = expected_receipt_digest(&receipt).unwrap();
            receipts.push(receipt);
        }
        let mut terminal_receipt = CaptureTerminalReceipt {
            kind: CaptureTerminalKind::Terminal,
            sequence: 11,
            source_commit: source_commit.clone(),
            scope,
            model_digest,
            provider_digest,
            occurred_at: receipts.last().unwrap().occurred_at + Duration::seconds(1),
            exit_code: 0,
            recovery_closed: true,
            receipt_digest: String::new(),
        };
        terminal_receipt.receipt_digest =
            expected_terminal_receipt_digest(&terminal_receipt).unwrap();
        let mut bundle = CaptureBundle {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            document_type: DOCUMENT_TYPE.into(),
            authority: AUTHORITY.into(),
            release_decision: RELEASE_DECISION.into(),
            source_commit,
            capture_id: digest('9'),
            session,
            receipts,
            terminal_receipt,
            bundle_root: String::new(),
        };
        bundle.bundle_root = expected_bundle_root(&bundle).unwrap();
        bundle
    }

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    #[test]
    fn checked_in_capture_contract_is_closed() {
        validate_contract().expect("capture contract");
        assert!(is_lower_hex(&contract_digest(), 32));
    }

    #[test]
    fn capture_replay_is_deterministic_for_current_commit() {
        let bundle = capture();
        let commit = source_commit();
        let first = validate_capture(&bundle, &commit).expect("capture validation");
        let replay = validate_capture(&bundle, &commit).expect("offline replay");
        assert_eq!(first, replay);
        assert_eq!(first.validator_status, CaptureValidatorStatus::NativePass);
        assert!(first.native_pass);
    }

    #[test]
    fn sequence_gap_and_missing_terminal_receipt_are_rejected() {
        let commit = source_commit();
        let mut gap = capture();
        gap.receipts[3].sequence = 7;
        assert!(validate_capture(&gap, &commit).is_err());

        let mut value = serde_json::to_value(capture()).unwrap();
        value.as_object_mut().unwrap().remove("terminalReceipt");
        assert!(
            crate::model::parse_strict_json::<CaptureBundle>(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }

    #[test]
    fn cross_mission_and_model_provider_drift_are_rejected() {
        let commit = source_commit();
        let mut cross_mission = capture();
        cross_mission.receipts[0].scope.mission_id = "other-mission".into();
        assert!(validate_capture(&cross_mission, &commit).is_err());

        let mut model_drift = capture();
        model_drift.receipts[1].model_digest = digest('a');
        assert!(validate_capture(&model_drift, &commit).is_err());

        let mut provider_drift = capture();
        provider_drift.terminal_receipt.provider_digest = digest('b');
        assert!(validate_capture(&provider_drift, &commit).is_err());
    }

    #[test]
    fn secret_leakage_and_repeated_recovery_are_rejected() {
        let commit = source_commit();
        let mut secret = capture();
        secret.session.durable_log.secret_scan.status = crate::model::SecretScanStatus::Findings;
        assert!(validate_capture(&secret, &commit).is_err());

        let mut repeated = capture();
        repeated.receipts[8].kind = CaptureReceiptKind::Revoke;
        assert!(validate_capture(&repeated, &commit).is_err());
    }

    #[test]
    fn strict_capture_json_rejects_unknown_and_duplicate_fields() {
        let value = serde_json::to_value(capture()).unwrap();
        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("forgedPass".into(), json!(true));
        assert!(
            crate::model::parse_strict_json::<CaptureBundle>(
                &serde_json::to_vec(&unknown).unwrap()
            )
            .is_err()
        );
        assert!(
            crate::model::parse_strict_json::<CaptureBundle>(
                br#"{"schemaVersion":"x","schemaVersion":"y"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn simulator_or_blocked_capture_is_not_native_pass() {
        let mut bundle = capture();
        bundle.session.provider.mode = ProviderMode::BlockedEnv;
        bundle.session.provider.credentials = crate::model::CredentialStatus::BlockedEnv;
        bundle.session.provider.output_present = false;
        bundle.session.provider.output_digest.clear();
        bundle.session.provider.identity_digest =
            crate::verifier::test_provider_identity_digest(&bundle.session.provider);
        assert!(validate_capture(&bundle, &source_commit()).is_err());
    }
}
