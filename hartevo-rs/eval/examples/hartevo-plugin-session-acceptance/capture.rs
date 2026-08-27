use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::{digest_json, is_lower_hex, sha256_hex};
use crate::model::{
    AdoptionDecision, ConsumerBinding, EvidenceProvenance, MissionScope, ProjectScope,
    ProviderBinding, ProviderMode, RecoveryHook, ResultStatus, ServiceBinding, SessionScope,
    parse_strict_json,
};

pub const CONTRACT_PATH: &str = "contracts/plugins/plugin-session-capture.v1.json";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-plugin-session-capture/v1";
pub const DOCUMENT_TYPE: &str = "plugin_session_capture";
pub const AUTHORITY: &str = "plugin_session_capture_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-plugin-session-capture-report/v1";

const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/plugins/plugin-session-capture.v1.json");
const REQUIRED_RECEIPT_KINDS: [CaptureReceiptKind; 8] = [
    CaptureReceiptKind::Mount,
    CaptureReceiptKind::ModelVisibleDurableLog,
    CaptureReceiptKind::Invoke,
    CaptureReceiptKind::Result,
    CaptureReceiptKind::Adopt,
    CaptureReceiptKind::Unmount,
    CaptureReceiptKind::Revoke,
    CaptureReceiptKind::Crash,
];
const REQUIRED_RECOVERY_HOOKS: [RecoveryHook; 3] = [
    RecoveryHook::Unmount,
    RecoveryHook::Revoke,
    RecoveryHook::Crash,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReceiptKind {
    Mount,
    ModelVisibleDurableLog,
    Invoke,
    Result,
    Adopt,
    Unmount,
    Revoke,
    Crash,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureFinalReceiptKind {
    Final,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureReceipt {
    pub kind: CaptureReceiptKind,
    pub sequence: u64,
    pub source_commit: String,
    pub scope: SessionScope,
    pub revision: u64,
    pub evaluator_id: String,
    pub binary_digest: String,
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
pub struct CaptureFinalReceipt {
    pub kind: CaptureFinalReceiptKind,
    pub sequence: u64,
    pub source_commit: String,
    pub scope: SessionScope,
    pub revision: u64,
    pub evaluator_id: String,
    pub binary_digest: String,
    pub provider_digest: String,
    pub occurred_at: DateTime<Utc>,
    pub exit_code: i32,
    pub recovery_hooks: Vec<RecoveryHook>,
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
    pub bundle_id: String,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub service: ServiceBinding,
    pub provider: ProviderBinding,
    pub consumer: ConsumerBinding,
    pub binary_digest: String,
    pub provider_digest: String,
    pub result_status: ResultStatus,
    pub result_provenance: EvidenceProvenance,
    pub adoption_decision: AdoptionDecision,
    pub result_digest: String,
    pub adoption_digest: String,
    pub receipts: Vec<CaptureReceipt>,
    pub final_receipt: CaptureFinalReceipt,
    pub bundle_root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureValidatorStatus {
    NativePass,
    NotEvaluated,
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
    pub bundle_id: String,
    pub bundle_root: String,
    pub replay_digest: String,
    pub project_id: String,
    pub mission_id: String,
    pub receipt_count: usize,
    pub final_sequence: u64,
    pub binary_digest: String,
    pub provider_digest: String,
    pub missing_reasons: Vec<String>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDigestMaterial<'a> {
    kind: CaptureReceiptKind,
    sequence: u64,
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    evaluator_id: &'a str,
    binary_digest: &'a str,
    provider_digest: &'a str,
    occurred_at: DateTime<Utc>,
    payload_digest: &'a str,
    exit_code: i32,
    old_evaluator_accepted: bool,
    old_decision_promotable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalReceiptDigestMaterial<'a> {
    kind: CaptureFinalReceiptKind,
    sequence: u64,
    source_commit: &'a str,
    scope: &'a SessionScope,
    revision: u64,
    evaluator_id: &'a str,
    binary_digest: &'a str,
    provider_digest: &'a str,
    occurred_at: DateTime<Utc>,
    exit_code: i32,
    recovery_hooks: &'a [RecoveryHook],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleRootMaterial<'a> {
    schema_version: &'static str,
    document_type: &'static str,
    authority: &'static str,
    release_decision: &'static str,
    source_commit: &'a str,
    bundle_id: &'a str,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    service: &'a ServiceBinding,
    provider: &'a ProviderBinding,
    consumer: &'a ConsumerBinding,
    binary_digest: &'a str,
    provider_digest: &'a str,
    result_status: ResultStatus,
    result_provenance: EvidenceProvenance,
    adoption_decision: AdoptionDecision,
    result_digest: &'a str,
    adoption_digest: &'a str,
    receipt_digests: Vec<&'a str>,
    final_receipt_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayMaterial<'a> {
    source_commit: &'a str,
    bundle_id: &'a str,
    bundle_root: &'a str,
    validator_status: CaptureValidatorStatus,
    native_pass: bool,
    receipt_count: usize,
    final_sequence: u64,
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
}

pub fn read_bundle(path: impl AsRef<Path>) -> Result<CaptureBundle> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("read capture bundle {}", path.display()))?;
    parse_strict_json(&bytes)
        .with_context(|| format!("parse strict capture bundle {}", path.display()))
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = parse_strict_json(CONTRACT_BYTES)
        .context("plugin session capture contract is not strict JSON")?;
    ensure!(
        contract.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema"),
        "capture contract must declare JSON Schema 2020-12"
    );
    ensure!(
        contract.get("$id").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION)
            && contract.get("type").and_then(Value::as_str) == Some("object")
            && contract
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false),
        "capture contract root is not the expected closed object"
    );
    let required = contract
        .get("required")
        .and_then(Value::as_array)
        .context("capture contract required fields")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .context("capture required field is not a string")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "bundleId",
        "project",
        "mission",
        "service",
        "provider",
        "consumer",
        "binaryDigest",
        "providerDigest",
        "resultStatus",
        "resultProvenance",
        "adoptionDecision",
        "resultDigest",
        "adoptionDigest",
        "receipts",
        "finalReceipt",
        "bundleRoot",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        required == expected,
        "capture contract root required set drifted"
    );
    let properties = contract
        .get("properties")
        .and_then(Value::as_object)
        .context("capture contract properties")?;
    ensure!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "capture contract root property set drifted"
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
            "capture contract {property} constant drifted"
        );
    }
    validate_contract_definitions(&contract)
}

fn validate_contract_definitions(contract: &Value) -> Result<()> {
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("capture contract definitions")?;
    let expected_defs = ["finalReceipt", "receipt", "scope"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    ensure!(
        defs.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_defs,
        "capture contract definition set drifted"
    );
    for definition in defs.values() {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "capture nested contract definitions must be closed"
        );
    }
    Ok(())
}

pub fn validate_bundle(
    bundle: &CaptureBundle,
    expected_source_commit: &str,
) -> Result<CaptureValidationReport> {
    validate_commit(expected_source_commit)?;
    validate_envelope(bundle, expected_source_commit)?;
    validate_scope_binding(bundle)?;
    validate_roles(bundle, expected_source_commit)?;
    validate_receipts(bundle, expected_source_commit)?;
    validate_final_receipt(bundle, expected_source_commit)?;
    ensure!(
        bundle.bundle_root == expected_bundle_root(bundle)?,
        "capture evidence bundle root is not derived from the exact bundle"
    );
    let native_candidate = native_candidate(bundle);
    let validator_status = if native_candidate {
        CaptureValidatorStatus::NativePass
    } else {
        CaptureValidatorStatus::NotEvaluated
    };
    let missing_reasons = missing_reasons(bundle);
    let replay_digest = digest_json(
        "hartevo-plugin-session-capture-replay/v1",
        &ReplayMaterial {
            source_commit: expected_source_commit,
            bundle_id: &bundle.bundle_id,
            bundle_root: &bundle.bundle_root,
            validator_status,
            native_pass: native_candidate,
            receipt_count: bundle.receipts.len(),
            final_sequence: bundle.final_receipt.sequence,
        },
    )?;
    Ok(CaptureValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status,
        native_pass: native_candidate,
        source_commit: expected_source_commit.into(),
        bundle_id: bundle.bundle_id.clone(),
        bundle_root: bundle.bundle_root.clone(),
        replay_digest,
        project_id: bundle.project.id.clone(),
        mission_id: bundle.mission.id.clone(),
        receipt_count: bundle.receipts.len(),
        final_sequence: bundle.final_receipt.sequence,
        binary_digest: bundle.binary_digest.clone(),
        provider_digest: bundle.provider_digest.clone(),
        missing_reasons,
    })
}

fn validate_envelope(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    ensure!(
        bundle.schema_version == CONTRACT_SCHEMA_VERSION
            && bundle.document_type == DOCUMENT_TYPE
            && bundle.authority == AUTHORITY
            && bundle.release_decision == RELEASE_DECISION,
        "capture envelope constants drifted"
    );
    ensure!(
        bundle.source_commit == expected_source_commit,
        "capture bundle is stale for the current source commit"
    );
    validate_identifier(&bundle.bundle_id, "bundle id")?;
    validate_digest(&bundle.binary_digest, "binary digest")?;
    validate_digest(&bundle.provider_digest, "provider digest")?;
    validate_digest(&bundle.result_digest, "result digest")?;
    validate_digest(&bundle.adoption_digest, "adoption digest")?;
    Ok(())
}

fn validate_scope_binding(bundle: &CaptureBundle) -> Result<()> {
    validate_identifier(&bundle.project.id, "Project id")?;
    validate_identifier(&bundle.mission.id, "Mission id")?;
    ensure!(bundle.project.revision > 0 && bundle.mission.revision > 0);
    validate_digest(&bundle.project.scope_digest, "Project scope digest")?;
    validate_digest(&bundle.mission.scope_digest, "Mission scope digest")?;
    let expected_scope = expected_scope_digest(bundle);
    for scope in all_scopes(bundle) {
        ensure!(
            scope.project_id == bundle.project.id
                && scope.mission_id == bundle.mission.id
                && scope.scope_digest == expected_scope,
            "capture Project/Mission scope binding drifted"
        );
    }
    Ok(())
}

fn validate_roles(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    validate_identifier(&bundle.service.id, "service id")?;
    validate_identifier(&bundle.provider.id, "provider id")?;
    validate_identifier(&bundle.consumer.id, "consumer id")?;
    validate_binding(&bundle.service.source_commit, &bundle.service.scope, bundle)?;
    validate_binding(
        &bundle.provider.source_commit,
        &bundle.provider.scope,
        bundle,
    )?;
    validate_binding(
        &bundle.consumer.source_commit,
        &bundle.consumer.scope,
        bundle,
    )?;
    ensure!(bundle.service.mounted, "captured service was not mounted");
    ensure!(
        bundle.provider.output_digest == bundle.provider_digest,
        "provider binding digest differs from the bundle provider root"
    );
    ensure!(
        bundle.consumer.adopted == (bundle.adoption_decision == AdoptionDecision::Adopt),
        "consumer adoption state is not bound to the captured decision"
    );
    ensure!(
        bundle.provider.source_commit == expected_source_commit
            && bundle.service.source_commit == expected_source_commit
            && bundle.consumer.source_commit == expected_source_commit,
        "capture role source commit differs from the current commit"
    );
    Ok(())
}

fn validate_binding(
    source_commit: &str,
    scope: &SessionScope,
    bundle: &CaptureBundle,
) -> Result<()> {
    validate_commit(source_commit)?;
    ensure!(
        scope.project_id == bundle.project.id && scope.mission_id == bundle.mission.id,
        "capture role scope differs from Project/Mission"
    );
    Ok(())
}

fn validate_receipts(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    ensure!(
        bundle.receipts.len() == REQUIRED_RECEIPT_KINDS.len(),
        "capture must contain the exact eight runtime receipts"
    );
    let mut timestamps = Vec::with_capacity(bundle.receipts.len() + 1);
    for (index, receipt) in bundle.receipts.iter().enumerate() {
        ensure!(
            receipt.kind == REQUIRED_RECEIPT_KINDS[index] && receipt.sequence == index as u64 + 1,
            "capture receipt sequence or kind is not exact"
        );
        ensure!(receipt.source_commit == expected_source_commit);
        ensure!(receipt.revision > 0 && receipt.revision == bundle.receipts[0].revision);
        ensure!(receipt.evaluator_id == bundle.receipts[0].evaluator_id);
        ensure!(receipt.binary_digest == bundle.binary_digest);
        ensure!(receipt.provider_digest == bundle.provider_digest);
        validate_digest(&receipt.payload_digest, "receipt payload digest")?;
        ensure!(
            receipt.receipt_digest == expected_receipt_digest(receipt)?,
            "capture receipt digest is not derived from its typed fields"
        );
        ensure!(receipt.exit_code == 0);
        ensure!(!receipt.old_evaluator_accepted && !receipt.old_decision_promotable);
        ensure_scope(&receipt.scope, bundle)?;
        timestamps.push(receipt.occurred_at);
    }
    ensure!(
        bundle.receipts[3].payload_digest == bundle.result_digest
            && bundle.receipts[4].payload_digest == bundle.adoption_digest,
        "result/adopt receipts do not bind the bundle result roots"
    );
    ensure!(timestamps.windows(2).all(|pair| pair[1] > pair[0]));
    Ok(())
}

fn validate_final_receipt(bundle: &CaptureBundle, expected_source_commit: &str) -> Result<()> {
    let final_receipt = &bundle.final_receipt;
    ensure!(
        final_receipt.kind == CaptureFinalReceiptKind::Final
            && final_receipt.sequence == REQUIRED_RECEIPT_KINDS.len() as u64 + 1
            && final_receipt.source_commit == expected_source_commit
            && final_receipt.revision == bundle.receipts[0].revision
            && final_receipt.evaluator_id == bundle.receipts[0].evaluator_id
            && final_receipt.binary_digest == bundle.binary_digest
            && final_receipt.provider_digest == bundle.provider_digest
            && final_receipt.exit_code == 0,
        "capture final receipt is incomplete or stale"
    );
    ensure_scope(&final_receipt.scope, bundle)?;
    ensure!(
        final_receipt.recovery_hooks == REQUIRED_RECOVERY_HOOKS,
        "capture final receipt does not close unmount/revoke/crash recovery"
    );
    ensure!(
        final_receipt.occurred_at > bundle.receipts.last().expect("eight receipts").occurred_at,
        "capture final receipt timestamp does not follow runtime receipts"
    );
    ensure!(
        final_receipt.receipt_digest == expected_final_receipt_digest(final_receipt)?,
        "capture final receipt digest is not derived from its typed fields"
    );
    Ok(())
}

fn native_candidate(bundle: &CaptureBundle) -> bool {
    bundle.provider.mode == ProviderMode::Native
        && bundle.provider.output_present
        && bundle.provider.output_digest == bundle.provider_digest
        && bundle.result_status == ResultStatus::Completed
        && bundle.result_provenance == EvidenceProvenance::NativeProvider
        && bundle.adoption_decision == AdoptionDecision::Adopt
        && bundle.consumer.adopted
}

fn missing_reasons(bundle: &CaptureBundle) -> Vec<String> {
    let mut reasons = Vec::new();
    if bundle.provider.mode != ProviderMode::Native {
        reasons.push("provider_provenance_is_not_native".into());
    }
    if !bundle.provider.output_present {
        reasons.push("real_provider_output_missing".into());
    }
    if bundle.result_provenance != EvidenceProvenance::NativeProvider {
        reasons.push("result_provenance_is_not_native_provider".into());
    }
    if bundle.result_status != ResultStatus::Completed {
        reasons.push("result_is_not_completed".into());
    }
    if bundle.adoption_decision != AdoptionDecision::Adopt {
        reasons.push("adoption_is_not_adopt".into());
    }
    reasons
}

fn ensure_scope(scope: &SessionScope, bundle: &CaptureBundle) -> Result<()> {
    ensure!(
        scope.project_id == bundle.project.id
            && scope.mission_id == bundle.mission.id
            && scope.scope_digest == expected_scope_digest(bundle),
        "capture receipt scope is not bound to Project/Mission"
    );
    Ok(())
}

fn all_scopes(bundle: &CaptureBundle) -> Vec<&SessionScope> {
    let mut scopes = vec![
        &bundle.service.scope,
        &bundle.provider.scope,
        &bundle.consumer.scope,
    ];
    scopes.extend(bundle.receipts.iter().map(|receipt| &receipt.scope));
    scopes.push(&bundle.final_receipt.scope);
    scopes
}

fn expected_scope_digest(bundle: &CaptureBundle) -> String {
    digest_json(
        "hartevo-plugin-session-capture-scope/v1",
        &ScopeDigestMaterial {
            project_id: &bundle.project.id,
            project_revision: bundle.project.revision,
            project_scope_digest: &bundle.project.scope_digest,
            mission_id: &bundle.mission.id,
            mission_revision: bundle.mission.revision,
            mission_scope_digest: &bundle.mission.scope_digest,
        },
    )
    .expect("capture scope material serializes")
}

fn expected_receipt_digest(receipt: &CaptureReceipt) -> Result<String> {
    digest_json(
        "hartevo-plugin-session-capture-receipt/v1",
        &ReceiptDigestMaterial {
            kind: receipt.kind,
            sequence: receipt.sequence,
            source_commit: &receipt.source_commit,
            scope: &receipt.scope,
            revision: receipt.revision,
            evaluator_id: &receipt.evaluator_id,
            binary_digest: &receipt.binary_digest,
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

fn expected_final_receipt_digest(final_receipt: &CaptureFinalReceipt) -> Result<String> {
    digest_json(
        "hartevo-plugin-session-capture-final-receipt/v1",
        &FinalReceiptDigestMaterial {
            kind: final_receipt.kind,
            sequence: final_receipt.sequence,
            source_commit: &final_receipt.source_commit,
            scope: &final_receipt.scope,
            revision: final_receipt.revision,
            evaluator_id: &final_receipt.evaluator_id,
            binary_digest: &final_receipt.binary_digest,
            provider_digest: &final_receipt.provider_digest,
            occurred_at: final_receipt.occurred_at,
            exit_code: final_receipt.exit_code,
            recovery_hooks: &final_receipt.recovery_hooks,
        },
    )
    .context("derive capture final receipt digest")
}

fn expected_bundle_root(bundle: &CaptureBundle) -> Result<String> {
    digest_json(
        "hartevo-plugin-session-capture-bundle/v1",
        &BundleRootMaterial {
            schema_version: CONTRACT_SCHEMA_VERSION,
            document_type: DOCUMENT_TYPE,
            authority: AUTHORITY,
            release_decision: RELEASE_DECISION,
            source_commit: &bundle.source_commit,
            bundle_id: &bundle.bundle_id,
            project: &bundle.project,
            mission: &bundle.mission,
            service: &bundle.service,
            provider: &bundle.provider,
            consumer: &bundle.consumer,
            binary_digest: &bundle.binary_digest,
            provider_digest: &bundle.provider_digest,
            result_status: bundle.result_status,
            result_provenance: bundle.result_provenance,
            adoption_decision: bundle.adoption_decision,
            result_digest: &bundle.result_digest,
            adoption_digest: &bundle.adoption_digest,
            receipt_digests: bundle
                .receipts
                .iter()
                .map(|receipt| receipt.receipt_digest.as_str())
                .collect(),
            final_receipt_digest: &bundle.final_receipt.receipt_digest,
        },
    )
    .context("derive capture bundle root")
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

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn source_commit() -> String {
        crate::verifier::current_source_commit().expect("current Git commit")
    }

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn bundle(provider_mode: ProviderMode) -> CaptureBundle {
        let source_commit = source_commit();
        let project = ProjectScope {
            id: "project-capture".into(),
            revision: 1,
            scope_digest: digest('1'),
        };
        let mission = MissionScope {
            id: "mission-capture".into(),
            revision: 1,
            scope_digest: digest('2'),
        };
        let project_id = project.id.clone();
        let mission_id = mission.id.clone();
        let scope_digest = digest_json(
            "hartevo-plugin-session-capture-scope/v1",
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
        let provider_digest = digest('a');
        let binary_digest = digest('b');
        let result_provenance = if provider_mode == ProviderMode::Native {
            EvidenceProvenance::NativeProvider
        } else {
            EvidenceProvenance::Simulator
        };
        let result_status = if provider_mode == ProviderMode::Native {
            ResultStatus::Completed
        } else {
            ResultStatus::NotEvaluated
        };
        let adoption_decision = if provider_mode == ProviderMode::Native {
            AdoptionDecision::Adopt
        } else {
            AdoptionDecision::NotEvaluated
        };
        let provider = ProviderBinding {
            id: "provider-capture".into(),
            source_commit: source_commit.clone(),
            scope: scope(),
            mode: provider_mode,
            output_present: provider_mode == ProviderMode::Native,
            output_digest: provider_digest.clone(),
        };
        let mut receipts = Vec::new();
        let start = Utc::now();
        for (index, kind) in REQUIRED_RECEIPT_KINDS.into_iter().enumerate() {
            let payload_digest = match kind {
                CaptureReceiptKind::Result => digest('c'),
                CaptureReceiptKind::Adopt => digest('d'),
                _ => digest(
                    ['e', 'f', '0', '1', '2', '3'][if index < 3 { index } else { index - 2 }],
                ),
            };
            let mut receipt = CaptureReceipt {
                kind,
                sequence: index as u64 + 1,
                source_commit: source_commit.clone(),
                scope: scope(),
                revision: 3,
                evaluator_id: "evaluator-capture".into(),
                binary_digest: binary_digest.clone(),
                provider_digest: provider_digest.clone(),
                occurred_at: start + Duration::seconds(index as i64 + 1),
                payload_digest,
                receipt_digest: String::new(),
                exit_code: 0,
                old_evaluator_accepted: false,
                old_decision_promotable: false,
            };
            receipt.receipt_digest = expected_receipt_digest(&receipt).unwrap();
            receipts.push(receipt);
        }
        let result_digest = receipts[3].payload_digest.clone();
        let adoption_digest = receipts[4].payload_digest.clone();
        let mut final_receipt = CaptureFinalReceipt {
            kind: CaptureFinalReceiptKind::Final,
            sequence: 9,
            source_commit: source_commit.clone(),
            scope: scope(),
            revision: 3,
            evaluator_id: "evaluator-capture".into(),
            binary_digest: binary_digest.clone(),
            provider_digest: provider_digest.clone(),
            occurred_at: start + Duration::seconds(9),
            exit_code: 0,
            recovery_hooks: REQUIRED_RECOVERY_HOOKS.into_iter().collect(),
            receipt_digest: String::new(),
        };
        final_receipt.receipt_digest = expected_final_receipt_digest(&final_receipt).unwrap();
        let mut bundle = CaptureBundle {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            document_type: DOCUMENT_TYPE.into(),
            authority: AUTHORITY.into(),
            release_decision: RELEASE_DECISION.into(),
            source_commit: source_commit.clone(),
            bundle_id: "bundle-capture-01".into(),
            project,
            mission,
            service: ServiceBinding {
                id: "service-capture".into(),
                source_commit: source_commit.clone(),
                scope: scope(),
                mounted: true,
            },
            provider,
            consumer: ConsumerBinding {
                id: "consumer-capture".into(),
                source_commit,
                scope: scope(),
                adopted: adoption_decision == AdoptionDecision::Adopt,
            },
            binary_digest,
            provider_digest,
            result_status,
            result_provenance,
            adoption_decision,
            result_digest,
            adoption_digest,
            receipts,
            final_receipt,
            bundle_root: String::new(),
        };
        bundle.bundle_root = expected_bundle_root(&bundle).unwrap();
        bundle
    }

    #[test]
    fn checked_in_capture_contract_is_closed() {
        validate_contract().expect("capture contract");
        assert!(is_lower_hex(&contract_digest(), 32));
    }

    #[test]
    fn native_capture_replays_to_the_same_current_commit_conclusion() {
        let bundle = bundle(ProviderMode::Native);
        let commit = source_commit();
        let first = validate_bundle(&bundle, &commit).expect("native capture");
        let replay = validate_bundle(&bundle, &commit).expect("replayed native capture");
        assert_eq!(first, replay);
        assert_eq!(first.validator_status, CaptureValidatorStatus::NativePass);
        assert!(first.native_pass);
        assert_eq!(first.final_sequence, 9);
    }

    #[test]
    fn fixture_and_simulator_capture_are_not_native_pass() {
        for mode in [ProviderMode::Simulator, ProviderMode::Fixture] {
            let report = validate_bundle(&bundle(mode), &source_commit()).unwrap();
            assert_eq!(
                report.validator_status,
                CaptureValidatorStatus::NotEvaluated
            );
            assert!(!report.native_pass);
        }
    }

    #[test]
    fn bundle_root_and_receipt_tamper_are_rejected() {
        let commit = source_commit();
        let mut tampered = bundle(ProviderMode::Native);
        tampered.bundle_root.replace_range(..1, "0");
        assert!(validate_bundle(&tampered, &commit).is_err());

        let mut tampered_receipt = bundle(ProviderMode::Native);
        tampered_receipt.receipts[2]
            .payload_digest
            .replace_range(..1, "1");
        assert!(validate_bundle(&tampered_receipt, &commit).is_err());

        let mut tampered_timestamp = bundle(ProviderMode::Native);
        tampered_timestamp.receipts[2].occurred_at += Duration::milliseconds(1);
        assert!(validate_bundle(&tampered_timestamp, &commit).is_err());
    }

    #[test]
    fn cross_commit_and_missing_final_receipt_are_rejected() {
        let bundle = bundle(ProviderMode::Native);
        assert!(validate_bundle(&bundle, &"0".repeat(40)).is_err());

        let mut value = serde_json::to_value(bundle).unwrap();
        value.as_object_mut().unwrap().remove("finalReceipt");
        assert!(parse_strict_json::<CaptureBundle>(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn old_evaluator_recovery_flags_and_nonzero_exit_are_rejected() {
        let commit = source_commit();
        let mut bundle_first = bundle(ProviderMode::Native);
        bundle_first.receipts[5].old_evaluator_accepted = true;
        assert!(validate_bundle(&bundle_first, &commit).is_err());

        let mut bundle_again = bundle(ProviderMode::Native);
        bundle_again.final_receipt.exit_code = 1;
        assert!(validate_bundle(&bundle_again, &commit).is_err());
    }

    #[test]
    fn capture_bundle_json_rejects_unknown_and_duplicate_fields() {
        let value = serde_json::to_value(bundle(ProviderMode::Native)).unwrap();
        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("forgedPass".into(), json!(true));
        assert!(
            parse_strict_json::<CaptureBundle>(&serde_json::to_vec(&unknown).unwrap()).is_err()
        );
        assert!(
            parse_strict_json::<CaptureBundle>(br#"{"schemaVersion":"x","schemaVersion":"y"}"#)
                .is_err()
        );
    }
}
