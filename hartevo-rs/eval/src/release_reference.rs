use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use hartevo_catalog::{
    BrowserEvaluationResultReference, BrowserReferenceEvidenceClass, BrowserReferenceProviderMode,
    BrowserReferenceValidationAuthority, BrowserReferenceVerdict, EvaluationRunResultReference,
    EvaluationRunResultReferences,
};
use serde::Serialize;
use serde_json::Value;

use crate::digest::digest_json;
use crate::model::{
    AggregateVerdict, BrowserCaseRegistry, BrowserReplay, BrowserRunReceipt, BrowserWorld,
    EvidenceClass, ProviderMode, parse_strict_json,
};
use crate::run_receipt::{
    EvaluationRunReceipt, validate_evaluation_run, validate_evaluation_run_result_reference,
};
use crate::verifier::{
    RELEASE_DECISION, ReceiptValidationSummary, RegistryValidation, VALIDATION_AUTHORITY,
    VALIDATION_SCHEMA_VERSION, raw_contract_digest, repository_relative_contract_exists,
    validate_receipt, validate_registry, validate_release_and_run_seam, validate_schema_contracts,
    validate_world_and_replay,
};

const BROWSER_VALIDATION_RESULT_DIGEST_DOMAIN: &str =
    "hartevo-release-browser-validation-result/v1";
const PLAN_FILE: &str = "plan.json";
const BROWSER_REGISTRY_PATH: &str = "contracts/browser-eval/browser-case-registry.v1.json";
const BROWSER_WORLD_SCHEMA_PATH: &str = "contracts/browser-eval/browser-world.v1.schema.json";
const BROWSER_REPLAY_SCHEMA_PATH: &str = "contracts/browser-eval/browser-replay.v1.schema.json";
const BROWSER_RECEIPT_SCHEMA_PATH: &str =
    "contracts/browser-eval/browser-run-receipt.v1.schema.json";
const RELEASE_EVIDENCE_SCHEMA_PATH: &str = "contracts/release-evidence/schema.v2.3.json";
const EVALUATION_RUN_SCHEMA_PATH: &str = "contracts/release-evidence/evaluation-run.v1.json";

const BROWSER_REGISTRY: &[u8] =
    include_bytes!("../../../contracts/browser-eval/browser-case-registry.v1.json");
const BROWSER_WORLD_SCHEMA: &[u8] =
    include_bytes!("../../../contracts/browser-eval/browser-world.v1.schema.json");
const BROWSER_REPLAY_SCHEMA: &[u8] =
    include_bytes!("../../../contracts/browser-eval/browser-replay.v1.schema.json");
const BROWSER_RECEIPT_SCHEMA: &[u8] =
    include_bytes!("../../../contracts/browser-eval/browser-run-receipt.v1.schema.json");
const RELEASE_EVIDENCE_SCHEMA: &[u8] =
    include_bytes!("../../../contracts/release-evidence/schema.v2.3.json");
const EVALUATION_RUN_SCHEMA: &[u8] =
    include_bytes!("../../../contracts/release-evidence/evaluation-run.v1.json");

#[derive(Clone, Copy, Debug)]
pub struct BrowserEvaluationPayload<'a> {
    world: &'a [u8],
    replay: &'a [u8],
    receipt: &'a [u8],
}

impl<'a> BrowserEvaluationPayload<'a> {
    pub const fn new(world: &'a [u8], replay: &'a [u8], receipt: &'a [u8]) -> Self {
        Self {
            world,
            replay,
            receipt,
        }
    }
}

pub fn validate_evaluation_run_result_references(
    run_root: impl AsRef<Path>,
) -> Result<EvaluationRunResultReferences> {
    let run = validate_evaluation_run_result_reference(run_root)?;
    EvaluationRunResultReferences::new(Some(run), Vec::new())
        .map_err(|error| anyhow::anyhow!(error))
}

/// Re-runs both RUN-01 and the full J-01 typed World/Replay/Receipt verifier.
/// No caller-supplied `validated` boolean, source-audit record or simulator
/// label can substitute for those validators. The resulting references still
/// carry `run_evidence_only`/`E1_MAX`; Release authority remains in Catalog.
pub fn validate_evaluation_run_and_browser_result_references(
    run_root: impl AsRef<Path>,
    payloads: &[BrowserEvaluationPayload<'_>],
) -> Result<EvaluationRunResultReferences> {
    ensure!(
        !payloads.is_empty(),
        "Browser result reference production requires at least one payload triple"
    );
    let run = ValidatedRunInput::load(run_root.as_ref())?;
    let contracts = CurrentBrowserContracts::load()?;
    let mut browser_results = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| validate_browser_payload(index, payload, &run, &contracts))
        .collect::<Result<Vec<_>>>()?;
    browser_results.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    ensure!(
        browser_results
            .windows(2)
            .all(|pair| pair[0].case_id != pair[1].case_id),
        "Browser result reference input contains duplicate case IDs"
    );
    EvaluationRunResultReferences::new(Some(run.reference), browser_results)
        .map_err(|error| anyhow::anyhow!(error))
}

struct ValidatedRunInput {
    reference: EvaluationRunResultReference,
    receipt: EvaluationRunReceipt,
    plan: Value,
}

impl ValidatedRunInput {
    fn load(root: &Path) -> Result<Self> {
        let canonical_root = root
            .canonicalize()
            .context("canonicalizing RUN-01 evaluation root")?;
        let plan_path = canonical_root.join(PLAN_FILE);
        let plan_before = read_regular_bytes(&plan_path)?;
        let reference = validate_evaluation_run_result_reference(&canonical_root)
            .context("RUN-01 result reference validation failed")?;
        let receipt = validate_evaluation_run(&canonical_root)
            .context("RUN-01 finalized receipt validation failed")?;
        let plan_after = read_regular_bytes(&plan_path)?;
        ensure!(
            plan_before == plan_after,
            "RUN-01 plan changed while Browser result references were produced"
        );
        ensure!(
            receipt.run_id() == reference.run_id
                && receipt.result_set_digest() == reference.result_set_digest
                && receipt.structurally_complete() == reference.structurally_complete
                && receipt.partition_complete() == reference.partition_complete
                && receipt.executed_case_count() == reference.executed_case_count,
            "RUN-01 public receipt and derived Release reference disagree"
        );
        let plan = parse_strict_json::<Value>(&plan_after)
            .context("validated RUN-01 plan is not strict JSON")?;
        Ok(Self {
            reference,
            receipt,
            plan,
        })
    }
}

struct CurrentBrowserContracts {
    registry: BrowserCaseRegistry,
    registry_validation: RegistryValidation,
    registry_digest: String,
    world_schema_digest: String,
    replay_schema_digest: String,
    receipt_schema_digest: String,
}

impl CurrentBrowserContracts {
    fn load() -> Result<Self> {
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for relative_path in [
            BROWSER_REGISTRY_PATH,
            BROWSER_WORLD_SCHEMA_PATH,
            BROWSER_REPLAY_SCHEMA_PATH,
            BROWSER_RECEIPT_SCHEMA_PATH,
            RELEASE_EVIDENCE_SCHEMA_PATH,
            EVALUATION_RUN_SCHEMA_PATH,
        ] {
            repository_relative_contract_exists(&repository_root, relative_path)?;
        }
        let registry = parse_strict_json::<BrowserCaseRegistry>(BROWSER_REGISTRY)
            .context("Browser case registry is not strict typed JSON")?;
        let registry_validation = validate_registry(&registry)?;
        let world_schema = parse_strict_json::<Value>(BROWSER_WORLD_SCHEMA)
            .context("Browser World schema is not strict JSON")?;
        let replay_schema = parse_strict_json::<Value>(BROWSER_REPLAY_SCHEMA)
            .context("Browser Replay schema is not strict JSON")?;
        let receipt_schema = parse_strict_json::<Value>(BROWSER_RECEIPT_SCHEMA)
            .context("Browser receipt schema is not strict JSON")?;
        let release_schema = parse_strict_json::<Value>(RELEASE_EVIDENCE_SCHEMA)
            .context("Release Evidence schema is not strict JSON")?;
        let evaluation_run_schema = parse_strict_json::<Value>(EVALUATION_RUN_SCHEMA)
            .context("RUN-01 schema is not strict JSON")?;
        validate_schema_contracts(&world_schema, &replay_schema, &receipt_schema)?;
        validate_release_and_run_seam(&registry, &release_schema, &evaluation_run_schema)?;
        Ok(Self {
            registry,
            registry_validation,
            registry_digest: raw_contract_digest(BROWSER_REGISTRY),
            world_schema_digest: raw_contract_digest(BROWSER_WORLD_SCHEMA),
            replay_schema_digest: raw_contract_digest(BROWSER_REPLAY_SCHEMA),
            receipt_schema_digest: raw_contract_digest(BROWSER_RECEIPT_SCHEMA),
        })
    }
}

fn validate_browser_payload(
    index: usize,
    payload: &BrowserEvaluationPayload<'_>,
    run: &ValidatedRunInput,
    contracts: &CurrentBrowserContracts,
) -> Result<BrowserEvaluationResultReference> {
    let world = parse_strict_json::<BrowserWorld>(payload.world)
        .with_context(|| format!("Browser payload #{} World is invalid", index + 1))?;
    let replay = parse_strict_json::<BrowserReplay>(payload.replay)
        .with_context(|| format!("Browser payload #{} Replay is invalid", index + 1))?;
    let receipt = parse_strict_json::<BrowserRunReceipt>(payload.receipt)
        .with_context(|| format!("Browser payload #{} receipt is invalid", index + 1))?;
    let (world_digest, replay_digest) = validate_world_and_replay(&world, &replay)
        .with_context(|| format!("Browser payload #{} World/Replay failed", index + 1))?;
    let summary = validate_receipt(
        &receipt,
        payload.receipt,
        &contracts.registry,
        &contracts.registry_validation,
        &contracts.registry_digest,
        &contracts.world_schema_digest,
        &contracts.replay_schema_digest,
        &contracts.receipt_schema_digest,
        &world,
        &world_digest,
        &replay,
        &replay_digest,
        &run.receipt,
        &run.plan,
    )
    .with_context(|| format!("Browser payload #{} receipt failed", index + 1))?;
    derive_browser_result_reference(
        &receipt,
        &summary,
        &world_digest,
        &replay_digest,
        &run.reference,
        contracts,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserValidationResultDigestMaterial<'a> {
    schema_version: &'static str,
    authority: &'static str,
    release_decision: &'static str,
    run_id: &'a str,
    result_set_digest: &'a str,
    registry_digest: &'a str,
    world_schema_digest: &'a str,
    replay_schema_digest: &'a str,
    receipt_schema_digest: &'a str,
    world_digest: &'a str,
    replay_digest: &'a str,
    summary: &'a ReceiptValidationSummary,
}

fn derive_browser_result_reference(
    receipt: &BrowserRunReceipt,
    summary: &ReceiptValidationSummary,
    world_digest: &str,
    replay_digest: &str,
    run: &EvaluationRunResultReference,
    contracts: &CurrentBrowserContracts,
) -> Result<BrowserEvaluationResultReference> {
    let evidence_classes = receipt
        .attempts
        .iter()
        .map(|attempt| map_evidence_class(attempt.evidence_class))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let validation_result_digest = digest_json(
        BROWSER_VALIDATION_RESULT_DIGEST_DOMAIN,
        &BrowserValidationResultDigestMaterial {
            schema_version: VALIDATION_SCHEMA_VERSION,
            authority: VALIDATION_AUTHORITY,
            release_decision: RELEASE_DECISION,
            run_id: &run.run_id,
            result_set_digest: &run.result_set_digest,
            registry_digest: &contracts.registry_digest,
            world_schema_digest: &contracts.world_schema_digest,
            replay_schema_digest: &contracts.replay_schema_digest,
            receipt_schema_digest: &contracts.receipt_schema_digest,
            world_digest,
            replay_digest,
            summary,
        },
    )?;
    Ok(BrowserEvaluationResultReference {
        validation_authority:
            BrowserReferenceValidationAuthority::HartevoBrowserContractValidatorV1,
        receipt_schema_version: receipt.schema_version.clone(),
        receipt_authority: receipt.authority.clone(),
        release_decision: receipt.release_decision.clone(),
        release_commit: run.release_commit.clone(),
        catalog_digest: run.catalog_digest.clone(),
        release_schema_digest: run.release_schema_digest.clone(),
        environment_digest: run.environment_digest.clone(),
        run_id: run.run_id.clone(),
        result_set_digest: run.result_set_digest.clone(),
        case_id: receipt.case.case_id.clone(),
        provider_mode: match receipt.provider.mode {
            ProviderMode::ControlledSimulator => BrowserReferenceProviderMode::ControlledSimulator,
            ProviderMode::NativeBrowserAccount => {
                BrowserReferenceProviderMode::NativeBrowserAccount
            }
        },
        evidence_classes,
        verdict: match summary.verdict {
            AggregateVerdict::Pass => BrowserReferenceVerdict::Pass,
            AggregateVerdict::Fail => BrowserReferenceVerdict::Fail,
            AggregateVerdict::Incomplete => BrowserReferenceVerdict::Incomplete,
        },
        configured_attempt_count: receipt.aggregate.configured_attempt_count,
        recorded_attempt_count: summary.recorded_attempt_count,
        executed_attempt_count: summary.executed_attempt_count,
        successful_attempt_count: receipt.aggregate.outcomes.pass,
        execution_started_attempt_count: receipt
            .attempts
            .iter()
            .filter(|attempt| attempt.execution_started)
            .count(),
        test_mode_attempt_count: receipt
            .attempts
            .iter()
            .filter(|attempt| attempt.test_mode)
            .count(),
        mock_attempt_count: receipt
            .attempts
            .iter()
            .filter(|attempt| attempt.mock)
            .count(),
        ignored_test_attempt_count: receipt
            .attempts
            .iter()
            .filter(|attempt| attempt.ignored_test)
            .count(),
        receipt_digest: summary.receipt_digest.clone(),
        validation_result_digest,
        release_evidence_authority: receipt.authority_claims.release_evidence_authority,
        e_level_ceiling: receipt.authority_claims.e_level.clone(),
    })
}

const fn map_evidence_class(value: EvidenceClass) -> BrowserReferenceEvidenceClass {
    match value {
        EvidenceClass::SourceAudit => BrowserReferenceEvidenceClass::SourceAudit,
        EvidenceClass::NativePreflight => BrowserReferenceEvidenceClass::NativePreflight,
        EvidenceClass::DeterministicSimulator => {
            BrowserReferenceEvidenceClass::DeterministicSimulator
        }
        EvidenceClass::NativeBrowser => BrowserReferenceEvidenceClass::NativeBrowser,
        EvidenceClass::NativeBrowserAccountReadback => {
            BrowserReferenceEvidenceClass::NativeBrowserAccountReadback
        }
    }
}

fn read_regular_bytes(path: &PathBuf) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "evidence path {} must be a regular file, not a symlink",
        path.display()
    );
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hartevo_catalog::ReleaseEvidence;
    use serde_json::json;

    const MISSING_STAGE_ROUTE_SCOPE: &str = "stage_application_route_scope";

    fn wave_zero_release_json() -> Value {
        serde_json::to_value(
            crate::wave_zero_release_evidence("a".repeat(40), Utc::now())
                .expect("Wave 0 Release Evidence"),
        )
        .expect("Release Evidence JSON")
    }

    #[test]
    fn checked_in_browser_contracts_and_release_seam_validate() {
        CurrentBrowserContracts::load().expect("current Browser contracts");
    }

    #[test]
    fn evidence_class_mapping_preserves_audit_and_execution_vocabulary() {
        assert_eq!(
            map_evidence_class(EvidenceClass::SourceAudit),
            BrowserReferenceEvidenceClass::SourceAudit
        );
        assert_eq!(
            map_evidence_class(EvidenceClass::DeterministicSimulator),
            BrowserReferenceEvidenceClass::DeterministicSimulator
        );
        assert_eq!(
            map_evidence_class(EvidenceClass::NativeBrowserAccountReadback),
            BrowserReferenceEvidenceClass::NativeBrowserAccountReadback
        );
    }

    #[test]
    fn browser_payload_constructor_carries_exact_three_public_documents() {
        let payload = BrowserEvaluationPayload::new(b"world", b"replay", b"receipt");
        assert_eq!(payload.world, b"world");
        assert_eq!(payload.replay, b"replay");
        assert_eq!(payload.receipt, b"receipt");
    }

    #[test]
    fn untyped_stage_route_scope_claims_cannot_be_smuggled_into_release_evidence() {
        let schema =
            parse_strict_json::<Value>(RELEASE_EVIDENCE_SCHEMA).expect("Release Evidence schema");
        assert_eq!(
            schema.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        for field in [
            "stageApplicationRouteScope",
            "stageApplicationRouteScopeDigest",
            "stageApplicationRouteScopeReleaseCommit",
            "stageApplicationRouteScopeHandlerIds",
        ] {
            assert!(
                schema.pointer(&format!("/properties/{field}")).is_none(),
                "{field} must remain unavailable until CT-04 defines a typed contract"
            );
        }

        let forged_scope = json!({
            "schemaVersion": "hartevo-stage-application-route-scope/v1",
            "scopeDigest": "b".repeat(64),
            "releaseCommit": "c".repeat(40),
            "catalogDigest": "d".repeat(64),
            "applicationHandlerRegistryVersion": "forged-handler-registry/v1",
            "applicationRouteCount": 52,
            "implementedHandlerCount": 52,
            "handlerIds": ["forged-handler"]
        });
        for (field, claim) in [
            ("stageApplicationRouteScope", forged_scope),
            ("stageApplicationRouteScopeDigest", json!("b".repeat(64))),
            (
                "stageApplicationRouteScopeReleaseCommit",
                json!("c".repeat(40)),
            ),
            (
                "stageApplicationRouteScopeHandlerIds",
                json!(["forged-handler"]),
            ),
        ] {
            let mut candidate = wave_zero_release_json();
            candidate["passed"] = Value::Bool(true);
            candidate["missingRequiredEvidence"] = json!(["evaluation_run_result_references"]);
            candidate
                .as_object_mut()
                .expect("Release Evidence object")
                .insert(field.to_owned(), claim);
            assert!(
                serde_json::from_value::<ReleaseEvidence>(candidate).is_err(),
                "untyped {field} claim must be rejected before gate evaluation"
            );
        }
    }

    #[test]
    fn forged_catalog_counts_cannot_delete_the_stage_route_scope_gap() {
        let mut evidence = crate::wave_zero_release_evidence("a".repeat(40), Utc::now())
            .expect("Wave 0 Release Evidence");
        evidence
            .missing_required_evidence
            .retain(|missing| missing != MISSING_STAGE_ROUTE_SCOPE);
        evidence.passed = true;
        evidence.release_commit = "c".repeat(40);
        evidence.catalog_digest = "d".repeat(64);
        evidence.application_handler_registry_version = "forged-handler-registry/v1".into();
        evidence.implemented_application_handler_count = evidence.application_route_count;
        evidence.not_implemented_application_route_count = 0;

        let violations = evidence
            .validate_fail_closed()
            .expect_err("forged route coverage must remain fail-closed");
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("exact current Catalog snapshot"))
        );
        assert!(violations.iter().any(|violation| {
            violation.contains("missingRequiredEvidence must be machine-derived")
        }));
        assert!(!evidence.derived_passed());
    }
}
