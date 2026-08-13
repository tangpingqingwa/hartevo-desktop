mod digest;
mod model;
mod verifier;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use crate::model::{
    BrowserCaseRegistry, BrowserReplay, BrowserRunReceipt, BrowserWorld, parse_strict_json,
};
use crate::verifier::{
    RELEASE_DECISION, RegistryValidation, VALIDATION_AUTHORITY, VALIDATION_SCHEMA_VERSION,
    raw_contract_digest, repository_relative_contract_exists, validate_receipt, validate_registry,
    validate_release_and_run_seam, validate_schema_contracts, validate_world_and_replay,
};

const REGISTRY_PATH: &str = "contracts/browser-eval/browser-case-registry.v1.json";
const WORLD_SCHEMA_PATH: &str = "contracts/browser-eval/browser-world.v1.schema.json";
const REPLAY_SCHEMA_PATH: &str = "contracts/browser-eval/browser-replay.v1.schema.json";
const RECEIPT_SCHEMA_PATH: &str = "contracts/browser-eval/browser-run-receipt.v1.schema.json";
const RELEASE_SCHEMA_PATH: &str = "contracts/release-evidence/schema.v2.3.json";
const EVALUATION_RUN_SCHEMA_PATH: &str = "contracts/release-evidence/evaluation-run.v1.json";

fn main() {
    if let Err(error) = run() {
        let failure = json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "authority": VALIDATION_AUTHORITY,
            "nativeCalls": 0,
            "releaseDecision": RELEASE_DECISION,
            "validatorStatus": "FAIL",
            "errorCode": "BROWSER_CONTRACT_VALIDATION_FAILED",
            "contractValidated": false,
            "browserExecutionPerformed": false,
            "writesPerformed": false,
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&failure)
                .expect("static Browser validator failure must serialize")
        );
        eprintln!("Browser contract validation error: {error:#}");
        std::process::exit(2);
    }
}

// Keep the top-level read-only validation flow linear so its no-write behavior is auditable.
#[allow(clippy::too_many_lines)]
fn run() -> Result<()> {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for contract in [
        REGISTRY_PATH,
        WORLD_SCHEMA_PATH,
        REPLAY_SCHEMA_PATH,
        RECEIPT_SCHEMA_PATH,
        RELEASE_SCHEMA_PATH,
        EVALUATION_RUN_SCHEMA_PATH,
    ] {
        repository_relative_contract_exists(&repository_root, contract)?;
    }
    let registry_bytes = read_contract(&repository_root, REGISTRY_PATH, "Browser case registry")?;
    let world_schema_bytes =
        read_contract(&repository_root, WORLD_SCHEMA_PATH, "Browser World schema")?;
    let replay_schema_bytes = read_contract(
        &repository_root,
        REPLAY_SCHEMA_PATH,
        "Browser Replay schema",
    )?;
    let receipt_schema_bytes = read_contract(
        &repository_root,
        RECEIPT_SCHEMA_PATH,
        "Browser run receipt schema",
    )?;
    let release_schema_bytes = read_contract(
        &repository_root,
        RELEASE_SCHEMA_PATH,
        "Release Evidence 2.3 schema",
    )?;
    let evaluation_run_schema_bytes = read_contract(
        &repository_root,
        EVALUATION_RUN_SCHEMA_PATH,
        "RUN-01 evaluation-run schema",
    )?;
    let registry = parse_strict_json::<BrowserCaseRegistry>(&registry_bytes)
        .context("Browser case registry is not strict typed JSON")?;
    let registry_validation = validate_registry(&registry)?;
    let world_schema = parse_strict_json::<Value>(&world_schema_bytes)
        .context("Browser World schema is not strict JSON")?;
    let replay_schema = parse_strict_json::<Value>(&replay_schema_bytes)
        .context("Browser Replay schema is not strict JSON")?;
    let receipt_schema = parse_strict_json::<Value>(&receipt_schema_bytes)
        .context("Browser run receipt schema is not strict JSON")?;
    let release_schema = parse_strict_json::<Value>(&release_schema_bytes)
        .context("Release Evidence 2.3 schema is not strict JSON")?;
    let evaluation_run_schema = parse_strict_json::<Value>(&evaluation_run_schema_bytes)
        .context("RUN-01 evaluation-run schema is not strict JSON")?;
    validate_schema_contracts(&world_schema, &replay_schema, &receipt_schema)?;
    validate_release_and_run_seam(&registry, &release_schema, &evaluation_run_schema)?;

    let registry_digest = raw_contract_digest(&registry_bytes);
    let world_schema_digest = raw_contract_digest(&world_schema_bytes);
    let replay_schema_digest = raw_contract_digest(&replay_schema_bytes);
    let receipt_schema_digest = raw_contract_digest(&receipt_schema_bytes);
    let release_schema_digest = raw_contract_digest(&release_schema_bytes);
    let evaluation_run_schema_digest = raw_contract_digest(&evaluation_run_schema_bytes);
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let (receipt_summaries, evaluation_run_validated) = match arguments.as_slice() {
        [] => (Vec::new(), false),
        [command] if command == "validate-contracts" => (Vec::new(), false),
        [command] if command == "--help" || command == "-h" => {
            print_help();
            return Ok(());
        }
        [command, run_root, paths @ ..] if command == "validate-payloads" => {
            ensure!(
                !paths.is_empty() && paths.len() % 3 == 0,
                "validate-payloads requires RUN_ROOT and one or more WORLD REPLAY RECEIPT triples"
            );
            let (evaluation_run, evaluation_plan) =
                validate_evaluation_run_input(Path::new(run_root))?;
            (
                validate_payload_inputs(
                    paths,
                    &registry,
                    &registry_validation,
                    &registry_digest,
                    &world_schema_digest,
                    &replay_schema_digest,
                    &receipt_schema_digest,
                    &evaluation_run,
                    &evaluation_plan,
                )?,
                true,
            )
        }
        _ => bail!("unsupported Browser contract command; use --help"),
    };

    let implemented_default_count = registry
        .cases
        .iter()
        .filter(|case| {
            case.execution_status == crate::model::ExecutionStatus::ImplementedDefaultTest
        })
        .count();
    let implemented_ignored_count = registry
        .cases
        .iter()
        .filter(|case| {
            case.execution_status == crate::model::ExecutionStatus::ImplementedIgnoredEnvTest
        })
        .count();
    let not_implemented_count = registry
        .cases
        .iter()
        .filter(|case| case.execution_status == crate::model::ExecutionStatus::NotImplemented)
        .count();
    let report = json!({
        "schemaVersion": VALIDATION_SCHEMA_VERSION,
        "authority": VALIDATION_AUTHORITY,
        "nativeCalls": 0,
        "releaseDecision": RELEASE_DECISION,
        "sourceCommit": registry.source_commit,
        "registryVersion": registry.registry_version,
        "registryDigest": registry_digest,
        "worldSchemaDigest": world_schema_digest,
        "replaySchemaDigest": replay_schema_digest,
        "receiptSchemaDigest": receipt_schema_digest,
        "releaseSchemaDigest": release_schema_digest,
        "evaluationRunSchemaDigest": evaluation_run_schema_digest,
        "caseCount": registry.cases.len(),
        "implementedDefaultTestCount": implemented_default_count,
        "implementedIgnoredEnvironmentTestCount": implemented_ignored_count,
        "notImplementedCount": not_implemented_count,
        "validatedPayloadCount": receipt_summaries.len(),
        "validatedPayloads": receipt_summaries,
        "evaluationRunValidated": evaluation_run_validated,
        "contractValidated": true,
        "browserExecutionPerformed": false,
        "writesPerformed": false,
        "releaseEvidenceWritten": false,
        "evaluationRunResultReferencesCleared": false,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn read_contract(repository_root: &Path, relative_path: &str, label: &str) -> Result<Vec<u8>> {
    fs::read(repository_root.join(relative_path)).with_context(|| format!("reading {label}"))
}

#[allow(clippy::too_many_arguments)]
fn validate_payload_inputs(
    paths: &[OsString],
    registry: &BrowserCaseRegistry,
    registry_validation: &RegistryValidation,
    registry_digest: &str,
    world_schema_digest: &str,
    replay_schema_digest: &str,
    receipt_schema_digest: &str,
    evaluation_run: &hartevo_eval::EvaluationRunReceipt,
    evaluation_plan: &Value,
) -> Result<Vec<verifier::ReceiptValidationSummary>> {
    let mut summaries = Vec::with_capacity(paths.len() / 3);
    let mut prior_case_id = None;
    for (index, triple) in paths.chunks_exact(3).enumerate() {
        let world_bytes = read_input(&triple[0], index, "World")?;
        let replay_bytes = read_input(&triple[1], index, "Replay")?;
        let receipt_bytes = read_input(&triple[2], index, "BrowserRunReceipt")?;
        let world = parse_strict_json::<BrowserWorld>(&world_bytes)
            .with_context(|| format!("payload #{} World is not strict typed JSON", index + 1))?;
        let replay = parse_strict_json::<BrowserReplay>(&replay_bytes)
            .with_context(|| format!("payload #{} Replay is not strict typed JSON", index + 1))?;
        let receipt =
            parse_strict_json::<BrowserRunReceipt>(&receipt_bytes).with_context(|| {
                format!(
                    "payload #{} BrowserRunReceipt is not strict typed JSON",
                    index + 1
                )
            })?;
        let (world_digest, replay_digest) = validate_world_and_replay(&world, &replay)
            .with_context(|| format!("payload #{} World/Replay is invalid", index + 1))?;
        let summary = validate_receipt(
            &receipt,
            &receipt_bytes,
            registry,
            registry_validation,
            registry_digest,
            world_schema_digest,
            replay_schema_digest,
            receipt_schema_digest,
            &world,
            &world_digest,
            &replay,
            &replay_digest,
            evaluation_run,
            evaluation_plan,
        )
        .with_context(|| format!("payload #{} BrowserRunReceipt is invalid", index + 1))?;
        if let Some(previous) = prior_case_id.as_deref() {
            ensure!(
                previous < summary.case_id.as_str(),
                "Browser payload triples must have sorted unique case ids"
            );
        }
        prior_case_id = Some(summary.case_id.clone());
        summaries.push(summary);
    }
    Ok(summaries)
}

fn validate_evaluation_run_input(
    run_root: &Path,
) -> Result<(hartevo_eval::EvaluationRunReceipt, Value)> {
    let canonical_root = run_root
        .canonicalize()
        .context("canonicalizing RUN-01 evaluation root")?;
    let plan_path = canonical_root.join("plan.json");
    let plan_before = fs::read(&plan_path).context("reading RUN-01 plan before validation")?;
    let receipt = hartevo_eval::validate_evaluation_run(&canonical_root)
        .context("RUN-01 evaluation run root is not a valid finalized run")?;
    let plan_after = fs::read(&plan_path).context("reading RUN-01 plan after validation")?;
    ensure!(
        plan_before == plan_after,
        "RUN-01 plan changed while Browser payloads were being validated"
    );
    let plan = parse_strict_json::<Value>(&plan_after)
        .context("validated RUN-01 plan is not strict JSON")?;
    Ok((receipt, plan))
}

fn read_input(path: &OsString, index: usize, kind: &str) -> Result<Vec<u8>> {
    fs::read(PathBuf::from(path))
        .with_context(|| format!("reading payload #{} {kind} input", index + 1))
}

fn print_help() {
    println!("hartevo-browser-contract [validate-contracts]");
    println!(
        "hartevo-browser-contract validate-payloads <run-root> <world.json> <replay.json> <receipt.json> ..."
    );
    println!("Validates Browser contracts and payloads; performs no Browser calls or writes.");
}
