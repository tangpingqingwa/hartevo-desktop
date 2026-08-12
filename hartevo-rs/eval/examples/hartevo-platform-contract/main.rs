mod digest;
mod model;
mod verifier;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use crate::digest::sha256_hex;
use crate::model::{PlatformMatrix, PlatformReceipt, parse_strict_json};
use crate::verifier::{
    INVENTORY_AUTHORITY, MatrixValidation, RELEASE_DECISION, VALIDATION_SCHEMA_VERSION,
    is_git_tool_unavailable, validate_matrix, validate_receipt, validate_receipt_schema,
    validate_receipt_schema_raw,
};

const MATRIX_PATH: &str = "contracts/platform/matrix.v1.json";
const RECEIPT_SCHEMA_PATH: &str = "contracts/platform/receipt.schema.v1.json";

fn main() {
    if let Err(error) = run() {
        let blocked_environment = is_git_tool_unavailable(&error);
        let failure = json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "authority": INVENTORY_AUTHORITY,
            "nativeCalls": 0,
            "releaseDecision": RELEASE_DECISION,
            "validatorStatus": if blocked_environment { "BLOCKED_ENV" } else { "FAIL" },
            "errorCode": if blocked_environment {
                "GIT_OBJECT_READER_UNAVAILABLE"
            } else {
                "CONTRACT_VALIDATION_FAILED"
            },
            "contractValidated": false,
            "platformCapabilitiesEvaluated": false,
            "writesPerformed": false,
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&failure)
                .expect("static validator failure report must serialize")
        );
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let matrix_bytes = read_contract(&repository_root, MATRIX_PATH, "platform matrix")?;
    let receipt_schema_bytes = read_contract(
        &repository_root,
        RECEIPT_SCHEMA_PATH,
        "platform receipt schema",
    )?;
    let matrix = parse_strict_json::<PlatformMatrix>(&matrix_bytes)
        .context("platform matrix is not strict typed JSON")?;
    validate_receipt_schema_raw(&receipt_schema_bytes, &matrix)?;
    let receipt_schema = parse_strict_json::<Value>(&receipt_schema_bytes)
        .context("platform receipt schema is not strict JSON")?;
    let matrix_validation = validate_matrix(&matrix, &repository_root)?;
    validate_receipt_schema(&receipt_schema, &receipt_schema_bytes, &matrix)?;

    let matrix_digest = sha256_hex(&matrix_bytes);
    let receipt_schema_digest = sha256_hex(&receipt_schema_bytes);
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let receipt_summaries = match args.as_slice() {
        [] => Vec::new(),
        [command] if command == "validate-contracts" => Vec::new(),
        [command] if command == "--help" || command == "-h" => {
            print_help();
            return Ok(());
        }
        [command, receipt_paths @ ..] if command == "validate-receipts" => {
            ensure!(
                !receipt_paths.is_empty(),
                "validate-receipts needs at least one receipt input"
            );
            validate_receipt_inputs(
                receipt_paths,
                &matrix,
                &matrix_validation,
                &matrix_digest,
                &receipt_schema_digest,
            )?
        }
        _ => bail!("unsupported command; use --help"),
    };

    let report = json!({
        "schemaVersion": VALIDATION_SCHEMA_VERSION,
        "authority": INVENTORY_AUTHORITY,
        "nativeCalls": 0,
        "releaseDecision": RELEASE_DECISION,
        "sourceCommit": matrix.source_commit,
        "matrixVersion": matrix.matrix_version,
        "matrixDigest": matrix_digest,
        "receiptSchemaDigest": receipt_schema_digest,
        "targetCount": matrix.targets.len(),
        "caseCount": matrix.cases.len(),
        "sourceAuditDispositionCounts": {
            "pass": matrix_validation.counts.pass,
            "fail": matrix_validation.counts.fail,
            "blockedEnv": matrix_validation.counts.blocked_env,
            "notImplemented": matrix_validation.counts.not_implemented,
        },
        "nativeReceiptCount": matrix.native_receipt_count,
        "validatedReceiptCount": receipt_summaries.len(),
        "validatedReceipts": receipt_summaries,
        "receiptSetComplete": receipt_summaries.len() == matrix.cases.len(),
        "missingReceiptCount": matrix.cases.len() - receipt_summaries.len(),
        "missingReceiptDisposition": "aggregate_failure",
        "contractValidated": true,
        "platformCapabilitiesEvaluated": false,
        "writesPerformed": false,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn read_contract(repository_root: &Path, relative_path: &str, label: &str) -> Result<Vec<u8>> {
    fs::read(repository_root.join(relative_path)).with_context(|| format!("reading {label}"))
}

fn validate_receipt_inputs(
    receipt_paths: &[OsString],
    matrix: &PlatformMatrix,
    matrix_validation: &MatrixValidation,
    matrix_digest: &str,
    receipt_schema_digest: &str,
) -> Result<Vec<verifier::ReceiptValidationSummary>> {
    let mut summaries = Vec::with_capacity(receipt_paths.len());
    let mut prior_case_id = None;
    for (index, path) in receipt_paths.iter().enumerate() {
        let bytes = fs::read(PathBuf::from(path))
            .with_context(|| format!("reading receipt input #{}", index + 1))?;
        let receipt = parse_strict_json::<PlatformReceipt>(&bytes)
            .with_context(|| format!("receipt input #{} is not strict typed JSON", index + 1))?;
        let summary = validate_receipt(
            &receipt,
            &bytes,
            matrix,
            matrix_validation,
            matrix_digest,
            receipt_schema_digest,
        )
        .with_context(|| format!("receipt input #{} is ineligible", index + 1))?;
        if let Some(previous) = prior_case_id.as_deref() {
            ensure!(
                previous < summary.case_id.as_str(),
                "receipt inputs must have sorted unique case ids"
            );
        }
        prior_case_id = Some(summary.case_id.clone());
        summaries.push(summary);
    }
    Ok(summaries)
}

fn print_help() {
    println!(
        "hartevo-platform-contract [validate-contracts | validate-receipts <receipt.json> ...]"
    );
    println!("Validates inventory contracts and optional content-free receipts; writes nothing.");
}
