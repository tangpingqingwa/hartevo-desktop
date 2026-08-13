mod digest;
mod evidence;
mod model;
mod verifier;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::evidence::{
    CONTRACT_PATH as EVIDENCE_CONTRACT_PATH, EvidenceVerificationReport, HonestyClassification,
    contract_digest as evidence_contract_digest, read_manifest,
    validate_contract as validate_evidence_contract,
};
use crate::model::{OracleReport, OracleStatus};
use crate::verifier::{
    AUTHORITY, CONTRACT_PATH, CONTRACT_SCHEMA_VERSION, DOCUMENT_TYPE, RELEASE_DECISION,
    REPORT_SCHEMA_VERSION, contract_digest, current_source_commit, read_journey, validate_contract,
    validate_journey,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutcome {
    Success,
    NotEvaluated,
    BlockedEnv,
}

fn main() -> ExitCode {
    match run() {
        Ok(CommandOutcome::Success) => ExitCode::SUCCESS,
        Ok(CommandOutcome::NotEvaluated | CommandOutcome::BlockedEnv) => ExitCode::from(3),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": REPORT_SCHEMA_VERSION,
                    "documentType": DOCUMENT_TYPE,
                    "authority": AUTHORITY,
                    "releaseDecision": RELEASE_DECISION,
                    "oracleStatus": "NOT_EVALUATED",
                    "nativePass": false,
                    "contractPath": CONTRACT_PATH,
                    "contractDigest": contract_digest(),
                    "evidenceContractDigest": evidence_contract_digest(),
                    "evidenceContractPath": EVIDENCE_CONTRACT_PATH,
                    "error": format!("{error:#}"),
                }))
                .expect("static failure report serializes")
            );
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<CommandOutcome> {
    validate_contract().context("validate checked-in plugin native journey contract")?;
    validate_evidence_contract().context("validate checked-in plugin journey evidence contract")?;
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => {
            print_blocked_report("real_runtime_model_plugin_or_provider_missing")?;
            Ok(CommandOutcome::BlockedEnv)
        }
        [command] if command == "--help" || command == "-h" => {
            print_help();
            Ok(CommandOutcome::Success)
        }
        [command] if command == "validate-contract" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": REPORT_SCHEMA_VERSION,
                    "contractSchemaVersion": CONTRACT_SCHEMA_VERSION,
                    "contractPath": CONTRACT_PATH,
                    "contractDigest": contract_digest(),
                    "evidenceContractDigest": evidence_contract_digest(),
                    "evidenceContractPath": EVIDENCE_CONTRACT_PATH,
                    "authority": AUTHORITY,
                    "releaseDecision": RELEASE_DECISION,
                    "oracleStatus": "NOT_EVALUATED",
                    "nativePass": false,
                }))?
            );
            Ok(CommandOutcome::NotEvaluated)
        }
        [command, path] if command == "verify" => verify_path(path),
        [command, journey_path, manifest_path] if command == "verify-evidence" => {
            verify_evidence_path(journey_path, manifest_path)
        }
        _ => bail!(
            "unsupported command; use --help, validate-contract, verify <journey.json>, or verify-evidence <journey.json> <manifest.json>"
        ),
    }
}

fn verify_path(path: &std::ffi::OsStr) -> Result<CommandOutcome> {
    let path = PathBuf::from(path);
    let expected_commit = current_source_commit()?;
    let journey = read_journey(&path)?;
    let report = validate_journey(&journey, &expected_commit)?;
    print_report(&report)?;
    Ok(match report.oracle_status {
        OracleStatus::NativePass => CommandOutcome::Success,
        OracleStatus::NotEvaluated => CommandOutcome::NotEvaluated,
        OracleStatus::BlockedEnv => CommandOutcome::BlockedEnv,
    })
}

fn verify_evidence_path(
    journey_path: &std::ffi::OsStr,
    manifest_path: &std::ffi::OsStr,
) -> Result<CommandOutcome> {
    let expected_commit = current_source_commit()?;
    let journey = read_journey(PathBuf::from(journey_path))?;
    let oracle = validate_journey(&journey, &expected_commit)?;
    let manifest = read_manifest(PathBuf::from(manifest_path))?;
    let mut replay_guard = evidence::ReplayGuard::default();
    let report = replay_guard.verify_once(&manifest, &journey, &oracle, &expected_commit)?;
    print_evidence_report(&report)?;
    Ok(if report.verdict == evidence::EvidenceVerdict::NativePass {
        CommandOutcome::Success
    } else if report.classification == HonestyClassification::BlockedEnv {
        CommandOutcome::BlockedEnv
    } else {
        CommandOutcome::NotEvaluated
    })
}

fn print_report(report: &OracleReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn print_evidence_report(report: &EvidenceVerificationReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn print_blocked_report(reason: &str) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "documentType": DOCUMENT_TYPE,
            "authority": AUTHORITY,
            "releaseDecision": RELEASE_DECISION,
            "oracleStatus": "BLOCKED_ENV",
            "nativePass": false,
            "missingReasons": [reason],
            "contractPath": CONTRACT_PATH,
            "contractDigest": contract_digest(),
            "evidenceContractDigest": evidence_contract_digest(),
            "evidenceContractPath": EVIDENCE_CONTRACT_PATH,
        }))?
    );
    Ok(())
}

fn print_help() {
    println!(
        "Usage: cargo run -p hartevo-eval --example hartevo-plugin-native-journey -- \\
         [validate-contract | verify <journey.json> | verify-evidence <journey.json> <manifest.json>]"
    );
    println!(
        "No input is a deliberate BLOCKED_ENV result; fixture, simulator, ignored, and missing real components never PASS."
    );
}
