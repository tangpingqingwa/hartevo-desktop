mod digest;
mod model;
mod verifier;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::json;

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
                    "authority": AUTHORITY,
                    "releaseDecision": RELEASE_DECISION,
                    "oracleStatus": "NOT_EVALUATED",
                    "nativePass": false,
                }))?
            );
            Ok(CommandOutcome::NotEvaluated)
        }
        [command, path] if command == "verify" => verify_path(path),
        _ => bail!("unsupported command; use --help, validate-contract, or verify <journey.json>"),
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

fn print_report(report: &OracleReport) -> Result<()> {
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
        }))?
    );
    Ok(())
}

fn print_help() {
    println!(
        "Usage: cargo run -p hartevo-eval --example hartevo-plugin-native-journey -- \\
         [validate-contract | verify <journey.json>]"
    );
    println!(
        "No input is a deliberate BLOCKED_ENV result; fixture, simulator, ignored, and missing real components never PASS."
    );
}
