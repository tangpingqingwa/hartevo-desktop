mod capture;
mod digest;
mod model;
mod verifier;

use std::env;

use anyhow::{Result, bail};
use serde_json::json;

use crate::capture::{
    AUTHORITY as CAPTURE_AUTHORITY, CONTRACT_PATH as CAPTURE_CONTRACT_PATH,
    RELEASE_DECISION as CAPTURE_RELEASE_DECISION,
    REPORT_SCHEMA_VERSION as CAPTURE_REPORT_SCHEMA_VERSION,
    contract_digest as capture_contract_digest, read_capture, validate_capture,
    validate_contract as validate_capture_contract,
};
use crate::verifier::{
    APP_SERVER_CONTRACT_PATH, AUTHORITY, CONTRACT_PATH, RELEASE_DECISION, REPORT_SCHEMA_VERSION,
    app_server_contract_digest, contract_digest, current_source_commit,
    read_capture as read_session, validate_bundle, validate_contract,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutcome {
    Success,
    NotEvaluated,
    BlockedEnv,
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(CommandOutcome::Success) => {}
        Ok(CommandOutcome::NotEvaluated | CommandOutcome::BlockedEnv) => std::process::exit(3),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": REPORT_SCHEMA_VERSION,
                    "authority": AUTHORITY,
                    "releaseDecision": RELEASE_DECISION,
                    "validatorStatus": "FAIL",
                    "nativePass": false,
                    "contractPath": CONTRACT_PATH,
                    "contractDigest": contract_digest(),
                    "error": error.to_string(),
                }))
                .expect("OpenInterpreter failure report serializes")
            );
            std::process::exit(2);
        }
    }
}

fn run(arguments: &[String]) -> Result<CommandOutcome> {
    validate_contract()?;
    validate_capture_contract()?;
    match arguments {
        [] => {
            print_missing_capture(&current_source_commit()?);
            Ok(CommandOutcome::BlockedEnv)
        }
        [command] if command == "validate-contract" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": REPORT_SCHEMA_VERSION,
                    "authority": AUTHORITY,
                    "releaseDecision": RELEASE_DECISION,
                    "validatorStatus": "NOT_EVALUATED",
                    "nativePass": false,
                    "contractPath": CONTRACT_PATH,
                    "contractDigest": contract_digest(),
                    "appServerContractPath": APP_SERVER_CONTRACT_PATH,
                    "appServerContractDigest": app_server_contract_digest(),
                    "contractValidated": true,
                }))?
            );
            Ok(CommandOutcome::Success)
        }
        [command] if command == "capture-validate-contract" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": CAPTURE_REPORT_SCHEMA_VERSION,
                    "authority": CAPTURE_AUTHORITY,
                    "releaseDecision": CAPTURE_RELEASE_DECISION,
                    "validatorStatus": "NOT_EVALUATED",
                    "nativePass": false,
                    "contractPath": CAPTURE_CONTRACT_PATH,
                    "contractDigest": capture_contract_digest(),
                    "contractValidated": true,
                }))?
            );
            Ok(CommandOutcome::Success)
        }
        [command, path] if command == "verify" => {
            let source_commit = current_source_commit()?;
            let session = read_session(path)?;
            let report = validate_bundle(&session, &source_commit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.native_pass {
                CommandOutcome::Success
            } else if report.validator_status == model::ValidatorStatus::BlockedEnv {
                CommandOutcome::BlockedEnv
            } else {
                CommandOutcome::NotEvaluated
            })
        }
        [command, path] if command == "capture-verify" => {
            let source_commit = current_source_commit()?;
            let capture = read_capture(path)?;
            let report = validate_capture(&capture, &source_commit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.native_pass {
                CommandOutcome::Success
            } else if report.validator_status == capture::CaptureValidatorStatus::BlockedEnv {
                CommandOutcome::BlockedEnv
            } else {
                CommandOutcome::NotEvaluated
            })
        }
        [command] if command == "--help" || command == "-h" => {
            print_help();
            Ok(CommandOutcome::Success)
        }
        _ => bail!(
            "unsupported command; use --help, validate-contract, verify <capture.json>, \
             capture-validate-contract, or capture-verify <capture.json>"
        ),
    }
}

fn print_missing_capture(source_commit: &str) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "authority": AUTHORITY,
            "releaseDecision": RELEASE_DECISION,
            "validatorStatus": "BLOCKED_ENV",
            "nativePass": false,
            "sourceCommit": source_commit,
            "contractPath": CONTRACT_PATH,
            "contractDigest": contract_digest(),
            "appServerContractPath": APP_SERVER_CONTRACT_PATH,
            "appServerContractDigest": app_server_contract_digest(),
            "missingReasons": ["real_model_credentials_or_runner_missing"],
        }))
        .expect("missing OpenInterpreter report serializes")
    );
}

fn print_help() {
    println!(
        "hartevo-openinterpreter-native-acceptance\n\n\
         Usage:\n  \
         hartevo-openinterpreter-native-acceptance validate-contract\n  \
         hartevo-openinterpreter-native-acceptance verify <capture.json>\n  \
         hartevo-openinterpreter-native-acceptance capture-validate-contract\n  \
         hartevo-openinterpreter-native-acceptance capture-verify <capture.json>\n\n\
         With no input, missing credentials/runner are BLOCKED_ENV and exit non-zero.\n\
         Fixture and simulator captures never become native PASS."
    );
}

#[cfg(test)]
mod tests {
    use super::{CommandOutcome, run};

    #[test]
    fn contract_command_path_is_executable() {
        assert_eq!(
            run(&["validate-contract".into()]).unwrap(),
            CommandOutcome::Success
        );
    }

    #[test]
    fn missing_real_runner_is_blocked_nonzero() {
        assert_eq!(run(&[]).unwrap(), CommandOutcome::BlockedEnv);
    }
}
