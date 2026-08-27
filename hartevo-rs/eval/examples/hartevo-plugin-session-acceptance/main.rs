mod capture;
mod digest;
mod model;
mod verifier;

use std::env;

use anyhow::{Result, bail};
use serde_json::json;

use crate::capture::{
    AUTHORITY as CAPTURE_AUTHORITY, CONTRACT_PATH as CAPTURE_CONTRACT_PATH,
    RELEASE_DECISION as CAPTURE_RELEASE_DECISION, REPORT_SCHEMA_VERSION as CAPTURE_REPORT_SCHEMA,
    contract_digest as capture_contract_digest, read_bundle, validate_bundle,
    validate_contract as validate_capture_contract,
};
use crate::verifier::{
    AUTHORITY, CONTRACT_PATH, RELEASE_DECISION, REPORT_SCHEMA_VERSION, contract_digest,
    current_source_commit, read_session, validate_contract, validate_session,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutcome {
    Success,
    NotEvaluated,
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(CommandOutcome::Success) => {}
        Ok(CommandOutcome::NotEvaluated) => std::process::exit(3),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": CAPTURE_REPORT_SCHEMA,
                    "authority": CAPTURE_AUTHORITY,
                    "releaseDecision": CAPTURE_RELEASE_DECISION,
                    "validatorStatus": "FAIL",
                    "nativePass": false,
                    "contractPath": CAPTURE_CONTRACT_PATH,
                    "contractDigest": capture_contract_digest(),
                    "error": error.to_string(),
                }))
                .expect("acceptance failure report serializes")
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
            print_capture_not_evaluated(&current_source_commit()?);
            Ok(CommandOutcome::NotEvaluated)
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
                    "contractValidated": true,
                }))?
            );
            Ok(CommandOutcome::Success)
        }
        [command] if command == "capture-validate-contract" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": CAPTURE_REPORT_SCHEMA,
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
            let report = validate_session(&session, &source_commit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.native_pass {
                CommandOutcome::Success
            } else {
                CommandOutcome::NotEvaluated
            })
        }
        [command, path] if command == "capture-verify" => {
            let source_commit = current_source_commit()?;
            let bundle = read_bundle(path)?;
            let report = validate_bundle(&bundle, &source_commit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.native_pass {
                CommandOutcome::Success
            } else {
                CommandOutcome::NotEvaluated
            })
        }
        [command] if command == "--help" || command == "-h" => {
            print_help();
            Ok(CommandOutcome::Success)
        }
        _ => bail!(
            "unsupported command; use --help, validate-contract, verify <path>, \
             capture-validate-contract, or capture-verify <path>"
        ),
    }
}

fn print_help() {
    println!(
        "Plugin Session Native Acceptance\n\n\
         Usage:\n  \
         hartevo-plugin-session-acceptance validate-contract\n  \
         hartevo-plugin-session-acceptance verify <acceptance.json>\n  \
         hartevo-plugin-session-acceptance capture-validate-contract\n  \
         hartevo-plugin-session-acceptance capture-verify <capture.json>\n\n\
         With no input, capture verification emits typed NOT_EVALUATED and exits non-zero because no real capture output is mounted."
    );
}

fn print_capture_not_evaluated(source_commit: &str) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": CAPTURE_REPORT_SCHEMA,
            "authority": CAPTURE_AUTHORITY,
            "releaseDecision": CAPTURE_RELEASE_DECISION,
            "validatorStatus": "NOT_EVALUATED",
            "nativePass": false,
            "sourceCommit": source_commit,
            "contractPath": CAPTURE_CONTRACT_PATH,
            "contractDigest": capture_contract_digest(),
            "missingReasons": ["real_capture_output_missing"],
        }))
        .expect("capture missing report serializes")
    );
}

#[cfg(test)]
mod tests {
    use crate::capture::validate_contract as validate_capture_contract;
    use crate::verifier::validate_contract;

    #[test]
    fn contract_command_path_is_executable() {
        validate_contract().expect("contract command validation");
        validate_capture_contract().expect("capture contract command validation");
    }
}
