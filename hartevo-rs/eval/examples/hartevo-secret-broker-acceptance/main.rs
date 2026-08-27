mod digest;
mod model;
mod verifier;

use std::env;

use anyhow::{Result, bail};
use serde_json::json;

use crate::verifier::{
    AUTHORITY, CONTRACT_PATH, RELEASE_DECISION, REPORT_SCHEMA_VERSION, ValidatorStatus,
    blocked_environment_report, contract_digest, current_source_commit, read_acceptance,
    validate_acceptance, validate_contract,
};

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            let failure = json!({
                "schemaVersion": REPORT_SCHEMA_VERSION,
                "authority": AUTHORITY,
                "releaseDecision": RELEASE_DECISION,
                "validatorStatus": "FAIL",
                "nativePass": false,
                "contractPath": CONTRACT_PATH,
                "contractDigest": contract_digest(),
                "error": error.to_string(),
            });
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&failure)
                    .expect("Secret Broker validator failure must serialize")
            );
            2
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn run() -> Result<i32> {
    validate_contract()?;
    match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => {
            let source_commit = current_source_commit()?;
            let report = blocked_environment_report(source_commit);
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(3)
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
            Ok(0)
        }
        [command, path] if command == "verify" => {
            let source_commit = current_source_commit()?;
            let acceptance = read_acceptance(path)?;
            let report = validate_acceptance(&acceptance, &source_commit)?;
            let code = if report.validator_status == ValidatorStatus::NativePass {
                0
            } else {
                3
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(code)
        }
        [command] if command == "--help" || command == "-h" => {
            print_help();
            Ok(0)
        }
        _ => {
            bail!("unsupported command; use --help, validate-contract, or verify <acceptance.json>")
        }
    }
}

fn print_help() {
    println!(
        "Secret Broker Native Acceptance\n\n\
         Usage:\n  \
         hartevo-secret-broker-acceptance validate-contract\n  \
         hartevo-secret-broker-acceptance verify <acceptance.json>\n\n\
         With no input, the verifier emits typed BLOCKED_ENV and exits non-zero because no OS\
         keyring or real provider output is mounted. Fixture evidence is NOT_EVALUATED and\
         cannot become native PASS."
    );
}

#[cfg(test)]
mod tests {
    use crate::verifier::validate_contract;

    #[test]
    fn contract_command_is_executable() {
        validate_contract().expect("acceptance contract command");
    }
}
