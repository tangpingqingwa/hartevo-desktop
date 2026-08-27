mod digest;
mod model;
mod verifier;

use std::env;

use anyhow::{Result, bail};
use serde_json::json;

use crate::verifier::{
    AUTHORITY, CONTRACT_PATH, RELEASE_DECISION, REPORT_SCHEMA_VERSION, ValidationReport,
    ValidatorStatus, contract_digest, current_source_commit, read_session, validate_contract,
    validate_session,
};

fn main() {
    if let Err(error) = run() {
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
            .expect("acceptance failure report serializes")
        );
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    validate_contract()?;
    match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => print_not_evaluated(&current_source_commit()?),
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
        }
        [command, path] if command == "verify" => {
            let source_commit = current_source_commit()?;
            let session = read_session(path)?;
            let report = validate_session(&session, &source_commit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        [command] if command == "--help" || command == "-h" => print_help(),
        _ => bail!("unsupported command; use --help, validate-contract, or verify <path>"),
    }
    Ok(())
}

fn print_not_evaluated(source_commit: &str) {
    let report = ValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status: ValidatorStatus::NotEvaluated,
        native_pass: false,
        source_commit: source_commit.into(),
        contract_digest: contract_digest(),
        project_id: String::new(),
        mission_id: String::new(),
        revision: 0,
        evidence_root: String::new(),
        provider_mode: "missing".into(),
        missing_reasons: vec!["real_provider_output_missing".into()],
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("not evaluated report serializes")
    );
}

fn print_help() {
    println!(
        "Plugin Session Native Acceptance\n\n\
         Usage:\n  \
         hartevo-plugin-session-acceptance validate-contract\n  \
         hartevo-plugin-session-acceptance verify <acceptance.json>\n\n\
         With no input, the verifier emits typed NOT_EVALUATED because no real provider output is mounted."
    );
}

#[cfg(test)]
mod tests {
    use crate::verifier::validate_contract;

    #[test]
    fn contract_command_path_is_executable() {
        validate_contract().expect("contract command validation");
    }
}
