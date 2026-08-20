mod digest;
mod model;
mod verifier;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::verifier::{
    DATASET_PATH, EXECUTION_MODE, REGISTRY_PATH, RELEASE_DECISION, VALIDATION_SCHEMA_VERSION,
    validate_contracts,
};

fn main() {
    if let Err(error) = run() {
        let failure = json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "executionMode": EXECUTION_MODE,
            "nativeReceiptCount": 0,
            "releaseDecision": RELEASE_DECISION,
            "productionEvaluation": RELEASE_DECISION,
            "validatorStatus": "FAIL",
            "writesPerformed": false,
            "errorCode": "GM01_DATASET_CONTRACT_VALIDATION_FAILED",
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&failure)
                .expect("static GM-01 validation failure must serialize")
        );
        eprintln!("GM-01 dataset validation error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let command = env::args().nth(1);
    match command.as_deref() {
        None | Some("validate") => validate(),
        Some("--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some(other) => bail!("unsupported command {other}; use validate or --help"),
    }
}

fn validate() -> Result<()> {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dataset_bytes = read_contract(&repository_root, DATASET_PATH, "GM-01 dataset")?;
    let registry_bytes = read_contract(&repository_root, REGISTRY_PATH, "dataset registry")?;
    let report = validate_contracts(&dataset_bytes, &registry_bytes)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn read_contract(repository_root: &Path, relative_path: &str, label: &str) -> Result<Vec<u8>> {
    let path = repository_root.join(relative_path);
    fs::read(&path).with_context(|| format!("read {label} at {}", path.display()))
}

fn print_help() {
    println!(
        "Usage: cargo run -p hartevo-eval --example hartevo-gm01-dataset-contract -- validate"
    );
    println!("Validates the synthetic DE VM-07 dataset and its exact registry binding.");
    println!(
        "The report is always SIMULATOR/REPLAY_ONLY with nativeReceiptCount=0 and Release NOT_EVALUATED."
    );
}
