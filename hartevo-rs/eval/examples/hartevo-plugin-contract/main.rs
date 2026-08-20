mod digest;
mod model;
mod verifier;

use std::env;

use anyhow::{Result, bail};
use serde_json::json;

use crate::verifier::{
    AUTHORITY, FIXTURE_PATH, MANIFEST_PATH, NOT_EVALUATED, REAL_PROVIDER_REASON, REGISTRY_PATH,
    RELEASE_DECISION, VALIDATION_SCHEMA_VERSION, validate_contracts,
};

const MANIFEST_BYTES: &[u8] = include_bytes!("../../../../contracts/plugins/manifest.v1.json");
const REGISTRY_BYTES: &[u8] = include_bytes!("../../../../contracts/plugins/registry.v1.json");
const FIXTURE_BYTES: &[u8] = include_bytes!("../../../../contracts/plugins/fixture.v1.json");

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "PLUGIN_READINESS_NOT_EVALUATED: {REAL_PROVIDER_REASON}; no real provider is registered"
            );
            std::process::exit(3);
        }
        Err(error) => {
            let failure = json!({
                "schemaVersion": VALIDATION_SCHEMA_VERSION,
                "authority": AUTHORITY,
                "validatorStatus": "FAIL",
                "readinessStatus": NOT_EVALUATED,
                "reasonCode": "PLUGIN_CONTRACT_VALIDATION_FAILED",
                "nativeCalls": 0,
                "providerExecution": false,
                "capabilityEvaluated": false,
                "releaseDecision": RELEASE_DECISION,
                "writesPerformed": false,
            });
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&failure)
                    .expect("static plugin validation failure serializes")
            );
            eprintln!("Plugin contract validation error: {error:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool> {
    match env::args().nth(1).as_deref() {
        None | Some("validate" | "validate-contracts") => {
            let report = validate_contracts(MANIFEST_BYTES, REGISTRY_BYTES, FIXTURE_BYTES)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(report.readiness_status == "READY")
        }
        Some("--help" | "-h") => {
            print_help();
            Ok(true)
        }
        Some(other) => bail!("unsupported command {other}; use validate or --help"),
    }
}

fn print_help() {
    println!("Usage: cargo run -p hartevo-eval --example hartevo-plugin-contract -- validate");
    println!(
        "Validates the Everything-is-a-Plugin manifest, empty registry and fixture lifecycle."
    );
    println!(
        "Contracts are checked only; catalog entries, empty registrations and fixture mounts never count as capability."
    );
    println!("Manifest: {MANIFEST_PATH}");
    println!("Registry: {REGISTRY_PATH}");
    println!("Fixture: {FIXTURE_PATH}");
}
