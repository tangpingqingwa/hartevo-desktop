mod digest;
mod model;
mod signature;
mod verifier;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use crate::digest::parse_strict_json;
use crate::model::{ProviderRegistry, ResultEnvelope};
use crate::verifier::{
    FederationResultConsumer, RELEASE_DECISION, ResultVerifier, VALIDATION_SCHEMA_VERSION,
    VerificationContext, VerificationStatus, validate_envelope_shape, validate_provider_registry,
};

const ENVELOPE_SCHEMA_PATH: &str = "contracts/federation/result-envelope.v1.schema.json";
const PROVIDER_SCHEMA_PATH: &str = "contracts/federation/provider-registry.v1.schema.json";
const PROVIDER_REGISTRY_PATH: &str = "contracts/federation/provider-registry.v1.json";
const FIXTURE_PATH: &str =
    "hartevo-rs/eval/examples/hartevo-federation-result/fixtures/not-evaluated-envelope.v1.json";

fn main() {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": VALIDATION_SCHEMA_VERSION,
                    "releaseDecision": RELEASE_DECISION,
                    "validatorStatus": "FAIL",
                    "verificationStatus": "REJECTED",
                    "adopted": false,
                    "writesPerformed": false,
                    "errorCode": "FEDERATION_RESULT_CONTRACT_VALIDATION_FAILED",
                    "error": error.to_string(),
                }))
                .expect("static Federation failure report must serialize")
            );
            std::process::exit(2);
        }
    }
}

fn run() -> Result<i32> {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let command = env::args().nth(1);
    match command.as_deref() {
        None | Some("validate-contracts") => {
            let registry = load_contracts(&repository_root)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": VALIDATION_SCHEMA_VERSION,
                    "releaseDecision": RELEASE_DECISION,
                    "validatorStatus": "CONTRACTS_VALIDATED",
                    "providerCount": registry.providers.len(),
                    "nativeWorkerVerifierAvailable": registry.native_worker_verifier_available,
                    "writesPerformed": false,
                }))?
            );
            Ok(0)
        }
        Some("verify-fixture") => verify_fixture(&repository_root),
        Some("--help" | "-h") => {
            print_help();
            Ok(0)
        }
        Some(other) => {
            bail!("unsupported command {other}; use validate-contracts or verify-fixture")
        }
    }
}

fn load_contracts(repository_root: &Path) -> Result<ProviderRegistry> {
    let envelope_schema = read_contract(
        repository_root,
        ENVELOPE_SCHEMA_PATH,
        "result envelope schema",
    )?;
    let provider_schema = read_contract(
        repository_root,
        PROVIDER_SCHEMA_PATH,
        "provider registry schema",
    )?;
    let registry_bytes =
        read_contract(repository_root, PROVIDER_REGISTRY_PATH, "provider registry")?;
    validate_schema_contract(
        &envelope_schema,
        "result envelope schema",
        "hartevo-federation-result-envelope/v1",
    )?;
    validate_schema_contract(
        &provider_schema,
        "provider registry schema",
        "hartevo-federation-provider-registry/v1",
    )?;
    let registry = parse_strict_json::<ProviderRegistry>(&registry_bytes)
        .context("provider registry is not strict typed JSON")?;
    validate_provider_registry(&registry).context("provider registry is invalid")?;
    Ok(registry)
}

fn verify_fixture(repository_root: &Path) -> Result<i32> {
    let registry = load_contracts(repository_root)?;
    let fixture_bytes = read_contract(repository_root, FIXTURE_PATH, "Federation result fixture")?;
    let fixture_value = parse_strict_json::<Value>(&fixture_bytes)
        .context("Federation result fixture is not strict JSON")?;
    ensure!(
        fixture_value.get("signature").is_some_and(Value::is_null),
        "fixture must keep signature missing so it cannot PASS"
    );
    ensure!(
        fixture_value
            .get("workerEvidence")
            .is_some_and(Value::is_null),
        "fixture must keep real worker evidence missing"
    );
    let envelope = parse_strict_json::<ResultEnvelope>(&fixture_bytes)
        .context("Federation result fixture is not strict typed JSON")?;
    validate_envelope_shape(&envelope).context("Federation result fixture shape is invalid")?;
    let current_commit =
        read_current_commit(repository_root).unwrap_or_else(|_| envelope.current_commit.clone());
    let worker_verifier_available = registry.native_worker_verifier_available;
    let mut verifier = ResultVerifier::new(VerificationContext::new(
        envelope.origin.project_id.clone(),
        envelope.origin.mission_id.clone(),
        current_commit,
        registry,
        worker_verifier_available,
    ));
    let decision = verifier.verify(&envelope);
    let adopted = FederationResultConsumer::adopt(&envelope, &decision).ok();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "releaseDecision": RELEASE_DECISION,
            "validatorStatus": "CONTRACTS_VALIDATED",
            "verificationStatus": decision.status().as_str(),
            "verificationReason": decision.reason().map(verifier::VerificationReason::as_str),
            "envelopeId": envelope.envelope_id,
            "adopted": adopted.is_some(),
            "writesPerformed": false,
        }))?
    );
    Ok(if decision.status() == VerificationStatus::Verified {
        0
    } else {
        2
    })
}

fn validate_schema_contract(bytes: &[u8], label: &str, schema_version: &str) -> Result<()> {
    let value =
        parse_strict_json::<Value>(bytes).with_context(|| format!("{label} is not JSON"))?;
    let object = value
        .as_object()
        .context("schema contract must be an object")?;
    ensure!(
        object.get("additionalProperties") == Some(&Value::Bool(false)),
        "{label} must deny unknown fields"
    );
    ensure!(
        object
            .get("properties")
            .and_then(Value::as_object)
            .is_some(),
        "{label} must declare properties"
    );
    let const_version = object
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("schemaVersion"))
        .and_then(Value::as_object)
        .and_then(|schema| schema.get("const"))
        .and_then(Value::as_str);
    ensure!(
        const_version == Some(schema_version),
        "{label} schema version mismatch"
    );
    Ok(())
}

fn read_contract(repository_root: &Path, relative_path: &str, label: &str) -> Result<Vec<u8>> {
    fs::read(repository_root.join(relative_path)).with_context(|| format!("reading {label}"))
}

fn read_current_commit(repository_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-C",
            repository_root
                .to_str()
                .context("repository path is not UTF-8")?,
            "rev-parse",
            "HEAD",
        ])
        .output()
        .context("reading current commit")?;
    ensure!(output.status.success(), "git rev-parse HEAD failed");
    let commit = String::from_utf8(output.stdout).context("git commit is not UTF-8")?;
    let commit = commit.trim().to_owned();
    ensure!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid current commit"
    );
    Ok(commit)
}

fn print_help() {
    println!(
        "Usage: cargo run -p hartevo-eval --example hartevo-federation-result -- [validate-contracts | verify-fixture]"
    );
    println!(
        "verify-fixture intentionally exits 2 with NOT_EVALUATED because no signed result or real worker evidence is present."
    );
}
