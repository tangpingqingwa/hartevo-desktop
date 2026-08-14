mod digest;
mod model;
mod signature;
mod verifier;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;

use crate::model::EvidenceStatus;
use crate::verifier::{
    CONSUMER, CONTRACT_PATH, CONTRACT_SCHEMA_PATH, DistributionVerifierProvider, GenerationInput,
    PROVIDER, RELEASE_DECISION, ReleaseEvidencePlugin, VALIDATION_SCHEMA_VERSION,
    VerificationInput,
};

fn main() {
    if let Err(error) = run() {
        let failure = json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "provider": PROVIDER,
            "consumer": CONSUMER,
            "status": "CODE_FAILURE",
            "releaseDecision": RELEASE_DECISION,
            "release": false,
            "deployment": false,
            "evidenceAccepted": false,
            "promotionEligible": false,
            "errorCode": "DISTRIBUTION_RELEASE_EVIDENCE_CONTRACT_FAILED",
            "error": error.to_string()
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&failure)
                .expect("static distribution evidence failure must serialize")
        );
        eprintln!("Distribution release evidence error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.is_empty()
        || arguments
            .first()
            .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        print_help();
        return Ok(());
    }
    let command = arguments[0]
        .to_str()
        .context("command is not valid UTF-8")?;
    let options = parse_options(&arguments[1..])?;
    match command {
        "validate-contracts" => validate_contract_command()?,
        "generate" => generate_command(&options)?,
        "verify" => verify_command(&options)?,
        other => bail!(
            "unsupported command {other}; use validate-contracts, generate, verify, or --help"
        ),
    }
    Ok(())
}

fn validate_contract_command() -> Result<()> {
    verifier::validate_contracts()?;
    let (contract_digest, schema_digest) = verifier::contract_digests();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": VALIDATION_SCHEMA_VERSION,
            "provider": PROVIDER,
            "consumer": CONSUMER,
            "releaseDecision": RELEASE_DECISION,
            "release": false,
            "deployment": false,
            "contractPath": CONTRACT_PATH,
            "contractSchemaPath": CONTRACT_SCHEMA_PATH,
            "contractDigest": contract_digest,
            "contractSchemaDigest": schema_digest,
            "contractValidated": true
        }))?
    );
    Ok(())
}

fn generate_command(options: &Options) -> Result<()> {
    let input = GenerationInput {
        version: required_string(options.version.as_ref(), "--version")?,
        platform: required_string(options.platform.as_ref(), "--platform")?,
        target_triple: required_string(options.target_triple.as_ref(), "--target-triple")?,
        source_commit: required_string(options.source_commit.as_ref(), "--source-commit")?,
        artifact_bytes: read_required(options.artifact.as_ref(), "artifact")?,
        sbom_bytes: read_required(options.sbom.as_ref(), "SBOM")?,
        attestation_bytes: read_required(options.attestation.as_ref(), "attestation")?,
        advisory_report_bytes: read_required(options.advisory_report.as_ref(), "advisory report")?,
        toolchain_version: required_string(
            options.toolchain_version.as_ref(),
            "--toolchain-version",
        )?,
        toolchain_digest: required_string(options.toolchain_digest.as_ref(), "--toolchain-digest")?,
        build_manifest_digest: required_string(
            options.build_manifest_digest.as_ref(),
            "--build-manifest-digest",
        )?,
        issued_at: required_string(options.issued_at.as_ref(), "--issued-at")?,
        expires_at: required_string(options.expires_at.as_ref(), "--expires-at")?,
    };
    let evidence = DistributionVerifierProvider.generate(&input)?;
    write_json(&evidence, options.output.as_deref())
}

fn verify_command(options: &Options) -> Result<()> {
    let signature_hex = options
        .signature
        .as_deref()
        .map(|path| read_required_path(path, "detached signature"))
        .transpose()?
        .map(|bytes| String::from_utf8(bytes).context("detached signature is not UTF-8"))
        .transpose()?;
    let registry_bytes = options
        .key_registry
        .as_deref()
        .map(|path| read_required_path(path, "verification key registry"))
        .transpose()?;
    let report = DistributionVerifierProvider.verify(&VerificationInput {
        evidence_bytes: read_required(options.evidence.as_ref(), "release evidence")?,
        artifact_bytes: read_required(options.artifact.as_ref(), "artifact")?,
        sbom_bytes: options
            .sbom
            .as_deref()
            .map(|path| read_required_path(path, "SBOM"))
            .transpose()?,
        attestation_bytes: options
            .attestation
            .as_deref()
            .map(|path| read_required_path(path, "attestation"))
            .transpose()?,
        signature_hex: signature_hex.map(|value| value.trim().to_owned()),
        key_registry_bytes: registry_bytes,
        as_of: required_string(options.as_of.as_ref(), "--as-of")?,
        expected_version: options.expected_version.clone(),
        expected_platform: options.expected_platform.clone(),
        expected_target_triple: options.expected_target_triple.clone(),
        expected_source_commit: options.expected_source_commit.clone(),
    })?;
    let status = report.status;
    write_json(&report, options.output.as_deref())?;
    if matches!(
        status,
        EvidenceStatus::CodeFailure | EvidenceStatus::BlockedEnv | EvidenceStatus::NotImplemented
    ) {
        std::process::exit(2);
    }
    Ok(())
}

#[derive(Default)]
struct Options {
    version: Option<String>,
    platform: Option<String>,
    target_triple: Option<String>,
    source_commit: Option<String>,
    artifact: Option<PathBuf>,
    sbom: Option<PathBuf>,
    attestation: Option<PathBuf>,
    advisory_report: Option<PathBuf>,
    toolchain_version: Option<String>,
    toolchain_digest: Option<String>,
    build_manifest_digest: Option<String>,
    issued_at: Option<String>,
    expires_at: Option<String>,
    evidence: Option<PathBuf>,
    signature: Option<PathBuf>,
    key_registry: Option<PathBuf>,
    as_of: Option<String>,
    expected_version: Option<String>,
    expected_platform: Option<String>,
    expected_target_triple: Option<String>,
    expected_source_commit: Option<String>,
    output: Option<PathBuf>,
}

fn parse_options(arguments: &[OsString]) -> Result<Options> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .with_context(|| format!("argument #{} is not valid UTF-8", index + 1))?;
        ensure!(
            index + 1 < arguments.len(),
            "option {flag} requires a value"
        );
        let value = arguments[index + 1]
            .to_str()
            .with_context(|| format!("value for {flag} is not valid UTF-8"))?;
        match flag {
            "--version" => options.version = Some(value.to_owned()),
            "--platform" => options.platform = Some(value.to_owned()),
            "--target-triple" => options.target_triple = Some(value.to_owned()),
            "--source-commit" => options.source_commit = Some(value.to_owned()),
            "--artifact" => options.artifact = Some(PathBuf::from(value)),
            "--sbom" => options.sbom = Some(PathBuf::from(value)),
            "--attestation" => options.attestation = Some(PathBuf::from(value)),
            "--advisory-report" => options.advisory_report = Some(PathBuf::from(value)),
            "--toolchain-version" => options.toolchain_version = Some(value.to_owned()),
            "--toolchain-digest" => options.toolchain_digest = Some(value.to_owned()),
            "--build-manifest-digest" => options.build_manifest_digest = Some(value.to_owned()),
            "--issued-at" => options.issued_at = Some(value.to_owned()),
            "--expires-at" => options.expires_at = Some(value.to_owned()),
            "--evidence" => options.evidence = Some(PathBuf::from(value)),
            "--signature" => options.signature = Some(PathBuf::from(value)),
            "--key-registry" => options.key_registry = Some(PathBuf::from(value)),
            "--as-of" => options.as_of = Some(value.to_owned()),
            "--expected-version" => options.expected_version = Some(value.to_owned()),
            "--expected-platform" => options.expected_platform = Some(value.to_owned()),
            "--expected-target-triple" => options.expected_target_triple = Some(value.to_owned()),
            "--expected-source-commit" => options.expected_source_commit = Some(value.to_owned()),
            "--output" => options.output = Some(PathBuf::from(value)),
            other => bail!("unknown option {other}"),
        }
        index += 2;
    }
    Ok(options)
}

fn required_string(value: Option<&String>, flag: &str) -> Result<String> {
    value
        .cloned()
        .with_context(|| format!("{flag} is required"))
}

fn read_required(path: Option<&PathBuf>, label: &str) -> Result<Vec<u8>> {
    let path = path.with_context(|| format!("{label} input is required"))?;
    read_required_path(path, label)
}

fn read_required_path(path: &Path, label: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read {label} at {}", path.display()))
}

fn write_json<T: serde::Serialize>(value: &T, output: Option<&Path>) -> Result<()> {
    let serialized = serde_json::to_string_pretty(value)? + "\n";
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }
        fs::write(output, serialized)
            .with_context(|| format!("write output at {}", output.display()))?;
    } else {
        print!("{serialized}");
    }
    Ok(())
}

fn print_help() {
    println!(
        "Usage:\n  cargo run -p hartevo-eval --example hartevo-distribution-adoption -- validate-contracts\n  cargo run -p hartevo-eval --example hartevo-distribution-adoption -- generate --version VERSION --platform PLATFORM --target-triple TARGET --source-commit SHA --artifact PATH --sbom PATH --attestation PATH --advisory-report PATH --toolchain-version VERSION --toolchain-digest SHA256 --build-manifest-digest SHA256 --issued-at RFC3339 --expires-at RFC3339 [--output PATH]\n  cargo run -p hartevo-eval --example hartevo-distribution-adoption -- verify --evidence PATH --artifact PATH --sbom PATH --attestation PATH --as-of RFC3339 [--signature PATH] [--key-registry PATH] [--expected-version VERSION] [--expected-platform PLATFORM] [--expected-target-triple TARGET] [--expected-source-commit SHA] [--output PATH]"
    );
    println!(
        "The provider emits unsigned evidence inventories and verifies externally detached Ed25519 signatures. The consumer always keeps release and deployment false."
    );
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn parser_keeps_verification_inputs_optional_for_blocked_env_receipts() {
        let options = parse_options(&[
            "--evidence".into(),
            "evidence.json".into(),
            "--artifact".into(),
            "artifact.bin".into(),
            "--as-of".into(),
            "2026-08-14T00:00:00Z".into(),
        ])
        .expect("options");
        assert!(options.signature.is_none());
        assert!(options.key_registry.is_none());
    }
}
