//! Distribution-contract crypto helpers and release-gate validation.
//!
//! This module deliberately owns only release plumbing. It does not decide
//! whether a Mission is complete; the existing catalog/evidence contracts keep
//! that authority and continue to report `passed: false` for the current
//! product baseline.

use std::fs;
use std::io::Write;
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

const GATE_SCHEMA: &str = "hartevo-distribution-gate/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DistributionGate {
    schema_version: String,
    issue: String,
    release_commit: String,
    source_dirty: bool,
    ci_status: String,
    release_decision: String,
    release_ready: bool,
    artifact_references: ArtifactReferences,
    checks: DistributionChecks,
    native_evidence: NativeEvidence,
    blocked_env: Vec<String>,
    failures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactReferences {
    manifest: String,
    sbom: String,
    update_metadata: String,
    telemetry: String,
    restore_drill: String,
    release_evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DistributionChecks {
    manifest: String,
    sbom: String,
    update_metadata: String,
    telemetry: String,
    restore_drill: String,
    release_evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeEvidence {
    status: String,
    required_for_release: bool,
    product_completion_counted: bool,
}

pub fn generate_keypair(
    private_path: impl AsRef<Path>,
    public_path: impl AsRef<Path>,
) -> Result<()> {
    let private_path = private_path.as_ref();
    let public_path = public_path.as_ref();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("generate Ed25519 key"))?;
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("load generated Ed25519 key"))?;
    write_new_private(private_path, pkcs8.as_ref())?;
    write_new(public_path, keypair.public_key().as_ref())
}

pub fn sign_file(
    private_path: impl AsRef<Path>,
    input_path: impl AsRef<Path>,
    signature_path: impl AsRef<Path>,
) -> Result<()> {
    let private = fs::read(private_path.as_ref())
        .with_context(|| format!("read private key {}", private_path.as_ref().display()))?;
    let keypair = Ed25519KeyPair::from_pkcs8(&private)
        .map_err(|_| anyhow::anyhow!("load Ed25519 PKCS#8 key"))?;
    let payload = fs::read(input_path.as_ref())
        .with_context(|| format!("read signing input {}", input_path.as_ref().display()))?;
    write_new(signature_path.as_ref(), keypair.sign(&payload).as_ref())
}

pub fn export_public_key(
    private_path: impl AsRef<Path>,
    public_path: impl AsRef<Path>,
) -> Result<()> {
    let private = fs::read(private_path.as_ref())
        .with_context(|| format!("read private key {}", private_path.as_ref().display()))?;
    let keypair = Ed25519KeyPair::from_pkcs8(&private)
        .map_err(|_| anyhow::anyhow!("load Ed25519 PKCS#8 key"))?;
    write_new(public_path.as_ref(), keypair.public_key().as_ref())
}

pub fn verify_file(
    public_path: impl AsRef<Path>,
    input_path: impl AsRef<Path>,
    signature_path: impl AsRef<Path>,
) -> Result<()> {
    let public_key = fs::read(public_path.as_ref())
        .with_context(|| format!("read public key {}", public_path.as_ref().display()))?;
    ensure!(
        public_key.len() == 32,
        "Ed25519 public key must contain exactly 32 raw bytes"
    );
    let payload = fs::read(input_path.as_ref())
        .with_context(|| format!("read verification input {}", input_path.as_ref().display()))?;
    let signature = fs::read(signature_path.as_ref())
        .with_context(|| format!("read signature {}", signature_path.as_ref().display()))?;
    ensure!(
        signature.len() == 64,
        "Ed25519 signature must contain exactly 64 raw bytes"
    );
    UnparsedPublicKey::new(&signature::ED25519, &public_key)
        .verify(&payload, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 signature verification failed"))
}

pub fn validate_gate(path: impl AsRef<Path>, expected_commit: &str) -> Result<()> {
    ensure!(
        expected_commit.len() == 40
            && expected_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "expected distribution commit must be a 40-character lowercase Git object id"
    );
    let bytes = fs::read(path.as_ref())
        .with_context(|| format!("read distribution gate {}", path.as_ref().display()))?;
    let gate: DistributionGate =
        serde_json::from_slice(&bytes).context("parse distribution gate")?;
    ensure!(
        gate.schema_version == GATE_SCHEMA,
        "unexpected distribution gate schema"
    );
    ensure!(
        gate.issue == "DIST-01",
        "distribution gate is not for DIST-01"
    );
    ensure!(
        gate.release_commit == expected_commit,
        "distribution gate commit mismatch"
    );
    ensure!(
        gate.release_decision == "NOT_EVALUATED",
        "distribution gate may not evaluate release"
    );
    ensure!(
        matches!(
            gate.ci_status.as_str(),
            "CI_EXECUTED" | "CI_NOT_EXECUTED" | "LOCAL_SCOPED"
        ),
        "distribution gate has an invalid CI status"
    );
    ensure!(
        !gate.release_ready,
        "DIST-01 gate must keep releaseReady=false until native evidence exists"
    );
    ensure!(
        gate.native_evidence.status == "NOT_PROVEN",
        "native evidence must remain NOT_PROVEN"
    );
    ensure!(
        gate.native_evidence.required_for_release,
        "native evidence must be required for release"
    );
    ensure!(
        !gate.native_evidence.product_completion_counted,
        "simulator or blocked distribution evidence cannot count as product completion"
    );
    ensure!(
        gate.checks.release_evidence != "PASS",
        "distribution gate cannot turn existing Release Evidence into a pass"
    );
    for reference in [
        &gate.artifact_references.manifest,
        &gate.artifact_references.sbom,
        &gate.artifact_references.update_metadata,
        &gate.artifact_references.telemetry,
        &gate.artifact_references.restore_drill,
        &gate.artifact_references.release_evidence,
    ] {
        ensure!(
            reference.starts_with("target/")
                && !Path::new(reference)
                    .components()
                    .any(|component| component == Component::ParentDir),
            "distribution artifact reference must be a safe repository-relative target path"
        );
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    write_new(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restrict private key permissions {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ed25519_file_round_trip() {
        let directory = tempdir().expect("temp directory");
        let private = directory.path().join("private.pk8");
        let public = directory.path().join("public.raw");
        let payload = directory.path().join("payload");
        let signature = directory.path().join("signature");
        generate_keypair(&private, &public).expect("generate keypair");
        fs::write(&payload, b"distribution payload").expect("payload");
        sign_file(&private, &payload, &signature).expect("sign");
        verify_file(&public, &payload, &signature).expect("verify");
    }
}
