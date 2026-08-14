//! Strict local verification for the DIST-02 distribution bundle.
//!
//! The verifier is intentionally independent of GitHub Actions.  It binds the
//! generated documents to one source commit and toolchain, recomputes every
//! listed file digest, and keeps signing/notarization as observable hooks.  A
//! structurally valid bundle is not release approval: `releaseReady` remains
//! false and native evidence remains `NOT_PROVEN`.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::DateTime;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

const LOCAL_MANIFEST_SCHEMA: &str = "hartevo-local-build-manifest/v1";
const CYCLONEDX_SCHEMA: &str = "hartevo-sbom/v1";
const SPDX_SCHEMA: &str = "SPDX-2.3";
const CHECKSUMS_SCHEMA: &str = "hartevo-distribution-checksums/v1";
const PROVENANCE_SCHEMA: &str = "hartevo-distribution-provenance/v1";
const TELEMETRY_SCHEMA: &str = "hartevo-operational-telemetry/v2";
const VERIFICATION_SCHEMA: &str = "hartevo-distribution-verification/v1";
const FORBIDDEN_TELEMETRY_TERMS: [&str; 15] = [
    "authorization",
    "cookie",
    "credential",
    "email",
    "header",
    "password",
    "pii",
    "prompt",
    "secret",
    "stdout",
    "token",
    "transcript",
    "url",
    "user_content",
    "usercontent",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceBinding {
    commit: String,
    tree: String,
    tree_sha256: String,
    dirty: bool,
    repository: String,
    source_date_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ToolchainBinding {
    rustc: String,
    cargo: String,
    target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildCommand {
    id: String,
    argv: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildEnvironment {
    source_date_epoch: u64,
    network_policy: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildBinding {
    profile: String,
    target: String,
    reproducible: bool,
    cargo_lock_sha256: String,
    commands: Vec<BuildCommand>,
    environment: BuildEnvironment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactRecord {
    id: String,
    kind: String,
    path: String,
    sha256: String,
    byte_count: u64,
    evidence_class: String,
    source_commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DigestPointer {
    path: String,
    sha256: String,
    byte_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PathPointer {
    path: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    byte_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SbomBinding {
    cyclone_dx: DigestPointer,
    spdx: DigestPointer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HookBinding {
    status: String,
    hook: String,
    #[serde(default)]
    evidence_path: Option<String>,
    #[serde(default)]
    evidence_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SigningHooks {
    macos_signing: HookBinding,
    macos_notarization: HookBinding,
    windows_signing: HookBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeEvidence {
    status: String,
    required_for_release: bool,
    release_eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalBuildManifest {
    schema_version: String,
    manifest_id: String,
    release_decision: String,
    release_ready: bool,
    source: SourceBinding,
    toolchain: ToolchainBinding,
    build: BuildBinding,
    artifacts: Vec<ArtifactRecord>,
    sbom: SbomBinding,
    checksums: PathPointer,
    provenance: PathPointer,
    telemetry: PathPointer,
    signing_hooks: SigningHooks,
    native_evidence: NativeEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChecksumsDocument {
    schema_version: String,
    algorithm: String,
    source_commit: String,
    toolchain: ToolchainBinding,
    artifacts: Vec<ArtifactRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvenanceDocument {
    schema_version: String,
    source: SourceBinding,
    toolchain: ToolchainBinding,
    checksum_manifest: DigestPointer,
    artifacts: Vec<ArtifactRecord>,
    signing_hooks: SigningHooks,
    native_evidence: NativeEvidence,
    release_decision: String,
    release_ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: String,
    download_location: String,
    files_analyzed: bool,
    license_concluded: String,
    license_declared: String,
    copyright_text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpdxRelationship {
    spdx_element_id: String,
    relationship_type: String,
    related_spdx_element: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpdxDocument {
    spdx_version: String,
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
    relationships: Vec<SpdxRelationship>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct TelemetryPolicy {
    default_enabled: bool,
    opt_in_required: bool,
    content_allowed: bool,
    secret_allowed: bool,
    pii_allowed: bool,
    content_free: bool,
    retention_days: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelemetryAttributes {
    #[serde(default)]
    failure_class: Option<String>,
    #[serde(default)]
    items: Option<u64>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    retry_count: Option<u64>,
    #[serde(default)]
    cost_minor: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelemetryEvent {
    schema_version: String,
    event_name: String,
    event_id: String,
    occurred_at: String,
    build_commit: String,
    build_manifest_sha256: String,
    tenant_pseudonym: String,
    project_pseudonym: String,
    mission_pseudonym: String,
    run_pseudonym: String,
    checkpoint_pseudonym: String,
    effect_pseudonym: String,
    provider_id: String,
    sequence: u64,
    status: String,
    duration_ms: u64,
    attributes: TelemetryAttributes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TelemetryDocument {
    schema_version: String,
    policy: TelemetryPolicy,
    event: TelemetryEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationChecks {
    manifest: String,
    cyclonedx: String,
    spdx: String,
    checksums: String,
    provenance: String,
    telemetry: String,
    signing_hooks: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributionVerificationReceipt {
    schema_version: String,
    status: String,
    source_commit: String,
    source_dirty: bool,
    toolchain: ToolchainBinding,
    checks: VerificationChecks,
    blocked_env: Vec<String>,
    release_decision: String,
    release_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributionVerificationPaths {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub cyclonedx: PathBuf,
    pub spdx: PathBuf,
    pub checksums: PathBuf,
    pub provenance: PathBuf,
    pub telemetry: PathBuf,
    pub expected_commit: String,
}

struct LoadedDistribution {
    manifest_path: PathBuf,
    cyclonedx_path: PathBuf,
    spdx_path: PathBuf,
    checksums_path: PathBuf,
    provenance_path: PathBuf,
    telemetry_path: PathBuf,
    manifest: LocalBuildManifest,
    checksums: ChecksumsDocument,
    provenance: ProvenanceDocument,
    telemetry: TelemetryDocument,
    cyclonedx: Value,
    spdx: SpdxDocument,
}

/// Verify a local distribution bundle without requiring a workflow runner.
pub fn verify_distribution(
    paths: &DistributionVerificationPaths,
) -> Result<DistributionVerificationReceipt> {
    let expected_commit = paths.expected_commit.as_str();
    let root = paths.root.canonicalize().with_context(|| {
        format!(
            "resolve distribution verification root {}",
            paths.root.display()
        )
    })?;
    validate_commit(expected_commit)?;
    let bundle = load_distribution(&root, paths)?;
    validate_manifest(&bundle.manifest, expected_commit)?;
    validate_provenance(&bundle.provenance, expected_commit)?;
    validate_checksums(&bundle.checksums, expected_commit)?;
    validate_cross_document_bindings(&bundle.manifest, &bundle.provenance, &bundle.checksums)?;
    let manifest_digest = validate_file_bindings(&root, &bundle, expected_commit)?;
    validate_payloads(&bundle, expected_commit, &manifest_digest)?;
    let signing_status = validate_distribution_hooks(&root, &bundle)?;
    let blocked_env = blocked_reasons(&bundle.manifest, &signing_status);
    let signing_hooks_check =
        if signing_status.0 == "PASS" && signing_status.1 == "PASS" && signing_status.2 == "PASS" {
            "PASS"
        } else if signing_status.0 == "CI_NOT_EXECUTED"
            || signing_status.1 == "CI_NOT_EXECUTED"
            || signing_status.2 == "CI_NOT_EXECUTED"
        {
            "CI_NOT_EXECUTED"
        } else {
            "BLOCKED_ENV"
        };

    Ok(DistributionVerificationReceipt {
        schema_version: VERIFICATION_SCHEMA.to_string(),
        status: "VERIFIED".to_string(),
        source_commit: expected_commit.to_string(),
        source_dirty: bundle.manifest.source.dirty,
        toolchain: bundle.manifest.toolchain.clone(),
        checks: VerificationChecks {
            manifest: "PASS".to_string(),
            cyclonedx: "PASS".to_string(),
            spdx: "PASS".to_string(),
            checksums: "PASS".to_string(),
            provenance: "PASS".to_string(),
            telemetry: "PASS".to_string(),
            signing_hooks: signing_hooks_check.to_string(),
        },
        blocked_env,
        release_decision: "NOT_EVALUATED".to_string(),
        release_ready: false,
    })
}

fn load_distribution(
    root: &Path,
    paths: &DistributionVerificationPaths,
) -> Result<LoadedDistribution> {
    let manifest_path = input_path(root, &paths.manifest);
    let cyclonedx_path = input_path(root, &paths.cyclonedx);
    let spdx_path = input_path(root, &paths.spdx);
    let checksums_path = input_path(root, &paths.checksums);
    let provenance_path = input_path(root, &paths.provenance);
    let telemetry_path = input_path(root, &paths.telemetry);
    Ok(LoadedDistribution {
        manifest: read_json(&manifest_path, "local build manifest")?,
        checksums: read_json(&checksums_path, "checksum manifest")?,
        provenance: read_json(&provenance_path, "provenance document")?,
        telemetry: read_json(&telemetry_path, "telemetry document")?,
        cyclonedx: read_json_value(&cyclonedx_path, "CycloneDX SBOM")?,
        spdx: read_json(&spdx_path, "SPDX SBOM")?,
        manifest_path,
        cyclonedx_path,
        spdx_path,
        checksums_path,
        provenance_path,
        telemetry_path,
    })
}

fn validate_checksums(checksums: &ChecksumsDocument, expected_commit: &str) -> Result<()> {
    ensure!(
        checksums.schema_version == CHECKSUMS_SCHEMA,
        "checksum manifest schema mismatch"
    );
    ensure!(
        checksums.algorithm == "SHA-256",
        "checksum manifest algorithm must be SHA-256"
    );
    ensure!(
        checksums.source_commit == expected_commit,
        "checksum manifest commit mismatch"
    );
    Ok(())
}

fn validate_cross_document_bindings(
    manifest: &LocalBuildManifest,
    provenance: &ProvenanceDocument,
    checksums: &ChecksumsDocument,
) -> Result<()> {
    ensure!(
        manifest.source == provenance.source,
        "manifest and provenance source bindings differ"
    );
    ensure!(
        manifest.toolchain == provenance.toolchain,
        "manifest and provenance toolchains differ"
    );
    ensure!(
        manifest.toolchain == checksums.toolchain,
        "manifest and checksum toolchains differ"
    );
    ensure!(
        manifest.build.target == manifest.toolchain.target,
        "manifest build target differs from toolchain target"
    );
    ensure!(
        manifest.build.environment.source_date_epoch == manifest.source.source_date_epoch,
        "manifest source date epoch drifted"
    );
    ensure!(
        manifest.build.reproducible,
        "local distribution manifest must declare reproducible=true"
    );
    Ok(())
}

fn validate_file_bindings(
    root: &Path,
    bundle: &LoadedDistribution,
    expected_commit: &str,
) -> Result<DigestAndLength> {
    verify_input_pointer(
        root,
        &bundle.manifest.sbom.cyclone_dx,
        &bundle.cyclonedx_path,
        "CycloneDX pointer",
    )?;
    verify_input_pointer(
        root,
        &bundle.manifest.sbom.spdx,
        &bundle.spdx_path,
        "SPDX pointer",
    )?;
    verify_path_pointer(
        root,
        &bundle.manifest.checksums,
        &bundle.checksums_path,
        "checksums pointer",
    )?;
    verify_path_pointer(
        root,
        &bundle.manifest.provenance,
        &bundle.provenance_path,
        "provenance pointer",
    )?;
    let manifest_digest = verify_input_file(&bundle.manifest_path, "local build manifest")?;
    verify_path_pointer(
        root,
        &bundle.manifest.telemetry,
        &bundle.telemetry_path,
        "telemetry pointer",
    )?;
    let manifest_records = verify_artifacts(
        root,
        &bundle.manifest.artifacts,
        expected_commit,
        "manifest",
    )?;
    let checksum_records = verify_artifacts(
        root,
        &bundle.checksums.artifacts,
        expected_commit,
        "checksums",
    )?;
    let provenance_records = verify_artifacts(
        root,
        &bundle.provenance.artifacts,
        expected_commit,
        "provenance",
    )?;
    ensure!(
        manifest_records.is_subset(&checksum_records),
        "manifest artifacts are not covered by checksums"
    );
    ensure!(
        checksum_records == provenance_records,
        "checksum and provenance artifact sets differ"
    );
    verify_digest_pointer(
        root,
        &bundle.provenance.checksum_manifest,
        &bundle.checksums_path,
        "provenance checksum pointer",
    )?;
    Ok(manifest_digest)
}

fn validate_payloads(
    bundle: &LoadedDistribution,
    expected_commit: &str,
    manifest_digest: &DigestAndLength,
) -> Result<()> {
    validate_cyclonedx(
        &bundle.cyclonedx,
        expected_commit,
        bundle.manifest.sbom.cyclone_dx.byte_count,
    )?;
    validate_spdx(
        &bundle.spdx,
        expected_commit,
        &bundle.manifest.source,
        bundle.manifest.sbom.spdx.byte_count,
    )?;
    validate_telemetry(&bundle.telemetry, expected_commit, manifest_digest)
}

fn validate_distribution_hooks(
    root: &Path,
    bundle: &LoadedDistribution,
) -> Result<(String, String, String)> {
    let signing_status = validate_hooks(
        root,
        &bundle.manifest.signing_hooks,
        "manifest signing hooks",
    )?;
    let provenance_signing_status = validate_hooks(
        root,
        &bundle.provenance.signing_hooks,
        "provenance signing hooks",
    )?;
    ensure!(
        bundle.manifest.signing_hooks == bundle.provenance.signing_hooks,
        "manifest and provenance signing hooks differ"
    );
    ensure!(
        bundle.manifest.native_evidence == bundle.provenance.native_evidence,
        "manifest and provenance native evidence differ"
    );
    ensure!(
        signing_status == provenance_signing_status,
        "signing hook status changed between manifest and provenance"
    );
    Ok(signing_status)
}

fn blocked_reasons(
    manifest: &LocalBuildManifest,
    signing_status: &(String, String, String),
) -> Vec<String> {
    let mut blocked_env = Vec::new();
    if manifest.source.dirty {
        blocked_env.push("source:DIRTY".to_string());
    }
    for (name, status) in [
        ("macos_signing", signing_status.0.as_str()),
        ("macos_notarization", signing_status.1.as_str()),
        ("windows_signing", signing_status.2.as_str()),
    ] {
        if status != "PASS" {
            blocked_env.push(format!("{name}:{status}"));
        }
    }
    blocked_env
}

fn validate_manifest(manifest: &LocalBuildManifest, expected_commit: &str) -> Result<()> {
    ensure!(
        manifest.schema_version == LOCAL_MANIFEST_SCHEMA,
        "local build manifest schema mismatch"
    );
    ensure!(
        manifest.manifest_id == format!("commit-{expected_commit}"),
        "local build manifest commit mismatch"
    );
    ensure!(
        manifest.release_decision == "NOT_EVALUATED",
        "local build manifest may not evaluate release"
    );
    ensure!(
        !manifest.release_ready,
        "local build manifest must keep releaseReady=false"
    );
    validate_source(&manifest.source, expected_commit, "manifest source")?;
    validate_toolchain(&manifest.toolchain, "manifest toolchain")?;
    ensure!(
        !manifest.build.profile.is_empty(),
        "manifest build profile is empty"
    );
    ensure!(
        !manifest.build.commands.is_empty(),
        "manifest build commands are empty"
    );
    for command in &manifest.build.commands {
        ensure!(
            !command.id.is_empty() && !command.argv.is_empty(),
            "manifest build command is incomplete"
        );
    }
    ensure!(
        manifest.native_evidence.status == "NOT_PROVEN",
        "native evidence must remain NOT_PROVEN"
    );
    ensure!(
        manifest.native_evidence.required_for_release,
        "native evidence must be required for release"
    );
    ensure!(
        !manifest.native_evidence.release_eligible,
        "native evidence cannot make the local bundle release eligible"
    );
    ensure!(
        manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "SBOM"),
        "manifest must list an SBOM artifact"
    );
    Ok(())
}

fn validate_provenance(provenance: &ProvenanceDocument, expected_commit: &str) -> Result<()> {
    ensure!(
        provenance.schema_version == PROVENANCE_SCHEMA,
        "provenance schema mismatch"
    );
    ensure!(
        provenance.release_decision == "NOT_EVALUATED",
        "provenance may not evaluate release"
    );
    ensure!(
        !provenance.release_ready,
        "provenance must keep releaseReady=false"
    );
    validate_source(&provenance.source, expected_commit, "provenance source")?;
    validate_toolchain(&provenance.toolchain, "provenance toolchain")?;
    ensure!(
        provenance.native_evidence.status == "NOT_PROVEN",
        "provenance native evidence must remain NOT_PROVEN"
    );
    ensure!(
        provenance.native_evidence.required_for_release,
        "provenance native evidence must be required for release"
    );
    ensure!(
        !provenance.native_evidence.release_eligible,
        "provenance cannot make the bundle release eligible"
    );
    Ok(())
}

fn validate_source(source: &SourceBinding, expected_commit: &str, label: &str) -> Result<()> {
    validate_commit(expected_commit)?;
    ensure!(source.commit == expected_commit, "{label} commit mismatch");
    ensure!(is_hex(&source.tree, 40), "{label} tree is invalid");
    ensure!(
        is_hex(&source.tree_sha256, 64),
        "{label} tree digest is invalid"
    );
    ensure!(
        source.repository.starts_with("https://"),
        "{label} repository URI is not HTTPS"
    );
    Ok(())
}

fn validate_toolchain(toolchain: &ToolchainBinding, label: &str) -> Result<()> {
    ensure!(!toolchain.rustc.is_empty(), "{label} rustc is empty");
    ensure!(!toolchain.cargo.is_empty(), "{label} cargo is empty");
    ensure!(!toolchain.target.is_empty(), "{label} target is empty");
    Ok(())
}

fn validate_commit(commit: &str) -> Result<()> {
    ensure!(
        is_hex(commit, 40),
        "expected distribution commit must be a 40-character lowercase Git object id"
    );
    Ok(())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn input_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn read_json<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {label} {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {label} {}", path.display()))
}

fn read_json_value(path: &Path, label: &str) -> Result<Value> {
    read_json(path, label)
}

fn verify_input_file(path: &Path, label: &str) -> Result<DigestAndLength> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{label} is not a regular file"
    );
    let digest = digest_file(path)?;
    Ok(digest)
}

fn verify_input_pointer(
    root: &Path,
    pointer: &DigestPointer,
    input: &Path,
    label: &str,
) -> Result<()> {
    let relative = relative_path(root, input)?;
    ensure!(
        pointer.path == relative,
        "{label} path does not match the CLI input"
    );
    verify_digest_pointer(root, pointer, input, label)
}

fn verify_path_pointer(
    root: &Path,
    pointer: &PathPointer,
    input: &Path,
    label: &str,
) -> Result<()> {
    let relative = relative_path(root, input)?;
    ensure!(
        pointer.path == relative,
        "{label} path does not match the CLI input"
    );
    if pointer.sha256.is_some() != pointer.byte_count.is_some() {
        ensure!(
            false,
            "{label} digest and byte count must be supplied together"
        );
    }
    if let (Some(sha256), Some(byte_count)) = (&pointer.sha256, pointer.byte_count) {
        ensure!(is_hex(sha256, 64), "{label} digest is invalid");
        let actual = verify_input_file(input, label)?;
        ensure!(actual.sha256 == *sha256, "{label} digest drifted");
        ensure!(
            actual.byte_count == byte_count,
            "{label} byte count drifted"
        );
    } else {
        verify_input_file(input, label)?;
    }
    Ok(())
}

fn verify_digest_pointer(
    root: &Path,
    pointer: &DigestPointer,
    input: &Path,
    label: &str,
) -> Result<()> {
    let relative = relative_path(root, input)?;
    ensure!(
        pointer.path == relative,
        "{label} path does not match the expected input"
    );
    ensure!(is_hex(&pointer.sha256, 64), "{label} digest is invalid");
    let actual = verify_input_file(input, label)?;
    ensure!(actual.sha256 == pointer.sha256, "{label} digest drifted");
    ensure!(
        actual.byte_count == pointer.byte_count,
        "{label} byte count drifted"
    );
    Ok(())
}

fn relative_path(root: &Path, input: &Path) -> Result<String> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolve root {}", root.display()))?;
    let input = input
        .canonicalize()
        .with_context(|| format!("resolve input {}", input.display()))?;
    let relative = input.strip_prefix(&root).with_context(|| {
        format!(
            "input {} is outside root {}",
            input.display(),
            root.display()
        )
    })?;
    ensure!(
        !relative.as_os_str().is_empty(),
        "distribution input may not be the repository root"
    );
    let value = relative.to_string_lossy().replace('\\', "/");
    validate_relative_path(&value)?;
    Ok(value)
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        !path.is_absolute() && !value.is_empty(),
        "distribution artifact path must be relative"
    );
    for component in path.components() {
        ensure!(
            !matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            ),
            "distribution artifact path escapes the verification root"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DigestAndLength {
    sha256: String,
    byte_count: u64,
}

fn digest_file(path: &Path) -> Result<DigestAndLength> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        byte_count += count as u64;
        digest.update(&buffer[..count]);
    }
    Ok(DigestAndLength {
        sha256: format!("{:x}", digest.finalize()),
        byte_count,
    })
}

fn verify_artifacts(
    root: &Path,
    records: &[ArtifactRecord],
    expected_commit: &str,
    label: &str,
) -> Result<BTreeSet<(String, String, String, u64)>> {
    ensure!(!records.is_empty(), "{label} artifact list is empty");
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut result = BTreeSet::new();
    for record in records {
        ensure!(
            ids.insert(record.id.clone()),
            "{label} artifact ids must be unique"
        );
        ensure!(
            paths.insert(record.path.clone()),
            "{label} artifact paths must be unique"
        );
        ensure!(
            is_hex(&record.sha256, 64),
            "{label} artifact digest is invalid"
        );
        ensure!(
            record.source_commit == expected_commit,
            "{label} artifact commit binding drifted"
        );
        ensure!(
            matches!(
                record.kind.as_str(),
                "APPLICATION" | "SBOM" | "MANIFEST" | "TELEMETRY"
            ),
            "{label} artifact kind is invalid"
        );
        ensure!(
            matches!(
                record.evidence_class.as_str(),
                "NATIVE" | "LOCAL_CONTRACT" | "BLOCKED_ENV" | "CI_NOT_EXECUTED"
            ),
            "{label} artifact evidence class is invalid"
        );
        validate_relative_path(&record.path)?;
        let path = root.join(&record.path);
        let actual = verify_input_file(&path, &format!("{label} artifact {}", record.id))?;
        ensure!(
            actual.sha256 == record.sha256,
            "{label} artifact {} digest drifted",
            record.id
        );
        ensure!(
            actual.byte_count == record.byte_count,
            "{label} artifact {} byte count drifted",
            record.id
        );
        result.insert((
            record.id.clone(),
            record.path.clone(),
            record.sha256.clone(),
            record.byte_count,
        ));
    }
    Ok(result)
}

fn validate_cyclonedx(value: &Value, expected_commit: &str, expected_bytes: u64) -> Result<()> {
    let object = value
        .as_object()
        .context("CycloneDX SBOM root must be an object")?;
    ensure!(
        object.get("schemaVersion").and_then(Value::as_str) == Some(CYCLONEDX_SCHEMA),
        "CycloneDX schema mismatch"
    );
    ensure!(
        object.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX"),
        "SBOM must be CycloneDX"
    );
    ensure!(
        object.get("specVersion").and_then(Value::as_str) == Some("1.5"),
        "CycloneDX version must be 1.5"
    );
    let components = object
        .get("components")
        .and_then(Value::as_array)
        .context("CycloneDX components are missing")?;
    ensure!(!components.is_empty(), "CycloneDX components are empty");
    let provenance = object
        .get("provenance")
        .and_then(Value::as_object)
        .context("CycloneDX provenance is missing")?;
    ensure!(
        provenance.get("commit").and_then(Value::as_str) == Some(expected_commit),
        "CycloneDX commit binding drifted"
    );
    ensure!(expected_bytes > 0, "CycloneDX artifact is empty");
    Ok(())
}

fn validate_spdx(
    document: &SpdxDocument,
    expected_commit: &str,
    source: &SourceBinding,
    expected_bytes: u64,
) -> Result<()> {
    ensure!(
        document.spdx_version == SPDX_SCHEMA,
        "SPDX version must be SPDX-2.3"
    );
    ensure!(
        document.data_license == "CC0-1.0",
        "SPDX data license must be CC0-1.0"
    );
    ensure!(
        document.spdx_id == "SPDXRef-DOCUMENT",
        "SPDX document id is invalid"
    );
    ensure!(
        document.document_namespace.contains(expected_commit),
        "SPDX namespace is not bound to the source commit"
    );
    ensure!(
        document.document_namespace.contains(&source.tree_sha256),
        "SPDX namespace is not bound to the source tree"
    );
    ensure!(
        !document.creation_info.created.is_empty() && !document.creation_info.creators.is_empty(),
        "SPDX creation information is incomplete"
    );
    DateTime::parse_from_rfc3339(&document.creation_info.created)
        .context("SPDX creation time is invalid")?;
    ensure!(!document.packages.is_empty(), "SPDX package list is empty");
    ensure!(expected_bytes > 0, "SPDX artifact is empty");
    let package_ids: BTreeSet<&str> = document
        .packages
        .iter()
        .map(|package| package.spdx_id.as_str())
        .collect();
    ensure!(
        package_ids.len() == document.packages.len(),
        "SPDX package ids must be unique"
    );
    for package in &document.packages {
        ensure!(
            package.spdx_id.starts_with("SPDXRef-Package-"),
            "SPDX package id is invalid"
        );
        ensure!(
            !package.name.is_empty() && !package.version_info.is_empty(),
            "SPDX package identity is incomplete"
        );
        ensure!(
            package.download_location == "NOASSERTION",
            "SPDX download locations must not claim an unverified source"
        );
        ensure!(
            !package.files_analyzed,
            "local SPDX must not claim file analysis"
        );
        ensure!(
            package.license_concluded == "NOASSERTION",
            "local SPDX must not claim concluded licenses"
        );
        ensure!(
            !package.license_declared.is_empty() && !package.copyright_text.is_empty(),
            "SPDX package license metadata is incomplete"
        );
    }
    for relationship in &document.relationships {
        let left_known = relationship.spdx_element_id == document.spdx_id
            || package_ids.contains(relationship.spdx_element_id.as_str());
        let right_known = relationship.related_spdx_element == document.spdx_id
            || package_ids.contains(relationship.related_spdx_element.as_str());
        ensure!(
            left_known && right_known,
            "SPDX relationship references an unknown element"
        );
        ensure!(
            matches!(
                relationship.relationship_type.as_str(),
                "DESCRIBES" | "DEPENDS_ON"
            ),
            "SPDX relationship type is not allowed"
        );
    }
    Ok(())
}

fn validate_telemetry(
    document: &TelemetryDocument,
    expected_commit: &str,
    manifest_digest: &DigestAndLength,
) -> Result<()> {
    ensure!(
        document.schema_version == TELEMETRY_SCHEMA,
        "telemetry schema mismatch"
    );
    validate_telemetry_policy(&document.policy)?;
    validate_telemetry_event(&document.event, expected_commit, manifest_digest)
}

fn validate_telemetry_policy(policy: &TelemetryPolicy) -> Result<()> {
    ensure!(
        !policy.default_enabled,
        "telemetry must be disabled by default"
    );
    ensure!(policy.opt_in_required, "telemetry must require opt-in");
    ensure!(
        !policy.content_allowed && !policy.secret_allowed && !policy.pii_allowed,
        "telemetry policy allows sensitive content"
    );
    ensure!(
        policy.content_free && policy.retention_days == 7,
        "telemetry content-free policy drifted"
    );
    Ok(())
}

fn validate_telemetry_event(
    event: &TelemetryEvent,
    expected_commit: &str,
    manifest_digest: &DigestAndLength,
) -> Result<()> {
    ensure!(
        event.schema_version == TELEMETRY_SCHEMA,
        "telemetry event schema mismatch"
    );
    ensure!(
        event.build_commit == expected_commit,
        "telemetry commit binding drifted"
    );
    ensure!(
        event.build_manifest_sha256 == manifest_digest.sha256,
        "telemetry manifest binding drifted"
    );
    validate_telemetry_event_identity(event)?;
    validate_telemetry_event_content(event)
}

fn validate_telemetry_event_identity(event: &TelemetryEvent) -> Result<()> {
    ensure!(
        matches!(
            event.event_name.as_str(),
            "app.start"
                | "app.update_check"
                | "app.update_apply"
                | "app.rollback"
                | "run.started"
                | "run.terminal"
                | "run.failure"
                | "restore.drill"
                | "crash.redacted"
        ),
        "telemetry event name is not allowlisted"
    );
    ensure!(is_hex(&event.event_id, 64), "telemetry event id is invalid");
    for digest in [
        &event.build_manifest_sha256,
        &event.tenant_pseudonym,
        &event.project_pseudonym,
        &event.mission_pseudonym,
        &event.run_pseudonym,
        &event.checkpoint_pseudonym,
        &event.effect_pseudonym,
    ] {
        ensure!(is_hex(digest, 64), "telemetry digest is invalid");
    }
    ensure!(
        event.provider_id.len() <= 64
            && !event.provider_id.is_empty()
            && event
                .provider_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')),
        "telemetry provider id is invalid"
    );
    ensure!(
        matches!(
            event.status.as_str(),
            "started"
                | "in_progress"
                | "succeeded"
                | "failed"
                | "uncertain"
                | "blocked"
                | "disabled"
        ),
        "telemetry status is invalid"
    );
    DateTime::parse_from_rfc3339(&event.occurred_at).context("telemetry timestamp is invalid")?;
    if let Some(failure_class) = &event.attributes.failure_class {
        ensure!(
            !failure_class.is_empty()
                && failure_class.len() <= 64
                && failure_class
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
            "telemetry failure class is invalid"
        );
    }
    Ok(())
}

fn validate_telemetry_event_content(event: &TelemetryEvent) -> Result<()> {
    let encoded = serde_json::to_string(event)?.to_lowercase();
    for term in FORBIDDEN_TELEMETRY_TERMS {
        ensure!(
            !encoded.contains(term),
            "telemetry payload contains forbidden lexical marker {term}"
        );
    }
    Ok(())
}

fn validate_hooks(
    root: &Path,
    hooks: &SigningHooks,
    label: &str,
) -> Result<(String, String, String)> {
    validate_hook(
        root,
        &hooks.macos_signing,
        &format!("{label} macOS signing"),
    )?;
    validate_hook(
        root,
        &hooks.macos_notarization,
        &format!("{label} macOS notarization"),
    )?;
    validate_hook(
        root,
        &hooks.windows_signing,
        &format!("{label} Windows signing"),
    )?;
    Ok((
        hooks.macos_signing.status.clone(),
        hooks.macos_notarization.status.clone(),
        hooks.windows_signing.status.clone(),
    ))
}

fn validate_hook(root: &Path, hook: &HookBinding, label: &str) -> Result<()> {
    ensure!(!hook.hook.is_empty(), "{label} hook name is empty");
    ensure!(
        matches!(
            hook.status.as_str(),
            "PASS" | "BLOCKED_ENV" | "CI_NOT_EXECUTED" | "FAIL"
        ),
        "{label} status is invalid"
    );
    ensure!(hook.status != "FAIL", "{label} reported FAIL");
    if hook.status == "PASS" {
        ensure!(
            hook.evidence_path.is_some() && hook.evidence_sha256.is_some(),
            "{label} PASS requires evidence path and digest"
        );
    }
    match (&hook.evidence_path, &hook.evidence_sha256) {
        (None, None) => Ok(()),
        (Some(path), Some(expected_sha256)) => {
            validate_relative_path(path)?;
            ensure!(
                is_hex(expected_sha256, 64),
                "{label} evidence digest is invalid"
            );
            let actual = verify_input_file(&root.join(path), label)?;
            ensure!(
                actual.sha256 == *expected_sha256,
                "{label} evidence digest drifted"
            );
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "{label} evidence path and digest must be supplied together"
        )),
    }
}

#[allow(dead_code)]
fn write_receipt(path: &Path, receipt: &DistributionVerificationReceipt) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create receipt directory {}", parent.display()))?;
    }
    let mut file =
        fs::File::create(path).with_context(|| format!("create receipt {}", path.display()))?;
    let json = serde_json::to_string_pretty(receipt)?;
    file.write_all(format!("{json}\n").as_bytes())
        .with_context(|| format!("write receipt {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn digest_validation_requires_lowercase_hex() {
        assert!(is_hex(&"a".repeat(64), 64));
        assert!(!is_hex(&"A".repeat(64), 64));
        assert!(!is_hex(&"0".repeat(63), 64));
    }

    #[test]
    fn artifact_paths_cannot_escape_the_verification_root() {
        assert!(validate_relative_path("target/distribution/file.json").is_ok());
        assert!(validate_relative_path("../outside.json").is_err());
        assert!(validate_relative_path("/absolute.json").is_err());
    }

    #[test]
    fn signing_hook_pass_requires_evidence() {
        let directory = tempdir().expect("temporary verification root");
        let hook = HookBinding {
            status: "PASS".to_string(),
            hook: "codesign".to_string(),
            evidence_path: None,
            evidence_sha256: None,
        };
        assert!(validate_hook(directory.path(), &hook, "test hook").is_err());
    }
}
