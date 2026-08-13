use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use chrono::DateTime;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::digest::{is_lower_hex, sha256_domain_canonical_json, sha256_hex, sha256_json};
use crate::model::{
    Architecture, AssertionOutcome, CaseDefinitionDigestMaterial, DispositionCounts, EvidenceMode,
    EvidenceReferenceKind, EvidenceRequirement, ImplementationState, MissingReceiptDisposition,
    NativeProducerMode, OperatingSystem, PlatformMatrix, PlatformReceipt, PlatformStatus,
    PlatformTarget, ReadinessClassification, ReceiptKind, RegistryEmptyPolicy, SignatureAlgorithm,
    SupportClass,
};

pub const EXPECTED_SOURCE_COMMIT: &str = "cc662d53d55216b32be43afdc61e0195f9e5659f";
pub const EXPECTED_MATRIX_SCHEMA_VERSION: &str = "hartevo-platform-matrix/v2";
pub const EXPECTED_MATRIX_VERSION: &str = "i-01b-native-receipt-matrix/2026-08-13-v2";
pub const MATRIX_V2_SHA256: &str =
    "6384d8b7e60a73c57757d0ea7920df911c254a92180549390542c8540792dbaa";
pub const EXPECTED_RECEIPT_SCHEMA_VERSION: &str = "hartevo-platform-native-receipt/v2";
pub const RECEIPT_SCHEMA_V2_URI: &str =
    "https://hartevo.local/contracts/platform/receipt.schema.v2.json";
pub const RECEIPT_SCHEMA_V2_SHA256: &str =
    "28dd733c2456da23eb9782cb666abb3b6fea1b41f3227129e25f3ece7b20d65e";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-platform-native-receipt-validation/v2";
pub const INVENTORY_AUTHORITY: &str = "platform_inventory_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const EXPECTED_REPOSITORY_ID: &str = "tangpingqingwa/hartevo-desktop";
pub const PRODUCER_READINESS: &str = "BLOCKED_ENV";
pub const NATIVE_RECEIPT_EMISSION_ALLOWED: bool = false;
pub const SIGNATURE_VERIFIER_AVAILABLE: bool = false;
pub const HOST_ATTESTATION_VERIFIER_AVAILABLE: bool = false;

const EXPECTED_BLOCKED_ENV_COUNT: usize = 16;
const EXPECTED_NOT_IMPLEMENTED_COUNT: usize = 25;
const IMPLEMENTATION_DIGEST_DOMAIN: &[u8] = b"hartevo-platform-implementation-digest/v2";
const RUNNER_REGISTRY_DIGEST_DOMAIN: &str = "hartevo-platform-runner-registry-digest/v2";

#[derive(Debug)]
pub struct GitToolUnavailable;

impl fmt::Display for GitToolUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("required Git object reader is unavailable")
    }
}

impl std::error::Error for GitToolUnavailable {}

pub fn is_git_tool_unavailable(error: &anyhow::Error) -> bool {
    error.downcast_ref::<GitToolUnavailable>().is_some()
}

#[derive(Debug)]
pub struct MatrixValidation {
    pub counts: DispositionCounts,
    implementation_digests: BTreeMap<String, String>,
}

impl MatrixValidation {
    fn implementation_digest(&self, case_id: &str) -> Result<&str> {
        self.implementation_digests
            .get(case_id)
            .map(String::as_str)
            .context("case implementation digest is absent from validated Git inventory")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GitBlobInventory {
    mode: String,
    blob_sha256: String,
    byte_count: u64,
}

#[derive(Clone, Copy)]
struct ExpectedTarget {
    id: &'static str,
    os: OperatingSystem,
    arch: Architecture,
    support_class: SupportClass,
}

const EXPECTED_TARGETS: &[ExpectedTarget] = &[
    ExpectedTarget {
        id: "macos-aarch64",
        os: OperatingSystem::Macos,
        arch: Architecture::Aarch64,
        support_class: SupportClass::Release,
    },
    ExpectedTarget {
        id: "macos-x86_64",
        os: OperatingSystem::Macos,
        arch: Architecture::X86_64,
        support_class: SupportClass::Release,
    },
    ExpectedTarget {
        id: "windows-aarch64",
        os: OperatingSystem::Windows,
        arch: Architecture::Aarch64,
        support_class: SupportClass::Release,
    },
    ExpectedTarget {
        id: "windows-x86_64",
        os: OperatingSystem::Windows,
        arch: Architecture::X86_64,
        support_class: SupportClass::Release,
    },
    ExpectedTarget {
        id: "linux-x86_64",
        os: OperatingSystem::Linux,
        arch: Architecture::X86_64,
        support_class: SupportClass::Compatibility,
    },
];

#[derive(Clone, Copy)]
struct ExpectedCase {
    target_id: &'static str,
    capability_id: &'static str,
    disposition: PlatformStatus,
    implementation_state: ImplementationState,
    evidence_requirement: EvidenceRequirement,
}

const fn blocked(target_id: &'static str, capability_id: &'static str) -> ExpectedCase {
    ExpectedCase {
        target_id,
        capability_id,
        disposition: PlatformStatus::BlockedEnv,
        implementation_state: ImplementationState::Implemented,
        evidence_requirement: EvidenceRequirement::NativeExecution,
    }
}

const fn missing(target_id: &'static str, capability_id: &'static str) -> ExpectedCase {
    ExpectedCase {
        target_id,
        capability_id,
        disposition: PlatformStatus::NotImplemented,
        implementation_state: ImplementationState::NotImplemented,
        evidence_requirement: EvidenceRequirement::SourceAudit,
    }
}

const EXPECTED_CASES: &[ExpectedCase] = &[
    blocked("macos-aarch64", "secret.macos_data_protection_signed"),
    blocked("macos-aarch64", "browser.pipe_platform_default"),
    blocked("macos-aarch64", "browser.profile_exclusive_lock"),
    blocked("macos-aarch64", "browser.posix_process_group"),
    missing("macos-aarch64", "auth.account_identity"),
    missing("macos-aarch64", "auth.cookie_restart"),
    missing("macos-aarch64", "auth.reauth_refusal"),
    blocked("macos-x86_64", "secret.macos_data_protection_signed"),
    blocked("macos-x86_64", "browser.pipe_platform_default"),
    blocked("macos-x86_64", "browser.profile_exclusive_lock"),
    blocked("macos-x86_64", "browser.posix_process_group"),
    missing("macos-x86_64", "auth.account_identity"),
    missing("macos-x86_64", "auth.cookie_restart"),
    missing("macos-x86_64", "auth.reauth_refusal"),
    missing("windows-aarch64", "browser.pipe"),
    missing("windows-aarch64", "browser.job_object"),
    blocked("windows-aarch64", "runtime.job_object"),
    blocked("windows-aarch64", "browser.profile_exclusive_lock"),
    missing("windows-aarch64", "path.reparse_defense"),
    missing("windows-aarch64", "path.private_acl"),
    missing("windows-aarch64", "secret.credential_manager_local"),
    missing("windows-aarch64", "auth.account_identity"),
    missing("windows-aarch64", "auth.cookie_restart"),
    missing("windows-aarch64", "auth.reauth_refusal"),
    missing("windows-x86_64", "browser.pipe"),
    missing("windows-x86_64", "browser.job_object"),
    blocked("windows-x86_64", "runtime.job_object"),
    blocked("windows-x86_64", "browser.profile_exclusive_lock"),
    missing("windows-x86_64", "path.reparse_defense"),
    missing("windows-x86_64", "path.private_acl"),
    missing("windows-x86_64", "secret.credential_manager_local"),
    missing("windows-x86_64", "auth.account_identity"),
    missing("windows-x86_64", "auth.cookie_restart"),
    missing("windows-x86_64", "auth.reauth_refusal"),
    blocked("linux-x86_64", "browser.pipe"),
    blocked("linux-x86_64", "browser.posix_process_group"),
    blocked("linux-x86_64", "browser.profile_lock_and_mode"),
    blocked("linux-x86_64", "secret.linux_keyutils"),
    missing("linux-x86_64", "auth.account_identity"),
    missing("linux-x86_64", "auth.cookie_restart"),
    missing("linux-x86_64", "auth.reauth_refusal"),
];

const EXPECTED_PROHIBITED_UPGRADE_EVIDENCE: &[&str] = &[
    "compile_only",
    "cross_compile",
    "fake_host",
    "ignored_test",
    "mock_credential_store",
    "source_audit",
];

const EXPECTED_PREFLIGHT_EVIDENCE_KINDS: &[EvidenceReferenceKind] = &[
    EvidenceReferenceKind::HostAttestation,
    EvidenceReferenceKind::NativePreflight,
    EvidenceReferenceKind::ProducerBinary,
    EvidenceReferenceKind::ProductionBinary,
    EvidenceReferenceKind::RunnerSignature,
];

const EXPECTED_EXECUTION_EVIDENCE_KINDS: &[EvidenceReferenceKind] = &[
    EvidenceReferenceKind::Cleanup,
    EvidenceReferenceKind::HostAttestation,
    EvidenceReferenceKind::NativeExecution,
    EvidenceReferenceKind::ProducerBinary,
    EvidenceReferenceKind::ProductionBinary,
    EvidenceReferenceKind::RunnerSignature,
];

const EXPECTED_READINESS_BLOCKERS: &[(&str, ReadinessClassification)] = &[
    (
        "NATIVE_HOST_ATTESTATION_UNAVAILABLE",
        ReadinessClassification::BlockedEnv,
    ),
    ("RUNNER_REGISTRY_EMPTY", ReadinessClassification::BlockedEnv),
    (
        "RUNNER_SIGNATURE_VERIFIER_NOT_IMPLEMENTED",
        ReadinessClassification::NotImplemented,
    ),
];

pub fn validate_matrix(
    matrix: &PlatformMatrix,
    repository_root: &Path,
) -> Result<MatrixValidation> {
    ensure!(
        matrix.schema_version == EXPECTED_MATRIX_SCHEMA_VERSION,
        "unexpected platform matrix schema version"
    );
    ensure!(
        matrix.matrix_version == EXPECTED_MATRIX_VERSION,
        "unexpected platform matrix version"
    );
    ensure!(
        matrix.repository_id == EXPECTED_REPOSITORY_ID,
        "platform matrix repositoryId changed"
    );
    ensure!(
        matrix.receipt_schema_uri == RECEIPT_SCHEMA_V2_URI
            && matrix.receipt_schema_sha256 == RECEIPT_SCHEMA_V2_SHA256,
        "platform matrix receipt schema binding changed"
    );
    ensure!(
        is_lower_hex(&matrix.source_commit, 20) && matrix.source_commit == EXPECTED_SOURCE_COMMIT,
        "platform matrix sourceCommit is not the published integration baseline"
    );
    validate_git_commit(repository_root, &matrix.source_commit)?;
    ensure!(
        matrix.evidence_mode == EvidenceMode::SourceAuditBaseline,
        "I-01B must preserve source-audit inventory authority"
    );
    ensure!(
        !matrix.release_eligible,
        "source inventory cannot be release eligible"
    );
    ensure!(
        matrix.native_receipt_count == 0,
        "I-01B contract-only preflight cannot claim native receipts"
    );
    ensure!(
        matrix.allowed_runners.is_empty(),
        "I-01B must remain fail-closed with an empty runner registry"
    );
    validate_native_producer_policy(matrix)?;
    validate_readiness_blockers(matrix)?;
    ensure!(
        matrix.runner_registry_epoch == 0
            && matrix.runner_registry_digest == derive_runner_registry_digest(matrix)?,
        "empty runner registry epoch or digest changed"
    );

    validate_receipt_policy(matrix)?;
    validate_exact_string_list(
        &matrix.prohibited_upgrade_evidence,
        EXPECTED_PROHIBITED_UPGRADE_EVIDENCE,
        "prohibitedUpgradeEvidence",
    )?;
    validate_sorted_unique_blocker_codes(&matrix.allowed_blocker_codes, "allowedBlockerCodes")?;
    ensure!(
        !matrix.allowed_blocker_codes.is_empty(),
        "allowedBlockerCodes cannot be empty"
    );
    validate_targets(&matrix.targets)?;
    let implementation_digests = validate_cases(matrix, repository_root)?;

    let recomputed = recompute_counts(matrix);
    ensure!(
        recomputed == matrix.source_audit_disposition_counts,
        "aggregate source-audit counts do not match the 41 case rows"
    );
    ensure!(
        recomputed.pass == 0
            && recomputed.fail == 0
            && recomputed.blocked_env == EXPECTED_BLOCKED_ENV_COUNT
            && recomputed.not_implemented == EXPECTED_NOT_IMPLEMENTED_COUNT,
        "I-01B must preserve 0 PASS / 0 FAIL / 16 BLOCKED_ENV / 25 NOT_IMPLEMENTED"
    );
    Ok(MatrixValidation {
        counts: recomputed,
        implementation_digests,
    })
}

pub fn validate_matrix_raw(raw_matrix: &[u8]) -> Result<()> {
    ensure!(
        sha256_hex(raw_matrix) == MATRIX_V2_SHA256,
        "platform matrix raw digest changed"
    );
    std::str::from_utf8(raw_matrix).context("platform matrix raw bytes must be UTF-8")?;
    Ok(())
}

fn validate_native_producer_policy(matrix: &PlatformMatrix) -> Result<()> {
    let policy = &matrix.native_producer_policy;
    ensure!(
        policy.mode == NativeProducerMode::ContractOnlyFailClosed
            && !policy.native_receipt_emission_allowed
            && policy.registry_empty_policy == RegistryEmptyPolicy::DenyAll
            && policy.trusted_registry_required
            && policy.runner_signature_required
            && policy.signature_algorithm == SignatureAlgorithm::Ed25519
            && !policy.signature_verifier_available
            && !policy.host_attestation_verifier_available
            && policy.real_host_required
            && policy.content_free
            && policy.challenge_nonce_digest_required
            && policy.max_challenge_age_seconds == 300
            && policy.max_run_duration_seconds == 3600
            && policy.signature_payload_domain == "hartevo-platform-native-receipt-signature/v2"
            && policy.preflight_evidence_kinds == EXPECTED_PREFLIGHT_EVIDENCE_KINDS
            && policy.execution_evidence_kinds == EXPECTED_EXECUTION_EVIDENCE_KINDS,
        "native producer policy is not the frozen fail-closed contract"
    );
    ensure!(
        !SIGNATURE_VERIFIER_AVAILABLE
            && !HOST_ATTESTATION_VERIFIER_AVAILABLE
            && !NATIVE_RECEIPT_EMISSION_ALLOWED,
        "compiled verifier capabilities cannot silently enable native receipts"
    );
    Ok(())
}

fn validate_readiness_blockers(matrix: &PlatformMatrix) -> Result<()> {
    ensure!(
        matrix.readiness_blockers.len() == EXPECTED_READINESS_BLOCKERS.len(),
        "native producer readiness blockers changed"
    );
    for (blocker, (expected_code, expected_classification)) in matrix
        .readiness_blockers
        .iter()
        .zip(EXPECTED_READINESS_BLOCKERS)
    {
        ensure!(
            blocker.code == *expected_code && blocker.classification == *expected_classification,
            "native producer readiness blocker identity changed"
        );
        validate_blocker_code(&blocker.code)?;
        validate_bounded_text(&blocker.observation_source, 240, "observationSource")?;
        validate_bounded_text(&blocker.exit_condition, 512, "exitCondition")?;
    }
    Ok(())
}

fn derive_runner_registry_digest(matrix: &PlatformMatrix) -> Result<String> {
    ensure!(
        matrix.allowed_runners.is_empty(),
        "v2 contract cannot derive an authenticated non-empty registry without signature support"
    );
    let material = format!(
        "{RUNNER_REGISTRY_DIGEST_DOMAIN}\nrepositoryId={}\nsourceCommit={}\nepoch={}\nrunnerCount=0\n",
        matrix.repository_id, matrix.source_commit, matrix.runner_registry_epoch
    );
    Ok(sha256_hex(material.as_bytes()))
}

fn validate_receipt_policy(matrix: &PlatformMatrix) -> Result<()> {
    let policy = &matrix.receipt_policy;
    ensure!(
        policy.pass_receipt_kind == ReceiptKind::NativeExecution
            && policy.fail_receipt_kind == ReceiptKind::NativeExecution
            && policy.blocked_env_receipt_kind == ReceiptKind::NativePreflight
            && policy.not_implemented_receipt_kind == ReceiptKind::SourceAudit
            && policy.native_target_must_match
            && policy.cleanup_required_for_native_execution
            && policy.missing_receipt_disposition == MissingReceiptDisposition::AggregateFailure,
        "platform receipt policy does not match I-01 eligibility rules"
    );
    Ok(())
}

fn validate_targets(targets: &[PlatformTarget]) -> Result<()> {
    ensure!(
        targets.len() == EXPECTED_TARGETS.len(),
        "platform target count must be exactly five"
    );
    let mut seen_ids = BTreeSet::new();
    let mut seen_tuples = BTreeSet::new();
    for (target, expected) in targets.iter().zip(EXPECTED_TARGETS) {
        ensure!(
            target.id == expected.id
                && target.os == expected.os
                && target.arch == expected.arch
                && target.support_class == expected.support_class,
            "platform target order or id/os/arch tuple is not canonical"
        );
        ensure!(
            seen_ids.insert(target.id.as_str()),
            "duplicate platform target id"
        );
        ensure!(
            seen_tuples.insert((target.os, target.arch)),
            "duplicate platform os/arch tuple"
        );
    }
    Ok(())
}

fn validate_cases(
    matrix: &PlatformMatrix,
    repository_root: &Path,
) -> Result<BTreeMap<String, String>> {
    ensure!(
        matrix.cases.len() == EXPECTED_CASES.len(),
        "platform case count must be exactly 41"
    );
    let targets = matrix
        .targets
        .iter()
        .map(|target| (target.id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    let global_blockers = matrix
        .allowed_blocker_codes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut case_ids = BTreeSet::new();
    let mut git_inventory = BTreeMap::new();
    let mut implementation_digests = BTreeMap::new();

    for (case, expected) in matrix.cases.iter().zip(EXPECTED_CASES) {
        let expected_case_id = format!("I-01.{}.{}", expected.target_id, expected.capability_id);
        ensure!(
            case.case_id == expected_case_id
                && case.target_id == expected.target_id
                && case.capability_id == expected.capability_id,
            "platform case order or identity is not canonical"
        );
        ensure!(
            case.source_audit_disposition == expected.disposition
                && case.implementation_state == expected.implementation_state
                && case.evidence_requirement == expected.evidence_requirement,
            "platform case disposition cannot be upgraded or reclassified"
        );
        ensure!(case_ids.insert(case.case_id.as_str()), "duplicate caseId");
        ensure!(
            targets.contains_key(case.target_id.as_str()),
            "case references an unknown targetId"
        );
        validate_machine_token(&case.capability_id, "capabilityId")?;
        validate_sorted_unique_tokens(&case.required_assertions, "requiredAssertions")?;
        validate_sorted_unique_blocker_codes(
            &case.allowed_blocker_codes,
            "case allowedBlockerCodes",
        )?;
        validate_sorted_unique_tokens(&case.missing_gates, "missingGates")?;
        ensure!(
            case.allowed_blocker_codes
                .iter()
                .all(|code| global_blockers.contains(code.as_str())),
            "case blocker is absent from the global blocker allow-list"
        );
        let implementation_digest =
            validate_source_bindings(matrix, case, repository_root, &mut git_inventory)?;
        ensure!(
            implementation_digests
                .insert(case.case_id.clone(), implementation_digest)
                .is_none(),
            "duplicate case implementation digest"
        );

        match case.source_audit_disposition {
            PlatformStatus::BlockedEnv => validate_blocked_case(case)?,
            PlatformStatus::NotImplemented => validate_not_implemented_case(case)?,
            PlatformStatus::Pass | PlatformStatus::Fail => {
                bail!("source-audit matrix rows cannot be PASS or FAIL");
            }
        }
    }
    Ok(implementation_digests)
}

fn validate_blocked_case(case: &crate::model::MatrixCase) -> Result<()> {
    ensure!(
        case.implementation_state == ImplementationState::Implemented
            && case.evidence_requirement == EvidenceRequirement::NativeExecution,
        "BLOCKED_ENV requires an implemented production path awaiting native evidence"
    );
    ensure!(
        case.production_component
            .as_deref()
            .is_some_and(|component| !component.is_empty()),
        "BLOCKED_ENV requires a production component"
    );
    validate_production_component(
        case.production_component
            .as_deref()
            .context("BLOCKED_ENV production component missing")?,
    )?;
    ensure!(
        !case.required_assertions.is_empty()
            && !case.allowed_blocker_codes.is_empty()
            && case.missing_gates.is_empty(),
        "BLOCKED_ENV assertion, blocker, or missing-gate fields are incompatible"
    );
    let blocker = case
        .current_blocker
        .as_ref()
        .context("BLOCKED_ENV requires a typed currentBlocker")?;
    ensure!(
        case.allowed_blocker_codes.contains(&blocker.code),
        "current blocker is not allowed for this case"
    );
    validate_blocker_code(&blocker.code)?;
    validate_bounded_text(
        &blocker.observation_source,
        240,
        "blocker observationSource",
    )?;
    validate_bounded_text(&blocker.exit_condition, 512, "blocker exitCondition")?;
    Ok(())
}

fn validate_not_implemented_case(case: &crate::model::MatrixCase) -> Result<()> {
    ensure!(
        case.implementation_state == ImplementationState::NotImplemented
            && case.evidence_requirement == EvidenceRequirement::SourceAudit,
        "NOT_IMPLEMENTED requires a source-audited missing implementation"
    );
    ensure!(
        case.production_component.is_none()
            && case.required_assertions.is_empty()
            && case.allowed_blocker_codes.is_empty()
            && case.current_blocker.is_none()
            && !case.missing_gates.is_empty(),
        "NOT_IMPLEMENTED fields are incompatible with a platform implementation"
    );
    Ok(())
}

fn validate_source_bindings(
    matrix: &PlatformMatrix,
    case: &crate::model::MatrixCase,
    repository_root: &Path,
    git_inventory: &mut BTreeMap<String, GitBlobInventory>,
) -> Result<String> {
    ensure!(
        !case.source_bindings.is_empty(),
        "every case needs a source binding"
    );
    let mut previous_path = None;
    let mut canonical_bindings = Vec::with_capacity(case.source_bindings.len());
    for binding in &case.source_bindings {
        validate_repository_relative_path(&binding.path)?;
        if let Some(previous) = previous_path {
            ensure!(
                previous < binding.path.as_str(),
                "sourceBindings must be sorted by unique canonical path"
            );
        }
        previous_path = Some(binding.path.as_str());
        validate_bounded_text(&binding.locator, 240, "source binding locator")?;
        validate_bounded_text(&binding.fact, 640, "source binding fact")?;
        ensure!(
            binding.mode == "100644" || binding.mode == "100755",
            "source binding mode must be a regular blob mode"
        );
        validate_digest(&binding.blob_sha256, "source binding blobSha256")?;

        let committed = if let Some(committed) = git_inventory.get(&binding.path) {
            committed.clone()
        } else {
            let committed = read_git_blob(repository_root, &matrix.source_commit, &binding.path)?;
            git_inventory.insert(binding.path.clone(), committed.clone());
            committed
        };
        ensure!(
            binding.mode == committed.mode
                && binding.blob_sha256 == committed.blob_sha256
                && binding.byte_count == committed.byte_count,
            "source binding metadata disagrees with the exact sourceCommit blob"
        );
        canonical_bindings.push((binding.path.as_str(), committed));
    }
    Ok(derive_implementation_digest(
        &matrix.repository_id,
        &matrix.source_commit,
        &case.case_id,
        &canonical_bindings,
    ))
}

fn validate_repository_relative_path(path_value: &str) -> Result<()> {
    ensure!(
        !path_value.is_empty()
            && !path_value.contains('\\')
            && !path_value.contains('\0')
            && !path_value.starts_with('/')
            && !path_value.ends_with('/')
            && !path_value.contains("//")
            && path_value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.')
            }),
        "source binding path is not a canonical repository-relative path"
    );
    let path = Path::new(path_value);
    ensure!(
        !path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "source binding path is not a canonical repository-relative path"
    );
    Ok(())
}

fn validate_git_commit(repository_root: &Path, source_commit: &str) -> Result<()> {
    let output = run_git(repository_root, &["cat-file", "-t", source_commit])?;
    ensure!(
        output == b"commit\n" || output == b"commit\r\n",
        "sourceCommit is missing or is not a Git commit object"
    );
    Ok(())
}

fn read_git_blob(
    repository_root: &Path,
    source_commit: &str,
    path: &str,
) -> Result<GitBlobInventory> {
    validate_repository_relative_path(path)?;
    let tree_output = run_git(
        repository_root,
        &["ls-tree", "-z", "--full-tree", source_commit, "--", path],
    )?;
    ensure!(
        tree_output.ends_with(&[0])
            && tree_output[..tree_output.len() - 1]
                .iter()
                .all(|byte| *byte != 0),
        "source binding must resolve to exactly one Git tree entry"
    );
    let record = &tree_output[..tree_output.len() - 1];
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .context("Git tree entry is malformed")?;
    let header = std::str::from_utf8(&record[..tab]).context("Git tree header is not UTF-8")?;
    let entry_path =
        std::str::from_utf8(&record[tab + 1..]).context("Git tree path is not UTF-8")?;
    ensure!(entry_path == path, "Git tree entry path is not exact");
    let header_parts = header.split(' ').collect::<Vec<_>>();
    ensure!(
        header_parts.len() == 3,
        "Git tree entry header is malformed"
    );
    let mode = header_parts[0];
    let object_type = header_parts[1];
    let object_id = header_parts[2];
    ensure!(
        (mode == "100644" || mode == "100755") && object_type == "blob",
        "source binding Git entry must be a regular 100644/100755 blob"
    );
    ensure!(
        is_lower_hex(object_id, 20) || is_lower_hex(object_id, 32),
        "Git blob object id is not canonical lowercase hex"
    );
    let bytes = run_git(repository_root, &["cat-file", "blob", object_id])?;
    let byte_count = u64::try_from(bytes.len()).context("Git blob byte count overflow")?;
    Ok(GitBlobInventory {
        mode: mode.to_owned(),
        blob_sha256: sha256_bytes(&bytes),
        byte_count,
    })
}

fn run_git(repository_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(repository_root)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .args(args)
        .output()
        .map_err(|_| anyhow::Error::new(GitToolUnavailable))?;
    ensure!(output.status.success(), "Git object lookup failed closed");
    Ok(output.stdout)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn derive_implementation_digest(
    repository_id: &str,
    source_commit: &str,
    case_id: &str,
    bindings: &[(&str, GitBlobInventory)],
) -> String {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, IMPLEMENTATION_DIGEST_DOMAIN);
    update_length_prefixed(&mut hasher, repository_id.as_bytes());
    update_length_prefixed(&mut hasher, source_commit.as_bytes());
    update_length_prefixed(&mut hasher, case_id.as_bytes());
    hasher.update((bindings.len() as u64).to_be_bytes());
    for (path, binding) in bindings {
        update_length_prefixed(&mut hasher, path.as_bytes());
        update_length_prefixed(&mut hasher, binding.mode.as_bytes());
        update_length_prefixed(&mut hasher, binding.blob_sha256.as_bytes());
        hasher.update(binding.byte_count.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn recompute_counts(matrix: &PlatformMatrix) -> DispositionCounts {
    let mut counts = DispositionCounts::zero();
    for case in &matrix.cases {
        counts.increment(case.source_audit_disposition);
    }
    counts
}

pub fn case_definition_digest(
    matrix: &PlatformMatrix,
    case: &crate::model::MatrixCase,
) -> Result<String> {
    let target = matrix
        .targets
        .iter()
        .find(|target| target.id == case.target_id)
        .context("case target missing while calculating definition digest")?;
    sha256_json(&CaseDefinitionDigestMaterial { target, case })
        .context("serializing case definition digest material")
}

pub fn validate_receipt_schema(
    schema: &Value,
    raw_schema: &[u8],
    matrix: &PlatformMatrix,
) -> Result<()> {
    validate_receipt_schema_raw(raw_schema, matrix)?;
    let root = schema
        .as_object()
        .context("receipt schema must be a JSON object")?;
    validate_exact_object_keys(
        root.keys().map(String::as_str),
        &[
            "$defs",
            "$id",
            "$schema",
            "additionalProperties",
            "allOf",
            "description",
            "properties",
            "required",
            "title",
            "type",
            "x-hartevo-policy",
        ],
        "receipt schema root",
    )?;
    ensure!(
        string_at(schema, "/$schema")? == "https://json-schema.org/draft/2020-12/schema"
            && string_at(schema, "/$id")?
                == "https://hartevo.local/contracts/platform/receipt.schema.v2.json"
            && string_at(schema, "/type")? == "object"
            && bool_at(schema, "/additionalProperties")? == Some(false),
        "receipt schema identity or closed-object boundary changed"
    );
    ensure!(
        string_at(schema, "/properties/schemaVersion/const")? == EXPECTED_RECEIPT_SCHEMA_VERSION,
        "receipt schemaVersion constant changed"
    );
    validate_v2_schema_shape(schema)?;
    ensure!(
        string_at(schema, "/x-hartevo-policy/authority")? == INVENTORY_AUTHORITY
            && bool_at(schema, "/x-hartevo-policy/nativeReceiptWriter")? == Some(false)
            && bool_at(schema, "/x-hartevo-policy/callerAggregatesAccepted")? == Some(false)
            && string_at(schema, "/x-hartevo-policy/releaseDecision")? == RELEASE_DECISION
            && bool_at(schema, "/x-hartevo-policy/sensitiveMaterialAllowed")? == Some(false)
            && bool_at(schema, "/x-hartevo-policy/sourceAuditReceiptAllowed")? == Some(false)
            && bool_at(schema, "/x-hartevo-policy/trustedRunnerRegistryRequired")? == Some(true)
            && bool_at(schema, "/x-hartevo-policy/runnerSignatureRequired")? == Some(true)
            && bool_at(schema, "/x-hartevo-policy/actualHostAttestationRequired")? == Some(true)
            && bool_at(schema, "/x-hartevo-policy/signatureVerifierAvailable")? == Some(false)
            && bool_at(schema, "/x-hartevo-policy/hostAttestationVerifierAvailable")?
                == Some(false),
        "receipt schema inventory-only authority changed"
    );
    Ok(())
}

pub fn validate_receipt_schema_raw(raw_schema: &[u8], matrix: &PlatformMatrix) -> Result<()> {
    let raw_digest = sha256_hex(raw_schema);
    ensure!(
        raw_digest == RECEIPT_SCHEMA_V2_SHA256
            && matrix.receipt_schema_sha256 == RECEIPT_SCHEMA_V2_SHA256
            && matrix.receipt_schema_uri == RECEIPT_SCHEMA_V2_URI,
        "receipt schema raw digest/URI binding changed"
    );
    std::str::from_utf8(raw_schema).context("receipt schema raw bytes must be UTF-8")?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_v2_schema_shape(schema: &Value) -> Result<()> {
    validate_exact_string_list(
        &string_array_at(schema, "/required")?,
        &[
            "schemaVersion",
            "matrixVersion",
            "sourceCommit",
            "matrixDigest",
            "caseDefinitionDigest",
            "receiptId",
            "runId",
            "attemptOrdinal",
            "caseId",
            "targetId",
            "target",
            "actualHost",
            "status",
            "receiptKind",
            "implementationState",
            "authority",
            "nativeCalls",
            "releaseDecision",
            "testMode",
            "mock",
            "startedAt",
            "completedAt",
            "executionStarted",
            "platformTouched",
            "runnerBinding",
            "challengeBinding",
            "productionBinding",
            "evidenceQualifiers",
            "artifacts",
            "evidenceReferences",
            "assertions",
            "signature",
        ],
        "receipt schema required fields",
    )?;
    validate_exact_object_keys(
        object_at(schema, "/properties")?.keys().map(String::as_str),
        &[
            "actualHost",
            "artifacts",
            "assertions",
            "attemptOrdinal",
            "authority",
            "blocker",
            "caseDefinitionDigest",
            "caseId",
            "challengeBinding",
            "cleanup",
            "completedAt",
            "evidenceQualifiers",
            "evidenceReferences",
            "executionStarted",
            "implementationState",
            "matrixDigest",
            "matrixVersion",
            "mock",
            "nativeCalls",
            "platformTouched",
            "productionBinding",
            "receiptId",
            "receiptKind",
            "releaseDecision",
            "runId",
            "runnerBinding",
            "schemaVersion",
            "signature",
            "sourceCommit",
            "startedAt",
            "status",
            "target",
            "targetId",
            "testMode",
        ],
        "receipt schema properties",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/properties/status/enum")?,
        &["PASS", "FAIL", "BLOCKED_ENV"],
        "native receipt status enum",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/properties/receiptKind/enum")?,
        &["native_preflight", "native_execution"],
        "native receipt kind enum",
    )?;
    validate_exact_object_keys(
        object_at(schema, "/$defs")?.keys().map(String::as_str),
        &[
            "actualHost",
            "assertion",
            "blocker",
            "caseId",
            "challengeBinding",
            "cleanup",
            "evidenceArtifact",
            "evidenceQualifiers",
            "evidenceReference",
            "nativeEvidenceQualifiers",
            "productionBinding",
            "receiptSignature",
            "runnerBinding",
            "sha256",
            "targetId",
            "targetTuple",
            "token",
        ],
        "receipt schema definitions",
    )?;
    for definition in [
        "actualHost",
        "assertion",
        "blocker",
        "challengeBinding",
        "cleanup",
        "evidenceArtifact",
        "evidenceQualifiers",
        "evidenceReference",
        "productionBinding",
        "receiptSignature",
        "runnerBinding",
        "targetTuple",
    ] {
        validate_closed_definition(schema, definition)?;
    }
    let rules = schema
        .pointer("/allOf")
        .and_then(Value::as_array)
        .context("native receipt schema allOf must be an array")?;
    ensure!(
        rules.len() == 3,
        "native receipt schema needs three status rules"
    );
    for (rule, (status, kind, calls_key, execution_started)) in rules.iter().zip([
        ("PASS", "native_execution", "minimum", true),
        ("FAIL", "native_execution", "minimum", true),
        ("BLOCKED_ENV", "native_preflight", "const", false),
    ]) {
        ensure!(
            string_at(rule, "/if/properties/status/const")? == status
                && string_at(rule, "/then/properties/receiptKind/const")? == kind
                && bool_at(rule, "/then/properties/executionStarted/const")?
                    == Some(execution_started)
                && rule
                    .pointer(&format!("/then/properties/nativeCalls/{calls_key}"))
                    .is_some(),
            "native receipt status rule changed"
        );
    }
    Ok(())
}

fn validate_closed_definition(schema: &Value, name: &str) -> Result<()> {
    let pointer = format!("/$defs/{name}");
    ensure!(
        string_at(schema, &format!("{pointer}/type"))? == "object"
            && bool_at(schema, &format!("{pointer}/additionalProperties"))? == Some(false),
        "receipt schema object definition is not closed"
    );
    let required = string_array_at(schema, &format!("{pointer}/required"))?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let properties = object_at(schema, &format!("{pointer}/properties"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        required == properties,
        "receipt schema object required/properties set changed"
    );
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptValidationSummary {
    pub receipt_id: String,
    pub run_id: String,
    pub case_id: String,
    pub status: &'static str,
    pub receipt_kind: &'static str,
    pub receipt_digest: String,
}

pub fn validate_content_free_receipt_json(value: &Value) -> Result<()> {
    fn walk(value: &Value) -> Result<()> {
        match value {
            Value::Null => bail!("receipt JSON null is forbidden"),
            Value::String(value) => {
                let lower = value.to_ascii_lowercase();
                let bytes = value.as_bytes();
                let windows_absolute = bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'/' | b'\\');
                ensure!(
                    value.len() <= 2048
                        && !value.chars().any(char::is_control)
                        && !value.starts_with('/')
                        && !value.starts_with("\\\\")
                        && !windows_absolute
                        && !lower.starts_with("file://")
                        && !lower.contains("/users/")
                        && !lower.contains("/home/")
                        && !lower.contains("\\users\\")
                        && !lower.contains("library/application support/google/chrome")
                        && !lower.contains(".config/google-chrome"),
                    "receipt contains raw or host-private material"
                );
            }
            Value::Array(values) => {
                for value in values {
                    walk(value)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    let normalized = key.to_ascii_lowercase();
                    ensure!(
                        !matches!(
                            normalized.as_str(),
                            "accounttoken"
                                | "cookie"
                                | "keychainitem"
                                | "profilepath"
                                | "rawsecret"
                                | "username"
                        ),
                        "receipt contains a forbidden sensitive field"
                    );
                    walk(value)?;
                }
            }
            Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }
    walk(value)
}

pub fn validate_receipt(
    receipt: &PlatformReceipt,
    receipt_bytes: &[u8],
    matrix: &PlatformMatrix,
    matrix_validation: &MatrixValidation,
    matrix_digest: &str,
    receipt_schema_digest: &str,
) -> Result<ReceiptValidationSummary> {
    validate_receipt_identity(receipt, matrix, matrix_digest, receipt_schema_digest)?;
    let case = matrix
        .cases
        .iter()
        .find(|case| case.case_id == receipt.case_id)
        .context("receipt references an unknown caseId")?;
    let target = matrix
        .targets
        .iter()
        .find(|target| target.id == case.target_id)
        .context("receipt case target is absent from the matrix")?;
    ensure!(
        case.implementation_state == ImplementationState::Implemented
            && receipt.implementation_state == ImplementationState::Implemented,
        "native receipt cannot represent a NOT_IMPLEMENTED inventory case"
    );
    ensure!(
        receipt.target_id == target.id
            && receipt.target.os == target.os
            && receipt.target.arch == target.arch,
        "receipt targetId and target tuple do not close over the matrix target"
    );
    ensure!(
        receipt.case_definition_digest == case_definition_digest(matrix, case)?,
        "receipt case-definition digest mismatch"
    );

    let (started_at, completed_at) = validate_receipt_time_window(receipt, matrix)?;
    validate_challenge(receipt, matrix, started_at, completed_at)?;
    validate_artifact_graph(receipt, started_at, completed_at)?;
    validate_evidence_references(receipt, matrix)?;
    validate_actual_host(receipt, target, matrix, started_at)?;
    validate_production_binding(receipt, case, matrix_validation)?;
    validate_signature_envelope(receipt, matrix)?;
    validate_receipt_common_safety(receipt)?;
    validate_status_semantics(receipt, case)?;

    validate_runner_authorization(receipt, matrix, started_at, completed_at)?;
    ensure!(
        SIGNATURE_VERIFIER_AVAILABLE && matrix.native_producer_policy.signature_verifier_available,
        "RUNNER_SIGNATURE_VERIFIER_NOT_IMPLEMENTED"
    );
    ensure!(
        HOST_ATTESTATION_VERIFIER_AVAILABLE
            && matrix
                .native_producer_policy
                .host_attestation_verifier_available,
        "NATIVE_HOST_ATTESTATION_UNAVAILABLE"
    );
    ensure!(
        NATIVE_RECEIPT_EMISSION_ALLOWED
            && matrix
                .native_producer_policy
                .native_receipt_emission_allowed,
        "native receipt emission is disabled"
    );

    Ok(ReceiptValidationSummary {
        receipt_id: receipt.receipt_id.clone(),
        run_id: receipt.run_id.clone(),
        case_id: receipt.case_id.clone(),
        status: receipt.status.as_str(),
        receipt_kind: receipt.receipt_kind.as_str(),
        receipt_digest: sha256_hex(receipt_bytes),
    })
}

fn validate_receipt_identity(
    receipt: &PlatformReceipt,
    matrix: &PlatformMatrix,
    matrix_digest: &str,
    receipt_schema_digest: &str,
) -> Result<()> {
    ensure!(
        receipt.schema_version == EXPECTED_RECEIPT_SCHEMA_VERSION
            && receipt.matrix_version == matrix.matrix_version
            && receipt.source_commit == EXPECTED_SOURCE_COMMIT
            && receipt.source_commit == matrix.source_commit,
        "receipt is bound to an old or unknown schema/matrix source"
    );
    ensure!(
        receipt.matrix_digest == MATRIX_V2_SHA256
            && receipt.matrix_digest == matrix_digest
            && receipt_schema_digest == RECEIPT_SCHEMA_V2_SHA256,
        "receipt contract digest binding mismatch"
    );
    validate_digest(&receipt.matrix_digest, "matrixDigest")?;
    validate_digest(&receipt.case_definition_digest, "caseDefinitionDigest")?;
    validate_machine_token(&receipt.receipt_id, "receiptId")?;
    validate_machine_token(&receipt.run_id, "runId")?;
    ensure!(
        receipt.attempt_ordinal > 0,
        "attemptOrdinal must be positive"
    );
    ensure!(
        !receipt.test_mode
            && !receipt.mock
            && receipt.authority == crate::model::InventoryAuthority::PlatformInventoryOnly
            && receipt.release_decision == crate::model::ReleaseDecision::NotEvaluated,
        "mock/test/release-authority receipt is ineligible"
    );
    ensure!(
        receipt.receipt_kind != ReceiptKind::SourceAudit
            && receipt.status != PlatformStatus::NotImplemented,
        "v2 accepts native receipts only; source audit remains in v1 inventory"
    );
    Ok(())
}

fn validate_receipt_time_window(
    receipt: &PlatformReceipt,
    matrix: &PlatformMatrix,
) -> Result<(DateTime<chrono::FixedOffset>, DateTime<chrono::FixedOffset>)> {
    let started_at = parse_utc_rfc3339(&receipt.started_at, "receipt startedAt")?;
    let completed_at = parse_utc_rfc3339(&receipt.completed_at, "receipt completedAt")?;
    ensure!(
        started_at <= completed_at,
        "receipt time window is inverted"
    );
    let duration = completed_at.signed_duration_since(started_at).num_seconds();
    ensure!(
        duration >= 0
            && u64::try_from(duration).is_ok_and(|seconds| {
                seconds <= matrix.native_producer_policy.max_run_duration_seconds
            }),
        "receipt exceeds the maximum native run duration"
    );
    Ok((started_at, completed_at))
}

fn validate_challenge(
    receipt: &PlatformReceipt,
    matrix: &PlatformMatrix,
    started_at: DateTime<chrono::FixedOffset>,
    completed_at: DateTime<chrono::FixedOffset>,
) -> Result<()> {
    let challenge = &receipt.challenge_binding;
    validate_digest(&challenge.nonce_digest, "challenge nonceDigest")?;
    validate_digest(&challenge.issuer_digest, "challenge issuerDigest")?;
    let issued_at = parse_utc_rfc3339(&challenge.issued_at, "challenge issuedAt")?;
    let expires_at = parse_utc_rfc3339(&challenge.expires_at, "challenge expiresAt")?;
    ensure!(
        issued_at <= started_at && completed_at <= expires_at && issued_at < expires_at,
        "receipt is outside its challenge validity window"
    );
    let challenge_age = started_at.signed_duration_since(issued_at).num_seconds();
    ensure!(
        challenge_age >= 0
            && u64::try_from(challenge_age).is_ok_and(|seconds| {
                seconds <= matrix.native_producer_policy.max_challenge_age_seconds
            }),
        "challenge is stale"
    );
    Ok(())
}

fn validate_runner_authorization(
    receipt: &PlatformReceipt,
    matrix: &PlatformMatrix,
    started_at: DateTime<chrono::FixedOffset>,
    completed_at: DateTime<chrono::FixedOffset>,
) -> Result<()> {
    validate_native_admission(receipt.status, receipt.receipt_kind, matrix)?;
    let binding = &receipt.runner_binding;
    validate_machine_token(&binding.runner_id, "runnerId")?;
    for (value, label) in [
        (&binding.runner_identity_digest, "runnerIdentityDigest"),
        (&binding.registry_digest, "registryDigest"),
        (&binding.signing_key_digest, "signingKeyDigest"),
        (&binding.producer_binary_digest, "producerBinaryDigest"),
    ] {
        validate_digest(value, label)?;
    }
    ensure!(
        binding.registry_epoch == matrix.runner_registry_epoch
            && binding.registry_digest == matrix.runner_registry_digest,
        "runner binding registry epoch/digest mismatch"
    );
    let runner = matrix
        .allowed_runners
        .iter()
        .find(|runner| runner.runner_id == binding.runner_id)
        .context("receipt runner is unknown")?;
    ensure!(
        runner.runner_identity_digest == binding.runner_identity_digest
            && runner.registry_epoch == binding.registry_epoch
            && runner.signing_key_digest == binding.signing_key_digest
            && runner.signature_algorithm == binding.signature_algorithm
            && runner.producer_binary_digest == binding.producer_binary_digest
            && runner.allowed_receipt_kinds.contains(&receipt.receipt_kind)
            && runner.allowed_targets.contains(&receipt.target_id)
            && runner
                .allowed_host_identity_digests
                .contains(&receipt.actual_host.host_identity_digest),
        "runner registration does not authorize this receipt/target/host"
    );
    let valid_from = parse_utc_rfc3339(&runner.valid_from, "runner validFrom")?;
    let valid_until = parse_utc_rfc3339(&runner.valid_until, "runner validUntil")?;
    ensure!(
        valid_from <= started_at && completed_at < valid_until,
        "receipt is outside runner validity"
    );
    Ok(())
}

fn validate_native_admission(
    status: PlatformStatus,
    receipt_kind: ReceiptKind,
    matrix: &PlatformMatrix,
) -> Result<()> {
    ensure!(
        matches!(
            (status, receipt_kind),
            (
                PlatformStatus::Pass | PlatformStatus::Fail,
                ReceiptKind::NativeExecution
            ) | (PlatformStatus::BlockedEnv, ReceiptKind::NativePreflight)
        ),
        "receipt status/receiptKind combination is invalid"
    );
    ensure!(!matrix.allowed_runners.is_empty(), "RUNNER_REGISTRY_EMPTY");
    Ok(())
}

fn validate_actual_host(
    receipt: &PlatformReceipt,
    target: &PlatformTarget,
    matrix: &PlatformMatrix,
    started_at: DateTime<chrono::FixedOffset>,
) -> Result<()> {
    let host = &receipt.actual_host;
    ensure!(
        host.os == target.os && host.arch == target.arch,
        "cross-target native receipt is forbidden"
    );
    validate_digest(&host.os_build_digest, "actualHost osBuildDigest")?;
    validate_digest(&host.host_identity_digest, "actualHost hostIdentityDigest")?;
    validate_digest(&host.attestation_digest, "actualHost attestationDigest")?;
    let observed_at = parse_utc_rfc3339(&host.observed_at, "actualHost observedAt")?;
    let observation_age = started_at.signed_duration_since(observed_at).num_seconds();
    ensure!(
        observation_age >= 0
            && u64::try_from(observation_age).is_ok_and(|seconds| {
                seconds <= matrix.native_producer_policy.max_challenge_age_seconds
            }),
        "host attestation is stale or postdates execution"
    );
    validate_linked_evidence(
        receipt,
        &host.attestation_reference_id,
        &host.attestation_digest,
        EvidenceReferenceKind::HostAttestation,
        "actualHost",
    )
}

fn validate_production_binding(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
    matrix_validation: &MatrixValidation,
) -> Result<()> {
    let expected_component = case
        .production_component
        .as_deref()
        .context("implemented case lacks production component")?;
    let binding = &receipt.production_binding;
    validate_production_component(&binding.component)?;
    ensure!(
        binding.component == expected_component,
        "production component mismatch"
    );
    ensure!(
        binding.implementation_digest == matrix_validation.implementation_digest(&case.case_id)?,
        "implementationDigest does not match exact sourceCommit blobs"
    );
    for (value, label) in [
        (&binding.implementation_digest, "implementationDigest"),
        (&binding.executable_digest, "executableDigest"),
        (&binding.build_manifest_digest, "buildManifestDigest"),
        (
            &binding.binary_attestation_digest,
            "binaryAttestationDigest",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_linked_evidence(
        receipt,
        &binding.binary_attestation_reference_id,
        &binding.binary_attestation_digest,
        EvidenceReferenceKind::ProductionBinary,
        "production binary",
    )
}

fn validate_signature_envelope(receipt: &PlatformReceipt, matrix: &PlatformMatrix) -> Result<()> {
    let signature = &receipt.signature;
    ensure!(
        signature.algorithm == SignatureAlgorithm::Ed25519
            && signature.algorithm == receipt.runner_binding.signature_algorithm
            && signature.key_digest == receipt.runner_binding.signing_key_digest,
        "receipt signature key/algorithm binding mismatch"
    );
    validate_digest(&signature.key_digest, "signature keyDigest")?;
    validate_digest(&signature.signed_payload_digest, "signedPayloadDigest")?;
    validate_digest(&signature.signature_digest, "signatureDigest")?;
    let mut unsigned = serde_json::to_value(receipt).context("serializing signed receipt")?;
    unsigned
        .as_object_mut()
        .context("serialized receipt must be an object")?
        .remove("signature")
        .context("serialized receipt signature field missing")?;
    for field in ["artifacts", "evidenceReferences"] {
        unsigned
            .get_mut(field)
            .and_then(Value::as_array_mut)
            .with_context(|| format!("serialized receipt {field} must be an array"))?
            .retain(|entry| {
                entry.get("kind").and_then(Value::as_str) != Some("runner_signature_digest")
            });
    }
    ensure!(
        signature.signed_payload_digest
            == sha256_domain_canonical_json(
                &matrix.native_producer_policy.signature_payload_domain,
                &unsigned,
            )?,
        "signedPayloadDigest does not cover the canonical receipt envelope"
    );
    validate_digest_kind(
        receipt,
        EvidenceReferenceKind::ProducerBinary,
        &receipt.runner_binding.producer_binary_digest,
        "producer binary",
    )?;
    validate_linked_evidence(
        receipt,
        &signature.signature_reference_id,
        &signature.signature_digest,
        EvidenceReferenceKind::RunnerSignature,
        "runner signature",
    )
}

fn validate_receipt_common_safety(receipt: &PlatformReceipt) -> Result<()> {
    let qualifiers = &receipt.evidence_qualifiers;
    ensure!(
        !qualifiers.compile_only
            && !qualifiers.cross_compiled
            && !qualifiers.fake_host
            && !qualifiers.ignored_test
            && !qualifiers.mock_credential_store
            && !qualifiers.source_audit_only,
        "compile/cross/mock/ignored/source-audit evidence is ineligible"
    );
    validate_sorted_unique_assertions(&receipt.assertions)?;
    for assertion in &receipt.assertions {
        validate_linked_evidence(
            receipt,
            &assertion.evidence_reference_id,
            &assertion.evidence_digest,
            EvidenceReferenceKind::NativeExecution,
            "assertion",
        )?;
    }
    Ok(())
}

fn validate_status_semantics(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
) -> Result<()> {
    match receipt.status {
        PlatformStatus::Pass | PlatformStatus::Fail => {
            ensure!(
                receipt.receipt_kind == ReceiptKind::NativeExecution
                    && receipt.native_calls > 0
                    && receipt.execution_started
                    && receipt.platform_touched
                    && receipt.blocker.is_none(),
                "PASS/FAIL require native execution without blocker"
            );
            let assertion_ids = receipt
                .assertions
                .iter()
                .map(|assertion| assertion.id.as_str())
                .collect::<Vec<_>>();
            ensure!(
                assertion_ids
                    == case
                        .required_assertions
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                "native assertion set differs from the case definition"
            );
            let cleanup = receipt
                .cleanup
                .as_ref()
                .context("execution requires cleanup")?;
            validate_cleanup(receipt, cleanup)?;
            if receipt.status == PlatformStatus::Pass {
                ensure!(
                    receipt
                        .assertions
                        .iter()
                        .all(|assertion| assertion.outcome == AssertionOutcome::Pass)
                        && cleanup.succeeded
                        && cleanup.residue_count == 0
                        && !cleanup.deadline_exceeded
                        && cleanup.before_state_digest == cleanup.after_state_digest,
                    "PASS requires all assertions and zero-residue state restoration"
                );
            } else {
                ensure!(
                    receipt.assertions.iter().any(|assertion| {
                        matches!(
                            assertion.outcome,
                            AssertionOutcome::Fail | AssertionOutcome::Timeout
                        )
                    }) || !cleanup.succeeded
                        || cleanup.residue_count > 0
                        || cleanup.deadline_exceeded,
                    "FAIL requires a failed assertion, timeout, or cleanup failure"
                );
            }
        }
        PlatformStatus::BlockedEnv => {
            ensure!(
                receipt.receipt_kind == ReceiptKind::NativePreflight
                    && receipt.native_calls == 0
                    && !receipt.execution_started
                    && !receipt.platform_touched
                    && receipt.assertions.is_empty()
                    && receipt.cleanup.is_none(),
                "BLOCKED_ENV requires zero-call native preflight"
            );
            let blocker = receipt
                .blocker
                .as_ref()
                .context("BLOCKED_ENV requires blocker evidence")?;
            let current = case
                .current_blocker
                .as_ref()
                .context("implemented case lacks blocker contract")?;
            ensure!(
                blocker.code == current.code && case.allowed_blocker_codes.contains(&blocker.code),
                "blocker code is not allowed for this case"
            );
            validate_digest(&blocker.observation_digest, "blocker observationDigest")?;
            ensure!(
                blocker.observation_digest == blocker.evidence_digest,
                "blocker observation is not bound to native preflight evidence"
            );
            ensure!(
                blocker.exit_condition_digest == sha256_hex(current.exit_condition.as_bytes()),
                "blocker exit-condition digest mismatch"
            );
            validate_linked_evidence(
                receipt,
                &blocker.evidence_reference_id,
                &blocker.evidence_digest,
                EvidenceReferenceKind::NativePreflight,
                "blocker",
            )?;
        }
        PlatformStatus::NotImplemented => {
            bail!("NOT_IMPLEMENTED remains a source-audit inventory disposition")
        }
    }
    Ok(())
}

fn validate_cleanup(
    receipt: &PlatformReceipt,
    cleanup: &crate::model::CleanupEvidence,
) -> Result<()> {
    ensure!(
        cleanup.required && cleanup.attempted,
        "cleanup must be required and attempted"
    );
    validate_machine_token(&cleanup.resource_kind, "cleanup resourceKind")?;
    validate_digest(&cleanup.before_state_digest, "cleanup beforeStateDigest")?;
    validate_digest(&cleanup.after_state_digest, "cleanup afterStateDigest")?;
    validate_digest(&cleanup.evidence_digest, "cleanup evidenceDigest")?;
    validate_linked_evidence(
        receipt,
        &cleanup.evidence_reference_id,
        &cleanup.evidence_digest,
        EvidenceReferenceKind::Cleanup,
        "cleanup",
    )
}

fn validate_evidence_references(receipt: &PlatformReceipt, matrix: &PlatformMatrix) -> Result<()> {
    ensure!(
        !receipt.evidence_references.is_empty() && receipt.evidence_references.len() <= 32,
        "evidence-reference cardinality is invalid"
    );
    let mut prior = None;
    let mut kind_counts = BTreeMap::new();
    for reference in &receipt.evidence_references {
        validate_machine_token(&reference.reference_id, "evidence reference id")?;
        validate_machine_token(&reference.artifact_id, "evidence artifact id")?;
        validate_digest(&reference.digest, "evidence reference digest")?;
        if let Some(previous) = prior {
            ensure!(
                previous < reference.reference_id.as_str(),
                "evidence references must be sorted and unique"
            );
        }
        prior = Some(reference.reference_id.as_str());
        *kind_counts.entry(reference.kind).or_insert(0_usize) += 1;
        ensure!(
            reference.kind != EvidenceReferenceKind::SourceBinding,
            "source-audit evidence is ineligible for native v2 receipts"
        );
    }
    let required = match receipt.receipt_kind {
        ReceiptKind::NativePreflight => &matrix.native_producer_policy.preflight_evidence_kinds,
        ReceiptKind::NativeExecution => &matrix.native_producer_policy.execution_evidence_kinds,
        ReceiptKind::SourceAudit => bail!("source-audit receipt kind is ineligible in v2"),
    };
    ensure!(
        kind_counts.len() == required.len(),
        "native receipt has an extra evidence kind"
    );
    for kind in required {
        ensure!(
            kind_counts.get(kind) == Some(&1),
            "native receipt is missing or duplicates a required evidence kind"
        );
    }
    Ok(())
}

fn validate_digest_kind(
    receipt: &PlatformReceipt,
    expected_kind: EvidenceReferenceKind,
    expected_digest: &str,
    label: &str,
) -> Result<()> {
    let reference = receipt
        .evidence_references
        .iter()
        .find(|reference| reference.kind == expected_kind)
        .with_context(|| format!("{label} evidence reference is unresolved"))?;
    ensure!(
        reference.digest == expected_digest,
        "{label} evidence digest does not match its binding"
    );
    Ok(())
}

fn validate_artifact_graph(
    receipt: &PlatformReceipt,
    started_at: DateTime<chrono::FixedOffset>,
    completed_at: DateTime<chrono::FixedOffset>,
) -> Result<()> {
    ensure!(
        !receipt.artifacts.is_empty()
            && receipt.artifacts.len() <= 32
            && receipt.artifacts.len() == receipt.evidence_references.len(),
        "artifact/reference cardinality does not close"
    );
    let mut prior_id = None;
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_digests = BTreeSet::new();
    for artifact in &receipt.artifacts {
        validate_machine_token(&artifact.artifact_id, "artifactId")?;
        validate_digest(&artifact.digest, "artifact digest")?;
        ensure!(
            artifact.byte_count > 0 && artifact.byte_count <= 16_777_216,
            "artifact byteCount is outside the contract"
        );
        let produced_at = parse_utc_rfc3339(&artifact.produced_at, "artifact producedAt")?;
        ensure!(
            started_at <= produced_at && produced_at <= completed_at,
            "artifact timestamp is outside the receipt run"
        );
        validate_artifact_media_type(artifact.kind, &artifact.media_type)?;
        if let Some(previous) = prior_id {
            ensure!(
                previous < artifact.artifact_id.as_str(),
                "artifacts are not sorted/unique"
            );
        }
        prior_id = Some(artifact.artifact_id.as_str());
        ensure!(
            artifact_ids.insert(artifact.artifact_id.as_str()),
            "duplicate artifactId"
        );
        ensure!(
            artifact_digests.insert(artifact.digest.as_str()),
            "artifact digest is replayed across evidence kinds"
        );
    }
    let mut referenced = BTreeSet::new();
    for reference in &receipt.evidence_references {
        let artifact = receipt
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == reference.artifact_id)
            .context("evidence reference does not resolve to an artifact")?;
        ensure!(
            artifact.kind == reference.kind && artifact.digest == reference.digest,
            "evidence reference and artifact disagree"
        );
        ensure!(
            referenced.insert(reference.artifact_id.as_str()),
            "artifact reused by refs"
        );
    }
    ensure!(
        artifact_ids == referenced,
        "artifact/reference sets do not close"
    );
    Ok(())
}

fn validate_artifact_media_type(kind: EvidenceReferenceKind, media_type: &str) -> Result<()> {
    let expected = match kind {
        EvidenceReferenceKind::RunnerSignature => "application/hartevo-signature",
        EvidenceReferenceKind::HostAttestation
        | EvidenceReferenceKind::CodesignAttestation
        | EvidenceReferenceKind::ProducerBinary
        | EvidenceReferenceKind::ProductionBinary => "application/hartevo-attestation+json",
        EvidenceReferenceKind::NativePreflight
        | EvidenceReferenceKind::NativeExecution
        | EvidenceReferenceKind::Cleanup => "application/hartevo-evidence+json",
        EvidenceReferenceKind::SourceBinding => bail!("source binding artifact is not native"),
    };
    ensure!(
        media_type == expected,
        "artifact mediaType does not match its kind"
    );
    Ok(())
}

fn validate_linked_evidence(
    receipt: &PlatformReceipt,
    reference_id: &str,
    expected_digest: &str,
    expected_kind: EvidenceReferenceKind,
    label: &str,
) -> Result<()> {
    validate_machine_token(reference_id, label)?;
    let reference = receipt
        .evidence_references
        .iter()
        .find(|reference| reference.reference_id == reference_id)
        .with_context(|| format!("{label} evidence reference is unresolved"))?;
    ensure!(
        reference.kind == expected_kind && reference.digest == expected_digest,
        "{label} evidence reference has the wrong kind or digest"
    );
    Ok(())
}

fn validate_sorted_unique_assertions(assertions: &[crate::model::AssertionEvidence]) -> Result<()> {
    ensure!(assertions.len() <= 64, "assertion cardinality is invalid");
    let mut prior = None;
    for assertion in assertions {
        validate_machine_token(&assertion.id, "assertion id")?;
        validate_machine_token(&assertion.evidence_reference_id, "assertion evidence ref")?;
        validate_digest(&assertion.evidence_digest, "assertion evidenceDigest")?;
        if let Some(previous) = prior {
            ensure!(
                previous < assertion.id.as_str(),
                "assertion ids are not sorted/unique"
            );
        }
        prior = Some(assertion.id.as_str());
    }
    Ok(())
}

fn parse_utc_rfc3339(value: &str, label: &str) -> Result<DateTime<chrono::FixedOffset>> {
    ensure!(value.ends_with('Z'), "{label} must use UTC Z");
    let parsed = DateTime::parse_from_rfc3339(value).with_context(|| format!("{label} invalid"))?;
    ensure!(
        parsed.offset().local_minus_utc() == 0,
        "{label} must be UTC"
    );
    Ok(parsed)
}

fn validate_sorted_unique_tokens(values: &[String], label: &str) -> Result<()> {
    let mut prior = None;
    for value in values {
        validate_machine_token(value, label)?;
        if let Some(previous) = prior {
            ensure!(
                previous < value.as_str(),
                "{label} must be sorted and unique"
            );
        }
        prior = Some(value.as_str());
    }
    Ok(())
}

fn validate_sorted_unique_blocker_codes(values: &[String], label: &str) -> Result<()> {
    let mut prior = None;
    for value in values {
        validate_blocker_code(value)?;
        if let Some(previous) = prior {
            ensure!(
                previous < value.as_str(),
                "{label} must be sorted and unique"
            );
        }
        prior = Some(value.as_str());
    }
    Ok(())
}

fn validate_exact_string_list(actual: &[String], expected: &[&str], label: &str) -> Result<()> {
    ensure!(
        actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()),
        "{label} is not the exact canonical list"
    );
    Ok(())
}

fn validate_exact_object_keys<'a>(
    actual: impl Iterator<Item = &'a str>,
    expected: &[&str],
    label: &str,
) -> Result<()> {
    let actual = actual.collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "{label} contains missing or unknown fields"
    );
    Ok(())
}

fn validate_machine_token(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_lowercase()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-' | b'.')
            }),
        "{label} is not a canonical machine token"
    );
    Ok(())
}

fn validate_blocker_code(value: &str) -> Result<()> {
    ensure!(
        value.len() >= 3
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_uppercase()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        "blocker code is not canonical"
    );
    Ok(())
}

fn validate_bounded_text(value: &str, max_len: usize, label: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max_len && !value.chars().any(char::is_control),
        "{label} is empty, oversized, or contains control characters"
    );
    Ok(())
}

fn validate_production_component(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            }),
        "production component is not canonical"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        is_lower_hex(value, 32),
        "{label} is not a lowercase SHA-256 digest"
    );
    Ok(())
}

fn object_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a serde_json::Map<String, Value>> {
    value
        .pointer(pointer)
        .and_then(Value::as_object)
        .with_context(|| format!("schema pointer {pointer} is not an object"))
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("schema pointer {pointer} is not a string"))
}

fn bool_at(value: &Value, pointer: &str) -> Result<Option<bool>> {
    value
        .pointer(pointer)
        .map(|value| {
            value
                .as_bool()
                .with_context(|| format!("schema pointer {pointer} is not a boolean"))
        })
        .transpose()
}

fn string_array_at(value: &Value, pointer: &str) -> Result<Vec<String>> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .with_context(|| format!("schema pointer {pointer} is not an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(ToOwned::to_owned)
                .with_context(|| format!("schema pointer {pointer} contains a non-string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::{
        EXPECTED_SOURCE_COMMIT, MATRIX_V2_SHA256, RECEIPT_SCHEMA_V2_SHA256, case_definition_digest,
        parse_utc_rfc3339, validate_content_free_receipt_json, validate_matrix,
        validate_matrix_raw, validate_native_admission, validate_receipt_schema,
        validate_v2_schema_shape,
    };
    use crate::digest::sha256_hex;
    use crate::model::{PlatformMatrix, PlatformStatus, ReceiptKind, parse_strict_json};

    const MATRIX: &[u8] = include_bytes!("../../../../contracts/platform/matrix.v2.json");
    const RECEIPT_SCHEMA: &[u8] =
        include_bytes!("../../../../contracts/platform/receipt.schema.v2.json");

    fn repository_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn matrix() -> PlatformMatrix {
        parse_strict_json::<PlatformMatrix>(MATRIX).expect("strict v2 matrix")
    }

    #[test]
    fn committed_contracts_validate_as_zero_pass_inventory() {
        let matrix = matrix();
        let schema = parse_strict_json::<Value>(RECEIPT_SCHEMA).expect("strict v2 schema");
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        validate_receipt_schema(&schema, RECEIPT_SCHEMA, &matrix).expect("schema contract");

        assert_eq!(matrix.source_commit, EXPECTED_SOURCE_COMMIT);
        assert_eq!(matrix.allowed_runners.len(), 0);
        assert_eq!(matrix.runner_registry_epoch, 0);
        assert_eq!(matrix.native_receipt_count, 0);
        assert_eq!(matrix.readiness_blockers.len(), 3);
        assert_eq!(validation.counts.pass, 0);
        assert_eq!(validation.counts.fail, 0);
        assert_eq!(validation.counts.blocked_env, 16);
        assert_eq!(validation.counts.not_implemented, 25);
        assert_eq!(
            matrix
                .cases
                .iter()
                .map(|case| case.source_bindings.len())
                .sum::<usize>(),
            47
        );
    }

    #[test]
    fn schema_raw_digest_is_compiled_matrix_and_runtime_bound() {
        let matrix = matrix();
        let bytes = fs::read(repository_root().join("contracts/platform/receipt.schema.v2.json"))
            .expect("read raw v2 schema");
        assert_eq!(sha256_hex(&bytes), RECEIPT_SCHEMA_V2_SHA256);
        assert_eq!(matrix.receipt_schema_sha256, RECEIPT_SCHEMA_V2_SHA256);
        let schema = parse_strict_json::<Value>(&bytes).expect("strict v2 schema");
        validate_receipt_schema(&schema, &bytes, &matrix).expect("three-way schema binding");
    }

    #[test]
    fn matrix_raw_digest_is_compiled_and_runtime_bound() {
        assert_eq!(sha256_hex(MATRIX), MATRIX_V2_SHA256);
        validate_matrix_raw(MATRIX).expect("raw v2 matrix binding");

        let mut mutation = MATRIX.to_vec();
        let offset = mutation
            .windows(b"contract_only_fail_closed".len())
            .position(|window| window == b"contract_only_fail_closed")
            .expect("policy marker");
        mutation[offset] = b'C';
        parse_strict_json::<Value>(&mutation).expect("mutation remains valid JSON");
        validate_matrix_raw(&mutation).expect_err("matrix byte drift must fail closed");
    }

    #[test]
    fn every_valid_json_schema_mutation_fails_the_raw_digest_gate() {
        let matrix = matrix();
        let baseline = parse_strict_json::<Value>(RECEIPT_SCHEMA).expect("strict schema");
        let mut mutations = Vec::new();

        let mut then_required = baseline.clone();
        then_required["allOf"][0]["then"]["required"] = json!([]);
        mutations.push(("then.required", then_required));

        let mut forbidden = baseline.clone();
        forbidden["allOf"][2]["then"]["not"] = json!({});
        mutations.push(("forbidden", forbidden));

        let mut definition = baseline.clone();
        definition["$defs"]["cleanup"]["additionalProperties"] = json!(true);
        mutations.push(("definition", definition));

        let mut enumeration = baseline.clone();
        enumeration["$defs"]["evidenceReference"]["properties"]["kind"]["enum"] =
            json!(["native_execution_digest"]);
        mutations.push(("evidence enum", enumeration));

        let mut constant = baseline.clone();
        constant["properties"]["authority"]["const"] = json!("release_authority");
        mutations.push(("authority const", constant));

        let mut root_closure = baseline;
        root_closure["additionalProperties"] = json!(true);
        mutations.push(("root closure", root_closure));

        for (label, mutation) in mutations {
            let bytes = serde_json::to_vec(&mutation).expect("serialize valid JSON mutation");
            let error = validate_receipt_schema(&mutation, &bytes, &matrix)
                .expect_err("schema byte drift must fail closed");
            assert!(
                error.to_string().contains("raw digest/URI"),
                "{label} reached the wrong gate: {error}"
            );
        }
    }

    #[test]
    fn schema_shape_smoke_rejects_structural_drift_independently() {
        let baseline = parse_strict_json::<Value>(RECEIPT_SCHEMA).expect("strict schema");

        let mut root_required = baseline.clone();
        root_required["required"] = json!(["schemaVersion"]);
        validate_v2_schema_shape(&root_required).expect_err("required-set drift must fail");

        let mut status = baseline.clone();
        status["properties"]["status"]["enum"] = json!(["PASS"]);
        validate_v2_schema_shape(&status).expect_err("status enum drift must fail");

        let mut definition = baseline;
        definition["$defs"]["actualHost"]["additionalProperties"] = json!(true);
        validate_v2_schema_shape(&definition).expect_err("definition closure drift must fail");
    }

    #[test]
    fn synchronized_aggregate_edit_cannot_upgrade_a_case() {
        let mut matrix = matrix();
        matrix.cases[0].source_audit_disposition = PlatformStatus::Pass;
        matrix.source_audit_disposition_counts.pass = 1;
        matrix.source_audit_disposition_counts.blocked_env = 15;
        let error = validate_matrix(&matrix, &repository_root())
            .expect_err("hard-coded case classification must reject upgrade");
        assert!(error.to_string().contains("cannot be upgraded"));
    }

    #[test]
    fn worktree_only_source_binding_cannot_satisfy_source_commit() {
        let mut matrix = matrix();
        let worktree_only = "contracts/platform/matrix.v2.json";
        assert!(repository_root().join(worktree_only).is_file());
        matrix.cases[0].source_bindings[0].path = worktree_only.to_owned();
        matrix.cases[0].source_bindings[0].mode = "100644".to_owned();
        matrix.cases[0].source_bindings[0].blob_sha256 = "aa".repeat(32);
        matrix.cases[0].source_bindings[0].byte_count = 1;
        let error = validate_matrix(&matrix, &repository_root())
            .expect_err("worktree fallback must be impossible");
        assert!(error.to_string().contains("Git tree entry"));
    }

    #[test]
    fn source_binding_mode_blob_and_size_drift_fail_closed() {
        for field in ["mode", "blobSha256", "byteCount"] {
            let mut matrix = matrix();
            match field {
                "mode" => matrix.cases[0].source_bindings[0].mode = "100755".to_owned(),
                "blobSha256" => matrix.cases[0].source_bindings[0].blob_sha256 = "bb".repeat(32),
                "byteCount" => matrix.cases[0].source_bindings[0].byte_count += 1,
                _ => unreachable!(),
            }
            let error = validate_matrix(&matrix, &repository_root())
                .expect_err("sourceCommit binding drift must fail");
            assert!(
                error.to_string().contains("metadata disagrees"),
                "{field} drift reached the wrong gate: {error}"
            );
        }
    }

    #[test]
    fn implementation_digest_is_git_derived_and_case_domain_separated() {
        let matrix = matrix();
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        let first = matrix
            .cases
            .iter()
            .find(|case| case.case_id == "I-01.macos-aarch64.auth.reauth_refusal")
            .expect("first case");
        let second = matrix
            .cases
            .iter()
            .find(|case| case.case_id == "I-01.macos-x86_64.auth.reauth_refusal")
            .expect("second case");
        assert_eq!(
            first.source_bindings[0].path,
            second.source_bindings[0].path
        );
        assert_eq!(
            first.source_bindings[0].blob_sha256,
            second.source_bindings[0].blob_sha256
        );
        assert_eq!(
            first.source_bindings[0].mode,
            second.source_bindings[0].mode
        );
        assert_eq!(
            first.source_bindings[0].byte_count,
            second.source_bindings[0].byte_count
        );
        assert_ne!(
            validation
                .implementation_digest(&first.case_id)
                .expect("first digest"),
            validation
                .implementation_digest(&second.case_id)
                .expect("second digest")
        );
        assert_ne!(
            case_definition_digest(&matrix, first).expect("first case digest"),
            case_definition_digest(&matrix, second).expect("second case digest")
        );
    }

    #[test]
    fn empty_runner_registry_rejects_all_native_statuses() {
        let matrix = matrix();
        for (status, kind) in [
            (PlatformStatus::Pass, ReceiptKind::NativeExecution),
            (PlatformStatus::Fail, ReceiptKind::NativeExecution),
            (PlatformStatus::BlockedEnv, ReceiptKind::NativePreflight),
        ] {
            let error = validate_native_admission(status, kind, &matrix)
                .expect_err("empty registry must reject every native receipt");
            assert_eq!(error.to_string(), "RUNNER_REGISTRY_EMPTY");
        }
    }

    #[test]
    fn non_native_or_mismatched_status_kind_is_rejected_before_registry() {
        let matrix = matrix();
        for (status, kind) in [
            (PlatformStatus::Pass, ReceiptKind::NativePreflight),
            (PlatformStatus::BlockedEnv, ReceiptKind::NativeExecution),
            (PlatformStatus::NotImplemented, ReceiptKind::SourceAudit),
        ] {
            let error = validate_native_admission(status, kind, &matrix)
                .expect_err("status/kind pairing must fail closed");
            assert!(error.to_string().contains("combination is invalid"));
        }
    }

    #[test]
    fn producer_policy_cannot_enable_native_admission() {
        let mut emission = matrix();
        emission
            .native_producer_policy
            .native_receipt_emission_allowed = true;
        validate_matrix(&emission, &repository_root()).expect_err("emission must remain disabled");

        let mut signature = matrix();
        signature
            .native_producer_policy
            .signature_verifier_available = true;
        validate_matrix(&signature, &repository_root())
            .expect_err("signature verification cannot be self-reported");

        let mut host = matrix();
        host.native_producer_policy
            .host_attestation_verifier_available = true;
        validate_matrix(&host, &repository_root())
            .expect_err("host verification cannot be self-reported");

        let mut registry = matrix();
        registry.runner_registry_digest = "cc".repeat(32);
        validate_matrix(&registry, &repository_root())
            .expect_err("registry digest drift must fail closed");
    }

    #[test]
    fn content_free_scan_rejects_secrets_identity_and_private_paths() {
        for value in [
            json!({"cookie": "redacted"}),
            json!({"username": "redacted"}),
            json!({"profilePath": "redacted"}),
            json!({"digest": "/Users/private/Library/Application Support/Google/Chrome"}),
            json!({"digest": "C:\\Users\\private\\Chrome"}),
            json!({"digest": "\\\\server\\private"}),
        ] {
            validate_content_free_receipt_json(&value)
                .expect_err("sensitive or host-private material must fail closed");
        }
        validate_content_free_receipt_json(&json!({"identityDigest": "dd".repeat(32)}))
            .expect("stable digest is content-free");
    }

    #[test]
    fn receipt_times_require_strict_utc_rfc3339() {
        parse_utc_rfc3339("2026-08-13T00:00:00Z", "timestamp").expect("UTC timestamp");
        parse_utc_rfc3339("2026-08-13T08:00:00+08:00", "timestamp")
            .expect_err("offset timestamp must fail");
        parse_utc_rfc3339("2026-08-13 00:00:00", "timestamp")
            .expect_err("non-RFC3339 timestamp must fail");
    }
}
