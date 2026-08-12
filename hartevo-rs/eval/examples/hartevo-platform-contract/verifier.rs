use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use chrono::DateTime;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::digest::{is_lower_hex, sha256_hex, sha256_json};
use crate::model::{
    Architecture, AssertionOutcome, CaseDefinitionDigestMaterial, DispositionCounts, EvidenceMode,
    EvidenceReferenceKind, EvidenceRequirement, ImplementationState, MissingReceiptDisposition,
    OperatingSystem, PlatformMatrix, PlatformReceipt, PlatformStatus, PlatformTarget, ReceiptKind,
    SupportClass,
};

pub const EXPECTED_SOURCE_COMMIT: &str = "8cfd62150e95eccef2bffa4ba1bc0ea49bf4f4f6";
pub const EXPECTED_MATRIX_SCHEMA_VERSION: &str = "hartevo-platform-matrix/v1";
pub const EXPECTED_MATRIX_VERSION: &str = "i-01a-platform-matrix/2026-08-13-v1";
pub const EXPECTED_RECEIPT_SCHEMA_VERSION: &str = "hartevo-platform-receipt/v1";
pub const RECEIPT_SCHEMA_V1_URI: &str =
    "https://hartevo.local/contracts/platform/receipt.schema.v1.json";
pub const RECEIPT_SCHEMA_V1_SHA256: &str =
    "846b556dbd4f0da1a2e51ac905ecf2f7bac5aa8bb62793f5f723bb116644a2af";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-platform-contract-validation/v1";
pub const INVENTORY_AUTHORITY: &str = "platform_inventory_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const EXPECTED_REPOSITORY_ID: &str = "tangpingqingwa/hartevo-desktop";

const EXPECTED_BLOCKED_ENV_COUNT: usize = 16;
const EXPECTED_NOT_IMPLEMENTED_COUNT: usize = 25;
const IMPLEMENTATION_DIGEST_DOMAIN: &[u8] = b"hartevo-platform-implementation-digest/v1";

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

struct ExpectedStatusRule<'a> {
    status: &'a str,
    kind: &'a str,
    implementation: &'a str,
    touched: bool,
    required: &'a [&'a str],
    forbidden: &'a [&'a str],
    properties: &'a [&'a str],
    qualifier_ref: &'a str,
    assertion_limit_keyword: &'a str,
    assertion_limit: u64,
    has_fail_condition: bool,
    has_pass_cleanup_constraint: bool,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptValidationSummary {
    pub case_id: String,
    pub status: &'static str,
    pub receipt_kind: &'static str,
    pub receipt_digest: String,
}

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
        matrix.receipt_schema_uri == RECEIPT_SCHEMA_V1_URI
            && matrix.receipt_schema_sha256 == RECEIPT_SCHEMA_V1_SHA256,
        "platform matrix receipt schema binding changed"
    );
    ensure!(
        is_lower_hex(&matrix.source_commit, 20) && matrix.source_commit == EXPECTED_SOURCE_COMMIT,
        "platform matrix sourceCommit is not the published integration baseline"
    );
    validate_git_commit(repository_root, &matrix.source_commit)?;
    ensure!(
        matrix.evidence_mode == EvidenceMode::SourceAuditBaseline,
        "I-01A must remain a source-audit baseline"
    );
    ensure!(
        !matrix.release_eligible,
        "source inventory cannot be release eligible"
    );
    ensure!(
        matrix.native_receipt_count == 0,
        "I-01A cannot claim native receipts"
    );
    ensure!(
        matrix.allowed_runners.is_empty(),
        "I-01A has no approved native or source-audit receipt runner"
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
        "I-01A must remain 0 PASS / 0 FAIL / 16 BLOCKED_ENV / 25 NOT_IMPLEMENTED"
    );
    Ok(MatrixValidation {
        counts: recomputed,
        implementation_digests,
    })
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
                == "https://hartevo.local/contracts/platform/receipt.schema.v1.json"
            && string_at(schema, "/type")? == "object"
            && bool_at(schema, "/additionalProperties")? == Some(false),
        "receipt schema identity or closed-object boundary changed"
    );
    ensure!(
        string_at(schema, "/properties/schemaVersion/const")? == EXPECTED_RECEIPT_SCHEMA_VERSION,
        "receipt schemaVersion constant changed"
    );
    validate_schema_property_sets(schema)?;
    validate_schema_status_rules(schema)?;
    ensure!(
        string_at(schema, "/x-hartevo-policy/authority")? == INVENTORY_AUTHORITY
            && bool_at(schema, "/x-hartevo-policy/nativeReceiptWriter")? == Some(false)
            && bool_at(schema, "/x-hartevo-policy/callerAggregatesAccepted")? == Some(false)
            && string_at(schema, "/x-hartevo-policy/releaseDecision")? == RELEASE_DECISION
            && bool_at(schema, "/x-hartevo-policy/sensitiveMaterialAllowed")? == Some(false),
        "receipt schema inventory-only authority changed"
    );
    Ok(())
}

pub fn validate_receipt_schema_raw(raw_schema: &[u8], matrix: &PlatformMatrix) -> Result<()> {
    let raw_digest = sha256_hex(raw_schema);
    ensure!(
        raw_digest == RECEIPT_SCHEMA_V1_SHA256
            && matrix.receipt_schema_sha256 == RECEIPT_SCHEMA_V1_SHA256
            && matrix.receipt_schema_uri == RECEIPT_SCHEMA_V1_URI,
        "receipt schema raw digest/URI binding changed"
    );
    std::str::from_utf8(raw_schema).context("receipt schema raw bytes must be UTF-8")?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_schema_property_sets(schema: &Value) -> Result<()> {
    let required = string_array_at(schema, "/required")?;
    validate_exact_string_list(
        &required,
        &[
            "schemaVersion",
            "matrixVersion",
            "sourceCommit",
            "matrixDigest",
            "caseDefinitionDigest",
            "caseId",
            "targetId",
            "target",
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
            "evidenceQualifiers",
            "artifacts",
            "evidenceReferences",
            "assertions",
        ],
        "receipt schema required fields",
    )?;
    let properties = object_at(schema, "/properties")?;
    validate_exact_object_keys(
        properties.keys().map(String::as_str),
        &[
            "actualHost",
            "artifacts",
            "assertions",
            "authority",
            "blocker",
            "caseDefinitionDigest",
            "caseId",
            "cleanup",
            "completedAt",
            "evidenceQualifiers",
            "evidenceReferences",
            "implementationState",
            "matrixDigest",
            "matrixVersion",
            "missingGates",
            "mock",
            "nativeCalls",
            "executionStarted",
            "startedAt",
            "platformTouched",
            "productionBinding",
            "receiptKind",
            "releaseDecision",
            "runnerBinding",
            "schemaVersion",
            "sourceCommit",
            "status",
            "target",
            "targetId",
            "testMode",
        ],
        "receipt schema properties",
    )?;
    let definitions = object_at(schema, "/$defs")?;
    validate_exact_object_keys(
        definitions.keys().map(String::as_str),
        &[
            "assertion",
            "blocker",
            "caseId",
            "cleanup",
            "evidenceArtifact",
            "evidenceQualifiers",
            "evidenceReference",
            "nativeEvidenceQualifiers",
            "productionBinding",
            "runnerBinding",
            "sha256",
            "sourceAuditEvidenceQualifiers",
            "targetId",
            "targetTuple",
            "token",
        ],
        "receipt schema definitions",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/properties/status/enum")?,
        &["PASS", "FAIL", "BLOCKED_ENV", "NOT_IMPLEMENTED"],
        "receipt status enum",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/properties/receiptKind/enum")?,
        &["source_audit", "native_preflight", "native_execution"],
        "receipt kind enum",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/$defs/targetId/enum")?,
        &[
            "macos-aarch64",
            "macos-x86_64",
            "windows-aarch64",
            "windows-x86_64",
            "linux-x86_64",
        ],
        "receipt target enum",
    )?;
    validate_schema_definitions(schema)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_schema_definitions(schema: &Value) -> Result<()> {
    validate_closed_schema_object(schema, "/$defs/targetTuple", &["os", "arch"])?;
    validate_closed_schema_object(
        schema,
        "/$defs/runnerBinding",
        &["runnerId", "runnerDigest"],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/productionBinding",
        &["component", "implementationDigest"],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/evidenceQualifiers",
        &[
            "compileOnly",
            "crossCompiled",
            "fakeHost",
            "ignoredTest",
            "mockCredentialStore",
            "sourceAuditOnly",
        ],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/evidenceArtifact",
        &["artifactId", "kind", "digest"],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/evidenceReference",
        &["referenceId", "kind", "artifactId", "digest"],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/assertion",
        &["id", "outcome", "evidenceReferenceId", "evidenceDigest"],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/cleanup",
        &[
            "required",
            "attempted",
            "succeeded",
            "evidenceReferenceId",
            "evidenceDigest",
        ],
    )?;
    validate_closed_schema_object(
        schema,
        "/$defs/blocker",
        &[
            "code",
            "evidenceReferenceId",
            "exitConditionDigest",
            "evidenceDigest",
        ],
    )?;

    validate_exact_schema_leaf(schema, "/$defs/sha256", &["pattern", "type"])?;
    ensure!(
        string_at(schema, "/$defs/sha256/type")? == "string"
            && string_at(schema, "/$defs/sha256/pattern")? == "^[0-9a-f]{64}$",
        "sha256 definition changed"
    );
    validate_exact_schema_leaf(schema, "/$defs/token", &["pattern", "type"])?;
    ensure!(
        string_at(schema, "/$defs/token/type")? == "string"
            && string_at(schema, "/$defs/token/pattern")? == "^[a-z][a-z0-9_.-]{0,127}$",
        "token definition changed"
    );
    validate_exact_schema_leaf(schema, "/$defs/caseId", &["maxLength", "pattern", "type"])?;
    ensure!(
        string_at(schema, "/$defs/caseId/type")? == "string"
            && string_at(schema, "/$defs/caseId/pattern")?
                == "^I-01\\.[a-z0-9_-]+\\.[a-z][a-z0-9_.-]+$"
            && u64_at(schema, "/$defs/caseId/maxLength")? == 192,
        "caseId definition changed"
    );
    validate_exact_schema_leaf(schema, "/$defs/targetId", &["enum"])?;

    validate_exact_string_list(
        &string_array_at(schema, "/$defs/targetTuple/properties/os/enum")?,
        &["macos", "windows", "linux"],
        "target os enum",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/$defs/targetTuple/properties/arch/enum")?,
        &["aarch64", "x86_64"],
        "target arch enum",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/runnerBinding/properties/runnerId",
        "#/$defs/token",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/runnerBinding/properties/runnerDigest",
        "#/$defs/sha256",
    )?;
    validate_exact_schema_leaf(
        schema,
        "/$defs/productionBinding/properties/component",
        &["pattern", "type"],
    )?;
    ensure!(
        string_at(schema, "/$defs/productionBinding/properties/component/type")? == "string"
            && string_at(
                schema,
                "/$defs/productionBinding/properties/component/pattern"
            )? == "^[A-Za-z0-9_.:-]{1,160}$",
        "production component definition changed"
    );
    validate_schema_ref(
        schema,
        "/$defs/productionBinding/properties/implementationDigest",
        "#/$defs/sha256",
    )?;

    for qualifier in [
        "compileOnly",
        "crossCompiled",
        "fakeHost",
        "ignoredTest",
        "mockCredentialStore",
        "sourceAuditOnly",
    ] {
        let pointer = format!("/$defs/evidenceQualifiers/properties/{qualifier}");
        validate_exact_schema_leaf(schema, &pointer, &["type"])?;
        ensure!(
            string_at(schema, &format!("{pointer}/type"))? == "boolean",
            "evidence qualifier type changed"
        );
    }
    validate_qualifier_overlay(schema, "/$defs/nativeEvidenceQualifiers", false)?;
    validate_qualifier_overlay(schema, "/$defs/sourceAuditEvidenceQualifiers", true)?;

    let evidence_kinds = [
        "source_binding_digest",
        "native_preflight_digest",
        "native_execution_digest",
        "host_attestation_digest",
        "codesign_attestation_digest",
        "cleanup_digest",
    ];
    validate_schema_ref(
        schema,
        "/$defs/evidenceArtifact/properties/artifactId",
        "#/$defs/token",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/$defs/evidenceArtifact/properties/kind/enum")?,
        &evidence_kinds,
        "artifact evidence kind enum",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/evidenceArtifact/properties/digest",
        "#/$defs/sha256",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/evidenceReference/properties/referenceId",
        "#/$defs/token",
    )?;
    validate_exact_string_list(
        &string_array_at(schema, "/$defs/evidenceReference/properties/kind/enum")?,
        &evidence_kinds,
        "reference evidence kind enum",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/evidenceReference/properties/artifactId",
        "#/$defs/token",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/evidenceReference/properties/digest",
        "#/$defs/sha256",
    )?;
    validate_schema_ref(schema, "/$defs/assertion/properties/id", "#/$defs/token")?;
    validate_exact_string_list(
        &string_array_at(schema, "/$defs/assertion/properties/outcome/enum")?,
        &["PASS", "FAIL", "TIMEOUT"],
        "assertion outcome enum",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/assertion/properties/evidenceReferenceId",
        "#/$defs/token",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/assertion/properties/evidenceDigest",
        "#/$defs/sha256",
    )?;
    ensure!(
        bool_at(schema, "/$defs/cleanup/properties/required/const")? == Some(true)
            && bool_at(schema, "/$defs/cleanup/properties/attempted/const")? == Some(true)
            && string_at(schema, "/$defs/cleanup/properties/succeeded/type")? == "boolean",
        "cleanup definition changed"
    );
    validate_schema_ref(
        schema,
        "/$defs/cleanup/properties/evidenceReferenceId",
        "#/$defs/token",
    )?;
    validate_schema_ref(
        schema,
        "/$defs/cleanup/properties/evidenceDigest",
        "#/$defs/sha256",
    )?;
    validate_exact_schema_leaf(
        schema,
        "/$defs/blocker/properties/code",
        &["pattern", "type"],
    )?;
    ensure!(
        string_at(schema, "/$defs/blocker/properties/code/type")? == "string"
            && string_at(schema, "/$defs/blocker/properties/code/pattern")?
                == "^[A-Z][A-Z0-9_]{2,127}$",
        "blocker code definition changed"
    );
    for field in [
        "evidenceReferenceId",
        "exitConditionDigest",
        "evidenceDigest",
    ] {
        let expected = if field == "evidenceReferenceId" {
            "#/$defs/token"
        } else {
            "#/$defs/sha256"
        };
        validate_schema_ref(
            schema,
            &format!("/$defs/blocker/properties/{field}"),
            expected,
        )?;
    }
    Ok(())
}

fn validate_closed_schema_object(
    schema: &Value,
    pointer: &str,
    expected_properties: &[&str],
) -> Result<()> {
    let definition = object_at(schema, pointer)?;
    validate_exact_object_keys(
        definition.keys().map(String::as_str),
        &["additionalProperties", "properties", "required", "type"],
        pointer,
    )?;
    ensure!(
        string_at(schema, &format!("{pointer}/type"))? == "object"
            && bool_at(schema, &format!("{pointer}/additionalProperties"))? == Some(false),
        "{pointer} must remain a closed object"
    );
    validate_exact_string_list(
        &string_array_at(schema, &format!("{pointer}/required"))?,
        expected_properties,
        pointer,
    )?;
    validate_exact_object_keys(
        object_at(schema, &format!("{pointer}/properties"))?
            .keys()
            .map(String::as_str),
        expected_properties,
        pointer,
    )?;
    Ok(())
}

fn validate_exact_schema_leaf(schema: &Value, pointer: &str, keys: &[&str]) -> Result<()> {
    validate_exact_object_keys(
        object_at(schema, pointer)?.keys().map(String::as_str),
        keys,
        pointer,
    )
}

fn validate_schema_ref(schema: &Value, pointer: &str, expected: &str) -> Result<()> {
    validate_exact_schema_leaf(schema, pointer, &["$ref"])?;
    ensure!(
        string_at(schema, &format!("{pointer}/$ref"))? == expected,
        "schema reference changed at {pointer}"
    );
    Ok(())
}

fn validate_qualifier_overlay(schema: &Value, pointer: &str, source_audit: bool) -> Result<()> {
    validate_exact_schema_leaf(schema, pointer, &["allOf"])?;
    let all_of = schema
        .pointer(&format!("{pointer}/allOf"))
        .and_then(Value::as_array)
        .context("qualifier overlay allOf must be an array")?;
    ensure!(
        all_of.len() == 2,
        "qualifier overlay must have two exact clauses"
    );
    validate_exact_object_keys(
        all_of[0]
            .as_object()
            .context("qualifier base clause must be an object")?
            .keys()
            .map(String::as_str),
        &["$ref"],
        "qualifier base clause",
    )?;
    ensure!(
        string_at(&all_of[0], "/$ref")? == "#/$defs/evidenceQualifiers",
        "qualifier base reference changed"
    );
    validate_exact_schema_leaf(&all_of[1], "", &["properties"])?;
    let properties = object_at(&all_of[1], "/properties")?;
    let names = [
        "compileOnly",
        "crossCompiled",
        "fakeHost",
        "ignoredTest",
        "mockCredentialStore",
        "sourceAuditOnly",
    ];
    validate_exact_object_keys(
        properties.keys().map(String::as_str),
        &names,
        "qualifier overlay properties",
    )?;
    for name in names {
        validate_exact_schema_leaf(&all_of[1], &format!("/properties/{name}"), &["const"])?;
        let expected = source_audit && name == "sourceAuditOnly";
        ensure!(
            bool_at(&all_of[1], &format!("/properties/{name}/const"))? == Some(expected),
            "qualifier overlay constant changed"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_schema_status_rules(schema: &Value) -> Result<()> {
    let rules = schema
        .pointer("/allOf")
        .and_then(Value::as_array)
        .context("receipt schema allOf must be an array")?;
    ensure!(rules.len() == 4, "receipt schema needs four status rules");
    let expected = [
        ExpectedStatusRule {
            status: "PASS",
            kind: "native_execution",
            implementation: "IMPLEMENTED",
            touched: true,
            required: &[
                "actualHost",
                "runnerBinding",
                "productionBinding",
                "cleanup",
            ],
            forbidden: &["blocker", "missingGates"],
            properties: &[
                "receiptKind",
                "implementationState",
                "nativeCalls",
                "platformTouched",
                "executionStarted",
                "evidenceQualifiers",
                "assertions",
                "cleanup",
            ],
            qualifier_ref: "#/$defs/nativeEvidenceQualifiers",
            assertion_limit_keyword: "minItems",
            assertion_limit: 1,
            has_fail_condition: false,
            has_pass_cleanup_constraint: true,
        },
        ExpectedStatusRule {
            status: "FAIL",
            kind: "native_execution",
            implementation: "IMPLEMENTED",
            touched: true,
            required: &[
                "actualHost",
                "runnerBinding",
                "productionBinding",
                "cleanup",
            ],
            forbidden: &["blocker", "missingGates"],
            properties: &[
                "receiptKind",
                "implementationState",
                "nativeCalls",
                "platformTouched",
                "executionStarted",
                "evidenceQualifiers",
                "assertions",
            ],
            qualifier_ref: "#/$defs/nativeEvidenceQualifiers",
            assertion_limit_keyword: "minItems",
            assertion_limit: 1,
            has_fail_condition: true,
            has_pass_cleanup_constraint: false,
        },
        ExpectedStatusRule {
            status: "BLOCKED_ENV",
            kind: "native_preflight",
            implementation: "IMPLEMENTED",
            touched: false,
            required: &[
                "actualHost",
                "runnerBinding",
                "productionBinding",
                "blocker",
            ],
            forbidden: &["cleanup", "missingGates"],
            properties: &[
                "receiptKind",
                "implementationState",
                "nativeCalls",
                "platformTouched",
                "executionStarted",
                "evidenceQualifiers",
                "assertions",
            ],
            qualifier_ref: "#/$defs/nativeEvidenceQualifiers",
            assertion_limit_keyword: "maxItems",
            assertion_limit: 0,
            has_fail_condition: false,
            has_pass_cleanup_constraint: false,
        },
        ExpectedStatusRule {
            status: "NOT_IMPLEMENTED",
            kind: "source_audit",
            implementation: "NOT_IMPLEMENTED",
            touched: false,
            required: &["missingGates"],
            forbidden: &[
                "actualHost",
                "runnerBinding",
                "productionBinding",
                "cleanup",
                "blocker",
            ],
            properties: &[
                "receiptKind",
                "implementationState",
                "nativeCalls",
                "platformTouched",
                "executionStarted",
                "evidenceQualifiers",
                "assertions",
            ],
            qualifier_ref: "#/$defs/sourceAuditEvidenceQualifiers",
            assertion_limit_keyword: "maxItems",
            assertion_limit: 0,
            has_fail_condition: false,
            has_pass_cleanup_constraint: false,
        },
    ];
    for (rule, expected) in rules.iter().zip(expected) {
        validate_exact_object_keys(
            rule.as_object()
                .context("receipt status rule must be an object")?
                .keys()
                .map(String::as_str),
            &["if", "then"],
            "receipt status rule",
        )?;
        validate_exact_object_keys(
            object_at(rule, "/if")?.keys().map(String::as_str),
            &["properties", "required"],
            "receipt status if rule",
        )?;
        validate_exact_string_list(
            &string_array_at(rule, "/if/required")?,
            &["status"],
            "receipt status discriminator requirement",
        )?;
        validate_exact_object_keys(
            object_at(rule, "/if/properties")?
                .keys()
                .map(String::as_str),
            &["status"],
            "receipt status discriminator properties",
        )?;
        let expected_then_keys = if expected.has_fail_condition {
            &["anyOf", "not", "properties", "required"][..]
        } else {
            &["not", "properties", "required"][..]
        };
        validate_exact_object_keys(
            object_at(rule, "/then")?.keys().map(String::as_str),
            expected_then_keys,
            "receipt status then rule",
        )?;
        validate_exact_string_list(
            &string_array_at(rule, "/then/required")?,
            expected.required,
            "receipt status required fields",
        )?;
        validate_status_forbidden_fields(rule, expected.forbidden)?;
        validate_exact_object_keys(
            object_at(rule, "/then/properties")?
                .keys()
                .map(String::as_str),
            expected.properties,
            "receipt status properties",
        )?;
        ensure!(
            string_at(rule, "/if/properties/status/const")? == expected.status
                && string_at(rule, "/then/properties/receiptKind/const")? == expected.kind
                && string_at(rule, "/then/properties/implementationState/const")?
                    == expected.implementation
                && bool_at(rule, "/then/properties/platformTouched/const")?
                    == Some(expected.touched)
                && bool_at(rule, "/then/properties/executionStarted/const")?
                    == Some(expected.touched)
                && string_at(rule, "/then/properties/evidenceQualifiers/$ref")?
                    == expected.qualifier_ref,
            "receipt status rule is incomplete or incompatible"
        );
        if matches!(expected.status, "PASS" | "FAIL") {
            ensure!(
                string_at(rule, "/then/properties/nativeCalls/type")? == "integer"
                    && u64_at(rule, "/then/properties/nativeCalls/minimum")? == 1,
                "native execution call cardinality changed"
            );
        } else {
            ensure!(
                u64_at(rule, "/then/properties/nativeCalls/const")? == 0,
                "zero-call status cardinality changed"
            );
        }
        ensure!(
            u64_at(
                rule,
                &format!(
                    "/then/properties/assertions/{}",
                    expected.assertion_limit_keyword
                ),
            )? == expected.assertion_limit,
            "status assertion cardinality changed"
        );
        if expected.has_pass_cleanup_constraint {
            validate_pass_schema_constraints(rule)?;
        }
        if expected.has_fail_condition {
            validate_fail_schema_condition(rule)?;
        }
    }
    Ok(())
}

fn validate_status_forbidden_fields(rule: &Value, expected: &[&str]) -> Result<()> {
    validate_exact_object_keys(
        object_at(rule, "/then/not")?.keys().map(String::as_str),
        &["anyOf"],
        "status forbidden field clause",
    )?;
    let any_of = rule
        .pointer("/then/not/anyOf")
        .and_then(Value::as_array)
        .context("status forbidden field anyOf must be an array")?;
    let mut actual = Vec::with_capacity(any_of.len());
    for clause in any_of {
        validate_exact_object_keys(
            clause
                .as_object()
                .context("forbidden field clause must be an object")?
                .keys()
                .map(String::as_str),
            &["required"],
            "forbidden field clause",
        )?;
        let required = string_array_at(clause, "/required")?;
        ensure!(
            required.len() == 1,
            "forbidden field clause must name one field"
        );
        actual.push(required[0].clone());
    }
    validate_exact_string_list(&actual, expected, "status forbidden fields")
}

fn validate_pass_schema_constraints(rule: &Value) -> Result<()> {
    validate_exact_object_keys(
        object_at(rule, "/then/properties/assertions")?
            .keys()
            .map(String::as_str),
        &["items", "minItems"],
        "PASS assertion rule",
    )?;
    validate_exact_object_keys(
        object_at(rule, "/then/properties/assertions/items")?
            .keys()
            .map(String::as_str),
        &["properties", "required"],
        "PASS assertion item rule",
    )?;
    validate_exact_string_list(
        &string_array_at(rule, "/then/properties/assertions/items/required")?,
        &["outcome"],
        "PASS assertion required fields",
    )?;
    ensure!(
        string_at(
            rule,
            "/then/properties/assertions/items/properties/outcome/const",
        )? == "PASS",
        "PASS assertion outcome constraint changed"
    );
    let cleanup = rule
        .pointer("/then/properties/cleanup/allOf")
        .and_then(Value::as_array)
        .context("PASS cleanup allOf must be an array")?;
    ensure!(
        cleanup.len() == 2,
        "PASS cleanup requires two exact clauses"
    );
    validate_exact_object_keys(
        cleanup[0]
            .as_object()
            .context("PASS cleanup base must be an object")?
            .keys()
            .map(String::as_str),
        &["$ref"],
        "PASS cleanup base",
    )?;
    ensure!(
        string_at(&cleanup[0], "/$ref")? == "#/$defs/cleanup"
            && bool_at(&cleanup[1], "/properties/succeeded/const")? == Some(true),
        "PASS cleanup constraint changed"
    );
    Ok(())
}

fn validate_fail_schema_condition(rule: &Value) -> Result<()> {
    let conditions = rule
        .pointer("/then/anyOf")
        .and_then(Value::as_array)
        .context("FAIL condition anyOf must be an array")?;
    ensure!(
        conditions.len() == 2,
        "FAIL needs two exact failure alternatives"
    );
    validate_exact_string_list(
        &string_array_at(&conditions[0], "/required")?,
        &["assertions"],
        "FAIL assertion alternative requirement",
    )?;
    validate_exact_string_list(
        &string_array_at(&conditions[0], "/properties/assertions/contains/required")?,
        &["outcome"],
        "FAIL outcome requirement",
    )?;
    validate_exact_string_list(
        &string_array_at(
            &conditions[0],
            "/properties/assertions/contains/properties/outcome/enum",
        )?,
        &["FAIL", "TIMEOUT"],
        "FAIL outcome enum",
    )?;
    validate_exact_string_list(
        &string_array_at(&conditions[1], "/required")?,
        &["cleanup"],
        "FAIL cleanup alternative requirement",
    )?;
    validate_exact_string_list(
        &string_array_at(&conditions[1], "/properties/cleanup/required")?,
        &["succeeded"],
        "FAIL cleanup result requirement",
    )?;
    ensure!(
        bool_at(
            &conditions[1],
            "/properties/cleanup/properties/succeeded/const",
        )? == Some(false),
        "FAIL cleanup alternative changed"
    );
    Ok(())
}

pub fn validate_receipt(
    receipt: &PlatformReceipt,
    receipt_bytes: &[u8],
    matrix: &PlatformMatrix,
    matrix_validation: &MatrixValidation,
    matrix_digest: &str,
    receipt_schema_digest: &str,
) -> Result<ReceiptValidationSummary> {
    ensure!(
        receipt.schema_version == EXPECTED_RECEIPT_SCHEMA_VERSION,
        "receipt schemaVersion mismatch"
    );
    ensure!(
        receipt.matrix_version == matrix.matrix_version
            && receipt.source_commit == EXPECTED_SOURCE_COMMIT
            && receipt.source_commit == matrix.source_commit,
        "receipt is bound to an old or unknown matrix source"
    );
    ensure!(
        receipt.matrix_digest == matrix_digest,
        "receipt matrix digest mismatch"
    );
    ensure!(
        receipt_schema_digest == RECEIPT_SCHEMA_V1_SHA256,
        "internal receipt schema digest is invalid"
    );
    ensure!(
        !receipt.test_mode && !receipt.mock,
        "testMode or mock receipts cannot enter the platform inventory"
    );

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
        receipt.target_id == target.id
            && receipt.target.os == target.os
            && receipt.target.arch == target.arch,
        "receipt targetId and target tuple do not close over the matrix target"
    );
    ensure!(
        receipt.case_definition_digest == case_definition_digest(matrix, case)?,
        "receipt case-definition digest mismatch"
    );
    ensure!(
        receipt.implementation_state == case.implementation_state,
        "receipt implementation state disagrees with the matrix"
    );
    validate_digest(&receipt.matrix_digest, "matrixDigest")?;
    validate_digest(&receipt.case_definition_digest, "caseDefinitionDigest")?;
    if receipt.receipt_kind != ReceiptKind::SourceAudit {
        validate_actual_host(receipt, target, true)?;
        validate_production_binding(receipt, case, matrix_validation)?;
    }
    let (started_at, completed_at) = validate_receipt_time_window(receipt)?;
    validate_runner(receipt, matrix, started_at, completed_at)?;
    validate_artifact_graph(receipt)?;
    validate_evidence_references(receipt)?;
    validate_receipt_common_safety(receipt)?;

    match receipt.status {
        PlatformStatus::Pass => {
            validate_pass(receipt, case, target, matrix_validation)?;
        }
        PlatformStatus::Fail => {
            validate_fail(receipt, case, target, matrix_validation)?;
        }
        PlatformStatus::BlockedEnv => {
            validate_blocked_receipt(receipt, case, target, matrix_validation)?;
        }
        PlatformStatus::NotImplemented => {
            validate_missing_receipt(receipt, case)?;
        }
    }

    Ok(ReceiptValidationSummary {
        case_id: receipt.case_id.clone(),
        status: receipt.status.as_str(),
        receipt_kind: receipt.receipt_kind.as_str(),
        receipt_digest: crate::digest::sha256_hex(receipt_bytes),
    })
}

fn validate_runner(
    receipt: &PlatformReceipt,
    matrix: &PlatformMatrix,
    started_at: DateTime<chrono::FixedOffset>,
    completed_at: DateTime<chrono::FixedOffset>,
) -> Result<()> {
    if receipt.receipt_kind == ReceiptKind::SourceAudit {
        ensure!(
            receipt.runner_binding.is_none(),
            "source-audit inventory must not fabricate a runner binding"
        );
        return Ok(());
    }
    let binding = receipt
        .runner_binding
        .as_ref()
        .context("native receipt requires runnerBinding")?;
    validate_machine_token(&binding.runner_id, "runnerId")?;
    validate_digest(&binding.runner_digest, "runnerDigest")?;
    let runner = matrix
        .allowed_runners
        .iter()
        .find(|runner| runner.runner_id == binding.runner_id)
        .context("receipt runner is unknown")?;
    ensure!(
        runner.runner_digest == binding.runner_digest,
        "receipt runner digest mismatch"
    );
    ensure!(
        runner.allowed_receipt_kinds.contains(&receipt.receipt_kind),
        "runner is not authorized for this receipt kind"
    );
    let valid_from = parse_utc_rfc3339(&runner.valid_from, "runner validFrom")?;
    ensure!(started_at >= valid_from, "receipt predates runner validity");
    if let Some(valid_until) = runner.valid_until.as_deref() {
        let valid_until = parse_utc_rfc3339(valid_until, "runner validUntil")?;
        ensure!(
            completed_at < valid_until,
            "receipt runner is expired before completion"
        );
    }
    Ok(())
}

fn validate_receipt_time_window(
    receipt: &PlatformReceipt,
) -> Result<(DateTime<chrono::FixedOffset>, DateTime<chrono::FixedOffset>)> {
    let started_at = parse_utc_rfc3339(&receipt.started_at, "receipt startedAt")?;
    let completed_at = parse_utc_rfc3339(&receipt.completed_at, "receipt completedAt")?;
    ensure!(
        started_at <= completed_at,
        "receipt startedAt must not follow completedAt"
    );
    Ok((started_at, completed_at))
}

fn parse_utc_rfc3339(value: &str, label: &str) -> Result<DateTime<chrono::FixedOffset>> {
    ensure!(
        value.ends_with('Z'),
        "{label} must use an explicit UTC Z suffix"
    );
    let parsed =
        DateTime::parse_from_rfc3339(value).with_context(|| format!("{label} is invalid"))?;
    ensure!(
        parsed.offset().local_minus_utc() == 0,
        "{label} must be UTC"
    );
    Ok(parsed)
}

fn validate_receipt_common_safety(receipt: &PlatformReceipt) -> Result<()> {
    let qualifiers = &receipt.evidence_qualifiers;
    ensure!(
        !qualifiers.compile_only
            && !qualifiers.cross_compiled
            && !qualifiers.fake_host
            && !qualifiers.ignored_test
            && !qualifiers.mock_credential_store,
        "compile, cross-compile, fake, ignored, or mock evidence is ineligible"
    );
    ensure!(
        qualifiers.source_audit_only == (receipt.receipt_kind == ReceiptKind::SourceAudit),
        "sourceAuditOnly must match receiptKind"
    );
    ensure!(
        receipt.authority == crate::model::InventoryAuthority::PlatformInventoryOnly
            && receipt.release_decision == crate::model::ReleaseDecision::NotEvaluated,
        "receipt cannot claim release authority"
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
    if let Some(binding) = &receipt.production_binding {
        validate_production_component(&binding.component)?;
        validate_digest(&binding.implementation_digest, "implementationDigest")?;
    }
    if let Some(cleanup) = &receipt.cleanup {
        validate_digest(&cleanup.evidence_digest, "cleanup evidenceDigest")?;
        validate_linked_evidence(
            receipt,
            &cleanup.evidence_reference_id,
            &cleanup.evidence_digest,
            EvidenceReferenceKind::Cleanup,
            "cleanup",
        )?;
    }
    if let Some(blocker) = &receipt.blocker {
        validate_blocker_code(&blocker.code)?;
        validate_digest(&blocker.evidence_digest, "blocker evidenceDigest")?;
        validate_digest(
            &blocker.exit_condition_digest,
            "blocker exitConditionDigest",
        )?;
    }
    if let Some(missing_gates) = &receipt.missing_gates {
        ensure!(
            !missing_gates.is_empty() && missing_gates.len() <= 32,
            "receipt missingGates cardinality is invalid"
        );
        validate_sorted_unique_tokens(missing_gates, "receipt missingGates")?;
    }
    Ok(())
}

fn validate_pass(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
    target: &PlatformTarget,
    matrix_validation: &MatrixValidation,
) -> Result<()> {
    validate_native_execution_base(receipt, case, target, matrix_validation)?;
    ensure!(
        receipt
            .assertions
            .iter()
            .all(|assertion| assertion.outcome == AssertionOutcome::Pass),
        "PASS receipt contains a failed or timed-out assertion"
    );
    let cleanup = receipt.cleanup.as_ref().context("PASS requires cleanup")?;
    ensure!(
        cleanup.required && cleanup.attempted && cleanup.succeeded,
        "PASS requires successful cleanup"
    );
    Ok(())
}

fn validate_fail(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
    target: &PlatformTarget,
    matrix_validation: &MatrixValidation,
) -> Result<()> {
    validate_native_execution_base(receipt, case, target, matrix_validation)?;
    let cleanup = receipt
        .cleanup
        .as_ref()
        .context("FAIL requires cleanup evidence")?;
    ensure!(
        cleanup.required && cleanup.attempted,
        "FAIL must attempt required cleanup"
    );
    ensure!(
        receipt.assertions.iter().any(|assertion| {
            matches!(
                assertion.outcome,
                AssertionOutcome::Fail | AssertionOutcome::Timeout
            )
        }) || !cleanup.succeeded,
        "FAIL needs a failed/timed-out assertion or failed cleanup"
    );
    Ok(())
}

fn validate_native_execution_base(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
    target: &PlatformTarget,
    matrix_validation: &MatrixValidation,
) -> Result<()> {
    ensure!(
        case.implementation_state == ImplementationState::Implemented
            && receipt.receipt_kind == ReceiptKind::NativeExecution
            && receipt.native_calls > 0
            && receipt.execution_started
            && receipt.platform_touched,
        "PASS/FAIL require an implemented native execution"
    );
    validate_actual_host(receipt, target, true)?;
    validate_production_binding(receipt, case, matrix_validation)?;
    ensure!(
        receipt.blocker.is_none() && receipt.missing_gates.is_none(),
        "native execution cannot carry blocker or missing-gate fields"
    );
    let assertion_ids = receipt
        .assertions
        .iter()
        .map(|assertion| assertion.id.as_str())
        .collect::<Vec<_>>();
    let required_ids = case
        .required_assertions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    ensure!(
        assertion_ids == required_ids,
        "native receipt assertion set does not match the case definition"
    );
    ensure!(
        receipt.cleanup.is_some(),
        "native execution requires cleanup"
    );
    Ok(())
}

fn validate_blocked_receipt(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
    target: &PlatformTarget,
    matrix_validation: &MatrixValidation,
) -> Result<()> {
    ensure!(
        case.implementation_state == ImplementationState::Implemented
            && receipt.receipt_kind == ReceiptKind::NativePreflight
            && receipt.native_calls == 0
            && !receipt.execution_started
            && !receipt.platform_touched,
        "BLOCKED_ENV requires a zero-call native preflight on implemented code"
    );
    validate_actual_host(receipt, target, true)?;
    validate_production_binding(receipt, case, matrix_validation)?;
    ensure!(
        receipt.assertions.is_empty()
            && receipt.cleanup.is_none()
            && receipt.missing_gates.is_none(),
        "BLOCKED_ENV cannot carry execution assertions, cleanup, or missing gates"
    );
    let blocker = receipt
        .blocker
        .as_ref()
        .context("BLOCKED_ENV requires blocker evidence")?;
    let current_blocker = case
        .current_blocker
        .as_ref()
        .context("BLOCKED_ENV case lacks a current blocker contract")?;
    ensure!(
        case.allowed_blocker_codes.contains(&blocker.code) && blocker.code == current_blocker.code,
        "BLOCKED_ENV code is not allowed for this case"
    );
    ensure!(
        blocker.exit_condition_digest
            == crate::digest::sha256_hex(current_blocker.exit_condition.as_bytes()),
        "BLOCKED_ENV exit-condition digest mismatch"
    );
    validate_linked_evidence(
        receipt,
        &blocker.evidence_reference_id,
        &blocker.evidence_digest,
        EvidenceReferenceKind::NativePreflight,
        "blocker",
    )?;
    Ok(())
}

fn validate_missing_receipt(
    receipt: &PlatformReceipt,
    case: &crate::model::MatrixCase,
) -> Result<()> {
    ensure!(
        case.implementation_state == ImplementationState::NotImplemented
            && receipt.receipt_kind == ReceiptKind::SourceAudit
            && receipt.native_calls == 0
            && !receipt.execution_started
            && !receipt.platform_touched,
        "NOT_IMPLEMENTED requires a zero-call source audit"
    );
    ensure!(
        receipt.actual_host.is_none()
            && receipt.runner_binding.is_none()
            && receipt.production_binding.is_none()
            && receipt.assertions.is_empty()
            && receipt.cleanup.is_none()
            && receipt.blocker.is_none(),
        "NOT_IMPLEMENTED cannot carry native execution fields"
    );
    ensure!(
        receipt.missing_gates.as_ref() == Some(&case.missing_gates),
        "NOT_IMPLEMENTED missing gates do not match the case definition"
    );
    ensure!(
        receipt
            .evidence_references
            .iter()
            .all(|reference| reference.kind == EvidenceReferenceKind::SourceBinding),
        "source audit accepts only source-binding evidence digests"
    );
    let receipt_digests = receipt
        .evidence_references
        .iter()
        .map(|reference| reference.digest.as_str())
        .collect::<BTreeSet<_>>();
    let committed_binding_digests = case
        .source_bindings
        .iter()
        .map(|binding| binding.blob_sha256.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        receipt_digests == committed_binding_digests
            && receipt.evidence_references.len() == case.source_bindings.len(),
        "source-audit evidence must be the exact sourceCommit binding blob set"
    );
    Ok(())
}

fn validate_actual_host(
    receipt: &PlatformReceipt,
    target: &PlatformTarget,
    required: bool,
) -> Result<()> {
    let Some(actual_host) = receipt.actual_host.as_ref() else {
        ensure!(!required, "native execution requires actualHost");
        return Ok(());
    };
    ensure!(
        actual_host.os == target.os && actual_host.arch == target.arch,
        "cross-target native receipt is forbidden"
    );
    Ok(())
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
    let binding = receipt
        .production_binding
        .as_ref()
        .context("implemented receipt lacks production binding")?;
    ensure!(
        binding.component == expected_component,
        "receipt production component mismatch"
    );
    ensure!(
        binding.implementation_digest == matrix_validation.implementation_digest(&case.case_id)?,
        "receipt implementationDigest does not match the exact sourceCommit blobs"
    );
    Ok(())
}

fn validate_evidence_references(receipt: &PlatformReceipt) -> Result<()> {
    ensure!(
        !receipt.evidence_references.is_empty() && receipt.evidence_references.len() <= 32,
        "receipt evidence-reference cardinality is invalid"
    );
    let mut prior = None;
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
    }
    match receipt.receipt_kind {
        ReceiptKind::SourceAudit => ensure!(
            receipt
                .evidence_references
                .iter()
                .any(|reference| reference.kind == EvidenceReferenceKind::SourceBinding),
            "source audit needs source-binding evidence"
        ),
        ReceiptKind::NativePreflight => ensure!(
            receipt
                .evidence_references
                .iter()
                .any(|reference| reference.kind == EvidenceReferenceKind::NativePreflight)
                && receipt
                    .evidence_references
                    .iter()
                    .any(|reference| reference.kind == EvidenceReferenceKind::HostAttestation),
            "native preflight needs preflight and host-attestation evidence"
        ),
        ReceiptKind::NativeExecution => ensure!(
            receipt
                .evidence_references
                .iter()
                .any(|reference| reference.kind == EvidenceReferenceKind::NativeExecution)
                && receipt
                    .evidence_references
                    .iter()
                    .any(|reference| reference.kind == EvidenceReferenceKind::Cleanup)
                && receipt
                    .evidence_references
                    .iter()
                    .any(|reference| reference.kind == EvidenceReferenceKind::HostAttestation),
            "native execution needs execution, cleanup, and host-attestation evidence"
        ),
    }
    Ok(())
}

fn validate_artifact_graph(receipt: &PlatformReceipt) -> Result<()> {
    ensure!(
        !receipt.artifacts.is_empty() && receipt.artifacts.len() <= 32,
        "receipt artifact cardinality is invalid"
    );
    ensure!(
        receipt.artifacts.len() == receipt.evidence_references.len(),
        "every evidence artifact must resolve through exactly one reference"
    );
    let mut prior_id = None;
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_digests = BTreeSet::new();
    for artifact in &receipt.artifacts {
        validate_machine_token(&artifact.artifact_id, "artifactId")?;
        validate_digest(&artifact.digest, "artifact digest")?;
        if let Some(previous) = prior_id {
            ensure!(
                previous < artifact.artifact_id.as_str(),
                "artifacts must be sorted and unique"
            );
        }
        prior_id = Some(artifact.artifact_id.as_str());
        ensure!(
            artifact_ids.insert(artifact.artifact_id.as_str()),
            "duplicate artifactId"
        );
        ensure!(
            artifact_digests.insert(artifact.digest.as_str()),
            "artifact digest cannot be replayed across evidence kinds"
        );
    }
    let mut referenced_artifacts = BTreeSet::new();
    for reference in &receipt.evidence_references {
        let artifact = receipt
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == reference.artifact_id)
            .context("evidence reference does not resolve to an artifact")?;
        ensure!(
            artifact.kind == reference.kind && artifact.digest == reference.digest,
            "evidence reference kind or digest disagrees with its artifact"
        );
        ensure!(
            referenced_artifacts.insert(reference.artifact_id.as_str()),
            "multiple evidence references resolve to one artifact"
        );
    }
    ensure!(
        artifact_ids == referenced_artifacts,
        "artifact and evidence-reference sets do not close"
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
        validate_machine_token(
            &assertion.evidence_reference_id,
            "assertion evidence reference id",
        )?;
        validate_digest(&assertion.evidence_digest, "assertion evidenceDigest")?;
        if let Some(previous) = prior {
            ensure!(
                previous < assertion.id.as_str(),
                "assertion ids must be sorted and unique"
            );
        }
        prior = Some(assertion.id.as_str());
    }
    Ok(())
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

fn u64_at(value: &Value, pointer: &str) -> Result<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .with_context(|| format!("schema pointer {pointer} is not an unsigned integer"))
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
        RECEIPT_SCHEMA_V1_SHA256, case_definition_digest, validate_actual_host,
        validate_blocked_receipt, validate_matrix, validate_missing_receipt,
        validate_native_execution_base, validate_pass, validate_production_binding,
        validate_receipt, validate_receipt_schema, validate_schema_property_sets,
        validate_schema_status_rules,
    };
    use crate::digest::sha256_hex;
    use crate::model::{PlatformMatrix, PlatformReceipt, PlatformStatus, parse_strict_json};

    const MATRIX: &[u8] = include_bytes!("../../../../contracts/platform/matrix.v1.json");
    const RECEIPT_SCHEMA: &[u8] =
        include_bytes!("../../../../contracts/platform/receipt.schema.v1.json");

    fn repository_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn matrix() -> PlatformMatrix {
        parse_strict_json::<PlatformMatrix>(MATRIX).expect("strict matrix")
    }

    fn parse_receipt(value: &Value) -> (PlatformReceipt, Vec<u8>) {
        let bytes = serde_json::to_vec(value).expect("serialize receipt fixture");
        let receipt = parse_strict_json::<PlatformReceipt>(&bytes).expect("strict receipt fixture");
        (receipt, bytes)
    }

    fn common_qualifiers(source_audit_only: bool) -> Value {
        json!({
            "compileOnly": false,
            "crossCompiled": false,
            "fakeHost": false,
            "ignoredTest": false,
            "mockCredentialStore": false,
            "sourceAuditOnly": source_audit_only,
        })
    }

    fn native_receipt(
        matrix: &PlatformMatrix,
        validation: &super::MatrixValidation,
        status: PlatformStatus,
    ) -> (PlatformReceipt, Vec<u8>) {
        let case = &matrix.cases[0];
        let target = &matrix.targets[0];
        let implementation_digest = validation
            .implementation_digest(&case.case_id)
            .expect("implementation digest");
        let execution = matches!(status, PlatformStatus::Pass | PlatformStatus::Fail);
        let (receipt_kind, native_calls) = if execution {
            ("native_execution", 1)
        } else {
            ("native_preflight", 0)
        };
        let mut value = json!({
            "schemaVersion": "hartevo-platform-receipt/v1",
            "matrixVersion": matrix.matrix_version,
            "sourceCommit": matrix.source_commit,
            "matrixDigest": sha256_hex(MATRIX),
            "caseDefinitionDigest": case_definition_digest(matrix, case).expect("case digest"),
            "caseId": case.case_id,
            "targetId": target.id,
            "target": { "os": target.os, "arch": target.arch },
            "actualHost": { "os": target.os, "arch": target.arch },
            "status": status,
            "receiptKind": receipt_kind,
            "implementationState": "IMPLEMENTED",
            "authority": "platform_inventory_only",
            "nativeCalls": native_calls,
            "releaseDecision": "NOT_EVALUATED",
            "testMode": false,
            "mock": false,
            "startedAt": "2026-08-13T00:00:00Z",
            "completedAt": "2026-08-13T00:00:01Z",
            "executionStarted": execution,
            "platformTouched": execution,
            "runnerBinding": {
                "runnerId": "runner_01",
                "runnerDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "productionBinding": {
                "component": case.production_component.as_deref().expect("production component"),
                "implementationDigest": implementation_digest,
            },
            "evidenceQualifiers": common_qualifiers(false),
            "artifacts": [],
            "evidenceReferences": [],
            "assertions": [],
        });
        if execution {
            value["artifacts"] = json!([
                {
                    "artifactId": "artifact_cleanup",
                    "kind": "cleanup_digest",
                    "digest": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                {
                    "artifactId": "artifact_execution",
                    "kind": "native_execution_digest",
                    "digest": "2222222222222222222222222222222222222222222222222222222222222222"
                },
                {
                    "artifactId": "artifact_host",
                    "kind": "host_attestation_digest",
                    "digest": "3333333333333333333333333333333333333333333333333333333333333333"
                }
            ]);
            value["evidenceReferences"] = json!([
                {
                    "referenceId": "reference_cleanup",
                    "kind": "cleanup_digest",
                    "artifactId": "artifact_cleanup",
                    "digest": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                {
                    "referenceId": "reference_execution",
                    "kind": "native_execution_digest",
                    "artifactId": "artifact_execution",
                    "digest": "2222222222222222222222222222222222222222222222222222222222222222"
                },
                {
                    "referenceId": "reference_host",
                    "kind": "host_attestation_digest",
                    "artifactId": "artifact_host",
                    "digest": "3333333333333333333333333333333333333333333333333333333333333333"
                }
            ]);
            value["assertions"] = Value::Array(
                case.required_assertions
                    .iter()
                    .enumerate()
                    .map(|(index, assertion_id)| {
                        json!({
                            "id": assertion_id,
                            "outcome": if status == PlatformStatus::Fail && index == 0 {
                                "FAIL"
                            } else {
                                "PASS"
                            },
                            "evidenceReferenceId": "reference_execution",
                            "evidenceDigest": "2222222222222222222222222222222222222222222222222222222222222222"
                        })
                    })
                    .collect(),
            );
            value["cleanup"] = json!({
                "required": true,
                "attempted": true,
                "succeeded": true,
                "evidenceReferenceId": "reference_cleanup",
                "evidenceDigest": "1111111111111111111111111111111111111111111111111111111111111111"
            });
        } else {
            let blocker = case.current_blocker.as_ref().expect("blocked case blocker");
            value["artifacts"] = json!([
                {
                    "artifactId": "artifact_host",
                    "kind": "host_attestation_digest",
                    "digest": "3333333333333333333333333333333333333333333333333333333333333333"
                },
                {
                    "artifactId": "artifact_preflight",
                    "kind": "native_preflight_digest",
                    "digest": "4444444444444444444444444444444444444444444444444444444444444444"
                }
            ]);
            value["evidenceReferences"] = json!([
                {
                    "referenceId": "reference_host",
                    "kind": "host_attestation_digest",
                    "artifactId": "artifact_host",
                    "digest": "3333333333333333333333333333333333333333333333333333333333333333"
                },
                {
                    "referenceId": "reference_preflight",
                    "kind": "native_preflight_digest",
                    "artifactId": "artifact_preflight",
                    "digest": "4444444444444444444444444444444444444444444444444444444444444444"
                }
            ]);
            value["blocker"] = json!({
                "code": blocker.code,
                "evidenceReferenceId": "reference_preflight",
                "evidenceDigest": "4444444444444444444444444444444444444444444444444444444444444444",
                "exitConditionDigest": sha256_hex(blocker.exit_condition.as_bytes())
            });
        }
        parse_receipt(&value)
    }

    fn source_audit_receipt(matrix: &PlatformMatrix) -> (PlatformReceipt, Vec<u8>) {
        let case = matrix
            .cases
            .iter()
            .find(|case| case.capability_id == "auth.account_identity")
            .expect("source-audit case");
        let target = matrix
            .targets
            .iter()
            .find(|target| target.id == case.target_id)
            .expect("source-audit target");
        let artifacts = case
            .source_bindings
            .iter()
            .enumerate()
            .map(|(index, binding)| {
                json!({
                    "artifactId": format!("artifact_{index:02}"),
                    "kind": "source_binding_digest",
                    "digest": binding.blob_sha256,
                })
            })
            .collect::<Vec<_>>();
        let references = case
            .source_bindings
            .iter()
            .enumerate()
            .map(|(index, binding)| {
                json!({
                    "referenceId": format!("reference_{index:02}"),
                    "kind": "source_binding_digest",
                    "artifactId": format!("artifact_{index:02}"),
                    "digest": binding.blob_sha256,
                })
            })
            .collect::<Vec<_>>();
        parse_receipt(&json!({
            "schemaVersion": "hartevo-platform-receipt/v1",
            "matrixVersion": matrix.matrix_version,
            "sourceCommit": matrix.source_commit,
            "matrixDigest": sha256_hex(MATRIX),
            "caseDefinitionDigest": case_definition_digest(matrix, case).expect("case digest"),
            "caseId": case.case_id,
            "targetId": target.id,
            "target": { "os": target.os, "arch": target.arch },
            "status": "NOT_IMPLEMENTED",
            "receiptKind": "source_audit",
            "implementationState": "NOT_IMPLEMENTED",
            "authority": "platform_inventory_only",
            "nativeCalls": 0,
            "releaseDecision": "NOT_EVALUATED",
            "testMode": false,
            "mock": false,
            "startedAt": "2026-08-13T00:00:00Z",
            "completedAt": "2026-08-13T00:00:00Z",
            "executionStarted": false,
            "platformTouched": false,
            "evidenceQualifiers": common_qualifiers(true),
            "artifacts": artifacts,
            "evidenceReferences": references,
            "assertions": [],
            "missingGates": case.missing_gates,
        }))
    }

    #[test]
    fn committed_contracts_validate_without_native_evidence() {
        let matrix = matrix();
        let schema = parse_strict_json::<Value>(RECEIPT_SCHEMA).expect("strict schema");
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        validate_receipt_schema(&schema, RECEIPT_SCHEMA, &matrix).expect("receipt schema contract");
        assert_eq!(validation.counts.pass, 0);
        assert_eq!(validation.counts.fail, 0);
        assert_eq!(validation.counts.blocked_env, 16);
        assert_eq!(validation.counts.not_implemented, 25);
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
    fn raw_schema_digest_is_compiled_and_matrix_bound() {
        let matrix = matrix();
        let bytes = fs::read(repository_root().join("contracts/platform/receipt.schema.v1.json"))
            .expect("read raw receipt schema");
        assert_eq!(sha256_hex(&bytes), RECEIPT_SCHEMA_V1_SHA256);
        assert_eq!(matrix.receipt_schema_sha256, RECEIPT_SCHEMA_V1_SHA256);
        let schema = parse_strict_json::<Value>(&bytes).expect("strict schema");
        validate_receipt_schema(&schema, &bytes, &matrix).expect("three-way schema binding");
    }

    #[test]
    fn every_valid_json_schema_byte_or_internal_mutation_fails_the_raw_digest_gate() {
        let matrix = matrix();

        let mut single_byte = RECEIPT_SCHEMA.to_vec();
        let offset = single_byte
            .windows(b"content-free".len())
            .position(|window| window == b"content-free")
            .expect("description marker");
        single_byte[offset + "content".len()] = b'_';
        let parsed = parse_strict_json::<Value>(&single_byte).expect("single-byte valid JSON");
        let error = validate_receipt_schema(&parsed, &single_byte, &matrix)
            .expect_err("single-byte schema mutation must fail");
        assert!(error.to_string().contains("raw digest/URI"));

        let baseline = parse_strict_json::<Value>(RECEIPT_SCHEMA).expect("strict schema");
        let mut mutations = Vec::new();

        let mut then_required = baseline.clone();
        then_required["allOf"][0]["then"]["required"] = json!(["actualHost"]);
        mutations.push(("then.required", then_required));

        let mut forbidden = baseline.clone();
        forbidden["allOf"][0]["then"]["not"]["anyOf"][0]["required"] = json!(["cleanup"]);
        mutations.push(("forbidden", forbidden));

        let mut definition = baseline.clone();
        definition["$defs"]["cleanup"]["additionalProperties"] = json!(true);
        mutations.push(("definition constraint", definition));

        let mut enumeration = baseline.clone();
        enumeration["properties"]["status"]["enum"] = json!(["PASS"]);
        mutations.push(("enum", enumeration));

        let mut constant = baseline.clone();
        constant["properties"]["authority"]["const"] = json!("release_authority");
        mutations.push(("const", constant));

        let mut closed_object = baseline;
        closed_object["additionalProperties"] = json!(true);
        mutations.push(("additionalProperties", closed_object));

        for (label, mutation) in mutations {
            let bytes = serde_json::to_vec(&mutation).expect("serialize valid JSON mutation");
            let parsed = parse_strict_json::<Value>(&bytes).expect("strict JSON mutation");
            let error = validate_receipt_schema(&parsed, &bytes, &matrix)
                .expect_err("schema mutation must fail before semantic checks");
            assert!(
                error.to_string().contains("raw digest/URI"),
                "{label} did not fail at the raw digest gate"
            );
        }
    }

    #[test]
    fn schema_shape_checks_independently_reject_internal_semantic_drift() {
        let baseline = parse_strict_json::<Value>(RECEIPT_SCHEMA).expect("strict schema");

        let mut status_rule = baseline.clone();
        status_rule["allOf"][0]["then"]["required"] = json!(["actualHost"]);
        validate_schema_status_rules(&status_rule)
            .expect_err("status required-field mutation must fail semantic checks");

        let mut definition = baseline.clone();
        definition["$defs"]["cleanup"]["additionalProperties"] = json!(true);
        validate_schema_property_sets(&definition)
            .expect_err("definition closure mutation must fail semantic checks");

        let mut enumeration = baseline;
        enumeration["properties"]["status"]["enum"] = json!(["PASS"]);
        validate_schema_property_sets(&enumeration)
            .expect_err("status enum mutation must fail semantic checks");
    }

    #[test]
    fn worktree_only_source_binding_cannot_satisfy_the_published_commit() {
        let mut matrix = matrix();
        let worktree_only = "contracts/platform/matrix.v1.json";
        assert!(repository_root().join(worktree_only).is_file());
        matrix.cases[0].source_bindings[0].path = worktree_only.to_owned();
        matrix.cases[0].source_bindings[0].mode = "100644".to_owned();
        matrix.cases[0].source_bindings[0].blob_sha256 =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        matrix.cases[0].source_bindings[0].byte_count = 1;
        let error = validate_matrix(&matrix, &repository_root())
            .expect_err("worktree fallback must be impossible");
        assert!(error.to_string().contains("Git tree entry"));
    }

    #[test]
    fn source_binding_mode_blob_digest_and_size_drift_fail_closed() {
        for field in ["mode", "blobSha256", "byteCount"] {
            let mut matrix = matrix();
            match field {
                "mode" => matrix.cases[0].source_bindings[0].mode = "100755".to_owned(),
                "blobSha256" => {
                    matrix.cases[0].source_bindings[0].blob_sha256 =
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned();
                }
                "byteCount" => matrix.cases[0].source_bindings[0].byte_count += 1,
                _ => unreachable!(),
            }
            let error = validate_matrix(&matrix, &repository_root())
                .expect_err("sourceCommit binding metadata drift must fail");
            assert!(
                error.to_string().contains("metadata disagrees"),
                "{field} drift reached the wrong result"
            );
        }
    }

    #[test]
    fn implementation_digest_is_git_derived_and_case_domain_separated() {
        let matrix = matrix();
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        let first_auth = matrix
            .cases
            .iter()
            .find(|case| case.case_id == "I-01.macos-aarch64.auth.reauth_refusal")
            .expect("first auth case");
        let second_auth = matrix
            .cases
            .iter()
            .find(|case| case.case_id == "I-01.macos-x86_64.auth.reauth_refusal")
            .expect("second auth case");
        assert_eq!(
            first_auth.source_bindings[0].blob_sha256,
            second_auth.source_bindings[0].blob_sha256
        );
        assert_ne!(
            validation
                .implementation_digest(&first_auth.case_id)
                .expect("first implementation digest"),
            validation
                .implementation_digest(&second_auth.case_id)
                .expect("second implementation digest")
        );

        let (mut receipt, _) = native_receipt(&matrix, &validation, PlatformStatus::Pass);
        receipt
            .production_binding
            .as_mut()
            .expect("production binding")
            .implementation_digest =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let error = validate_production_binding(&receipt, &matrix.cases[0], &validation)
            .expect_err("caller-selected implementation digest must fail");
        assert!(error.to_string().contains("exact sourceCommit blobs"));
    }

    #[test]
    fn empty_runner_registry_rejects_every_native_receipt_status() {
        let matrix = matrix();
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        assert!(matrix.allowed_runners.is_empty());
        for status in [
            PlatformStatus::Pass,
            PlatformStatus::Fail,
            PlatformStatus::BlockedEnv,
        ] {
            let (receipt, bytes) = native_receipt(&matrix, &validation, status);
            let error = validate_receipt(
                &receipt,
                &bytes,
                &matrix,
                &validation,
                &sha256_hex(MATRIX),
                RECEIPT_SCHEMA_V1_SHA256,
            )
            .expect_err("empty runner registry must reject native receipt");
            assert!(
                error.to_string().contains("runner is unknown"),
                "{} native receipt did not fail on runner authorization",
                status.as_str()
            );
        }
    }

    #[test]
    fn not_implemented_source_audit_has_no_native_identity_or_binding() {
        let matrix = matrix();
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        let (receipt, bytes) = source_audit_receipt(&matrix);
        assert!(receipt.runner_binding.is_none());
        assert!(receipt.actual_host.is_none());
        assert!(receipt.production_binding.is_none());
        let summary = validate_receipt(
            &receipt,
            &bytes,
            &matrix,
            &validation,
            &sha256_hex(MATRIX),
            RECEIPT_SCHEMA_V1_SHA256,
        )
        .expect("source-audit inventory receipt must validate without native fields");
        assert_eq!(summary.status, "NOT_IMPLEMENTED");
    }

    #[test]
    fn receipt_parser_rejects_unknown_wrong_type_present_null_and_duplicate_keys() {
        let matrix = matrix();
        let (_, baseline_bytes) = source_audit_receipt(&matrix);
        let baseline = serde_json::from_slice::<Value>(&baseline_bytes).expect("receipt JSON");

        let mut unknown = baseline.clone();
        unknown["unknownField"] = json!(false);
        let bytes = serde_json::to_vec(&unknown).expect("unknown field mutation");
        parse_strict_json::<PlatformReceipt>(&bytes)
            .expect_err("unknown receipt field must fail typed parsing");

        let mut wrong_type = baseline.clone();
        wrong_type["nativeCalls"] = json!("0");
        let bytes = serde_json::to_vec(&wrong_type).expect("wrong type mutation");
        parse_strict_json::<PlatformReceipt>(&bytes)
            .expect_err("wrong receipt field type must fail typed parsing");

        let mut present_null = baseline;
        present_null["runnerBinding"] = Value::Null;
        let bytes = serde_json::to_vec(&present_null).expect("present null mutation");
        parse_strict_json::<PlatformReceipt>(&bytes)
            .expect_err("present null must fail strict parsing");

        let mut duplicate = String::from_utf8(baseline_bytes).expect("UTF-8 receipt");
        duplicate.insert_str(1, "\"schemaVersion\":\"hartevo-platform-receipt/v1\",");
        parse_strict_json::<PlatformReceipt>(duplicate.as_bytes())
            .expect_err("duplicate receipt key must fail strict parsing");
    }

    #[test]
    fn manual_status_rules_reject_cross_target_old_commit_and_incompatible_fields() {
        let matrix = matrix();
        let validation = validate_matrix(&matrix, &repository_root()).expect("matrix contract");
        let case = &matrix.cases[0];
        let target = &matrix.targets[0];

        let (mut cross_target, _) = native_receipt(&matrix, &validation, PlatformStatus::Pass);
        cross_target.actual_host.as_mut().expect("actual host").arch =
            crate::model::Architecture::X86_64;
        validate_actual_host(&cross_target, target, true)
            .expect_err("cross-target native host must fail");

        let (mut old_commit, bytes) = native_receipt(&matrix, &validation, PlatformStatus::Pass);
        old_commit.source_commit = "0000000000000000000000000000000000000000".to_owned();
        validate_receipt(
            &old_commit,
            &bytes,
            &matrix,
            &validation,
            &sha256_hex(MATRIX),
            RECEIPT_SCHEMA_V1_SHA256,
        )
        .expect_err("old source commit must fail before runner authorization");

        let (mut wrong_kind, _) = native_receipt(&matrix, &validation, PlatformStatus::Pass);
        wrong_kind.receipt_kind = crate::model::ReceiptKind::NativePreflight;
        validate_native_execution_base(&wrong_kind, case, target, &validation)
            .expect_err("PASS/native_preflight combination must fail");

        let (mut extra_assertion, _) = native_receipt(&matrix, &validation, PlatformStatus::Pass);
        extra_assertion.assertions.push(
            extra_assertion
                .assertions
                .last()
                .expect("required assertion")
                .clone(),
        );
        validate_native_execution_base(&extra_assertion, case, target, &validation)
            .expect_err("extra or duplicate assertion must fail");

        let (mut failed_cleanup, _) = native_receipt(&matrix, &validation, PlatformStatus::Pass);
        failed_cleanup.cleanup.as_mut().expect("cleanup").succeeded = false;
        validate_pass(&failed_cleanup, case, target, &validation)
            .expect_err("PASS with failed cleanup must fail");

        let (mut wrong_blocker, _) =
            native_receipt(&matrix, &validation, PlatformStatus::BlockedEnv);
        wrong_blocker.blocker.as_mut().expect("blocker").code =
            "LINUX_X86_64_NATIVE_HOST_UNAVAILABLE".to_owned();
        validate_blocked_receipt(&wrong_blocker, case, target, &validation)
            .expect_err("case-incompatible blocker must fail");

        let (mut source_audit, _) = source_audit_receipt(&matrix);
        source_audit.actual_host = Some(crate::model::TargetTuple::from(target));
        let source_case = matrix
            .cases
            .iter()
            .find(|candidate| candidate.case_id == source_audit.case_id)
            .expect("source case");
        validate_missing_receipt(&source_audit, source_case)
            .expect_err("NOT_IMPLEMENTED cannot carry actualHost");
    }
}
