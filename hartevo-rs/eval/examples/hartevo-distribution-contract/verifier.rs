use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::digest::{is_lower_hex, sha256_hex};
use crate::model::{
    AdvisoryCategory, CargoMetadata, CargoPackage, CargoResolve, Disposition, InputContract,
    PolicyDocument, TargetGraphPolicy, TargetRole, parse_strict_json,
};

pub const POLICY_PATH: &str = "contracts/distribution/dependency-advisory-policy.v1.json";
pub const POLICY_SCHEMA_PATH: &str =
    "contracts/distribution/dependency-advisory-policy.schema.v1.json";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-distribution-dependency-advisory/v1";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const SOURCE_COMMIT_LENGTH: usize = 20;
pub const LOCK_DIGEST_LENGTH: usize = 32;

const EXPECTED_POLICY_SCHEMA: &str = "hartevo-distribution-dependency-advisory-policy/v1";
const EXPECTED_POLICY_ID: &str = "DIST-SBOM-TARGET-01";
const EXPECTED_POLICY_AUTHORITY: &str = "hartevo-distribution-contract";
const EXPECTED_METADATA_ENVELOPE_SCHEMA: &str = "hartevo-cargo-metadata-receipt/v1";
const EXPECTED_CARGO_METADATA_COMMAND: &str =
    "cargo metadata --locked --format-version 1 --filter-platform <target>";
const EXPECTED_CARGO_AUDIT_TOOL: &str = "cargo-audit 0.22.2";
const EXPECTED_REQUIRED_BINDINGS: [&str; 4] = [
    "sourceCommit",
    "lockfileSha256",
    "metadataPerTarget",
    "cargoAuditReceipt",
];
const EXPECTED_FINDING_FIELDS: [&str; 10] = [
    "advisoryId",
    "category",
    "package",
    "dependencyPath",
    "target",
    "targetReachability",
    "releaseImpact",
    "sourceCommit",
    "lockfileSha256",
    "auditReceiptSha256",
];
const EXPECTED_RELEASE_TARGETS: [&str; 2] = ["macos-aarch64", "macos-x86_64"];
const EXPECTED_TARGET_GRAPH_IDS: [&str; 3] = ["macos-aarch64", "macos-x86_64", "linux-x86_64-ci"];
const EXPECTED_TARGET_TRIPLES: [&str; 3] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
];
const EXPECTED_ALLOWED_CATEGORIES: [AdvisoryCategory; 4] = [
    AdvisoryCategory::Notice,
    AdvisoryCategory::Unmaintained,
    AdvisoryCategory::Unsound,
    AdvisoryCategory::Vulnerability,
];
const EXPECTED_FAILURE_CATEGORIES: [AdvisoryCategory; 2] =
    [AdvisoryCategory::Unsound, AdvisoryCategory::Vulnerability];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataInput {
    pub target_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedTargetMetadata {
    target_id: String,
    target_triple: String,
    raw_sha256: String,
    metadata: CargoMetadata,
    release_root_packages: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AuditFindingInput {
    advisory_id: String,
    category: AdvisoryCategory,
    package_name: String,
    package_version: String,
    package_source: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageKey {
    name: String,
    version: String,
    source: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetReachability {
    Reachable,
    #[serde(rename = "target-unreachable")]
    TargetUnreachable,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingDisposition {
    CodeFailure,
    InformationalWarning,
    ReviewedException,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageRecord {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionEvidence {
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityProof {
    pub method: &'static str,
    pub release_root_packages: Vec<String>,
    pub visited_package_count: usize,
    pub package_present_in_target_metadata: bool,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRecord {
    pub advisory_id: String,
    pub category: AdvisoryCategory,
    pub package: PackageRecord,
    pub dependency_path: Vec<String>,
    pub target: String,
    pub target_triple: String,
    pub target_role: TargetRole,
    pub target_reachability: TargetReachability,
    pub release_impact: FindingDisposition,
    pub disposition: FindingDisposition,
    pub reason_code: &'static str,
    pub exception: Option<ExceptionEvidence>,
    pub reachability_proof: ReachabilityProof,
    pub source_commit: String,
    pub lockfile_sha256: String,
    pub audit_receipt_sha256: String,
    pub metadata_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetMetadataSummary {
    pub target: String,
    pub target_triple: String,
    pub role: TargetRole,
    pub release: bool,
    pub metadata_sha256: String,
    pub package_count: usize,
    pub release_root_packages: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributionReport {
    pub schema_version: &'static str,
    pub policy_id: String,
    pub status: &'static str,
    pub release_decision: &'static str,
    pub release: bool,
    pub deployment: bool,
    pub source_commit: String,
    pub lockfile_sha256: String,
    pub audit_receipt_sha256: String,
    pub policy_sha256: String,
    pub evaluated_at: String,
    pub target_metadata: Vec<TargetMetadataSummary>,
    pub findings: Vec<FindingRecord>,
    pub finding_count: usize,
    pub code_failure_count: usize,
    pub informational_warning_count: usize,
    pub reviewed_exception_count: usize,
    pub no_blanket_ignore: bool,
}

pub fn validate_policy_schema(schema_bytes: &[u8]) -> Result<()> {
    let schema = parse_strict_json::<Value>(schema_bytes)
        .context("dependency advisory policy schema is not strict JSON")?;
    ensure!(
        schema.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema"),
        "dependency advisory policy schema draft drift"
    );
    ensure!(
        schema.get("$id").and_then(Value::as_str)
            == Some(
                "https://hartevo.dev/contracts/distribution/dependency-advisory-policy.schema.v1.json"
            ),
        "dependency advisory policy schema id drift"
    );
    ensure!(
        schema.get("type").and_then(Value::as_str) == Some("object")
            && schema.get("additionalProperties").and_then(Value::as_bool) == Some(false),
        "dependency advisory policy schema must be a closed object"
    );
    ensure!(
        schema.get("$defs").and_then(Value::as_object).is_some(),
        "dependency advisory policy schema is missing definitions"
    );
    Ok(())
}

pub fn validate_policy(policy: &PolicyDocument) -> Result<()> {
    ensure!(
        policy.schema_version == EXPECTED_POLICY_SCHEMA,
        "dependency advisory policy schema drift"
    );
    ensure!(
        policy.policy_id == EXPECTED_POLICY_ID && policy.authority == EXPECTED_POLICY_AUTHORITY,
        "dependency advisory policy identity drift"
    );
    ensure!(
        policy.release_decision == crate::model::ReleaseDecision::NotEvaluated
            && !policy.release.passed
            && !policy.release.deployment,
        "distribution policy cannot promote release or deployment"
    );
    ensure!(
        policy.release_targets == EXPECTED_RELEASE_TARGETS,
        "release target set drift"
    );
    ensure!(
        policy.allowed_categories == EXPECTED_ALLOWED_CATEGORIES,
        "allowed advisory category set drift"
    );
    ensure!(
        policy.failure_categories == EXPECTED_FAILURE_CATEGORIES,
        "release failure category set drift"
    );
    ensure!(
        policy.unreachable_disposition == Disposition::InformationalWarning
            && policy.release_failure_disposition == Disposition::CodeFailure,
        "advisory disposition policy drift"
    );
    ensure!(
        policy.no_blanket_ignore,
        "blanket advisory ignore is forbidden"
    );
    validate_input_contract(&policy.input_contract)?;
    ensure!(
        policy.finding_record_fields
            == EXPECTED_FINDING_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect::<Vec<_>>(),
        "finding record field contract drift"
    );
    validate_target_graphs(policy)?;
    validate_reviewed_exceptions(policy)?;
    Ok(())
}

fn validate_input_contract(input: &InputContract) -> Result<()> {
    ensure!(
        input.required_bindings
            == EXPECTED_REQUIRED_BINDINGS
                .iter()
                .map(|binding| (*binding).to_owned())
                .collect::<Vec<_>>(),
        "distribution input binding set drift"
    );
    ensure!(
        input.cargo_metadata_command == EXPECTED_CARGO_METADATA_COMMAND
            && input.cargo_audit_tool == EXPECTED_CARGO_AUDIT_TOOL
            && input.lock_digest_algorithm == "sha256"
            && input.metadata_digest_algorithm == "sha256"
            && input.audit_receipt_digest_algorithm == "sha256",
        "distribution input command or digest policy drift"
    );
    Ok(())
}

fn validate_target_graphs(policy: &PolicyDocument) -> Result<()> {
    ensure!(
        policy.target_graphs.len() == EXPECTED_TARGET_GRAPH_IDS.len(),
        "distribution policy must contain exactly three target graphs"
    );
    let mut ids = BTreeSet::new();
    let mut release_ids = Vec::new();
    for (graph, (expected_id, expected_target)) in policy.target_graphs.iter().zip(
        EXPECTED_TARGET_GRAPH_IDS
            .iter()
            .zip(EXPECTED_TARGET_TRIPLES),
    ) {
        ensure!(
            graph.id == *expected_id && graph.target == expected_target,
            "target graph identity drift"
        );
        ensure!(ids.insert(graph.id.as_str()), "duplicate target graph id");
        ensure!(
            graph.release_roots == ["hartevo-desktop".to_owned()],
            "release graph roots must be the exact desktop product root"
        );
        match graph.role {
            TargetRole::Release => ensure!(graph.release, "release graph must be release=true"),
            TargetRole::Ci => ensure!(!graph.release, "CI graph must be release=false"),
        }
        if graph.release {
            release_ids.push(graph.id.clone());
        }
    }
    ensure!(
        release_ids == EXPECTED_RELEASE_TARGETS,
        "release graph ids must match releaseTargets"
    );
    Ok(())
}

fn validate_reviewed_exceptions(policy: &PolicyDocument) -> Result<()> {
    let target_ids = policy
        .target_graphs
        .iter()
        .map(|graph| graph.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeSet::new();
    for exception in &policy.reviewed_exceptions {
        ensure!(
            exception
                .category
                .is_release_failure(&policy.failure_categories),
            "reviewed exceptions may only cover release-failure categories"
        );
        ensure!(
            target_ids.contains(exception.target.as_str()),
            "reviewed exception target is not a declared target graph"
        );
        ensure!(
            !exception.owner.trim().is_empty(),
            "reviewed exception owner is empty"
        );
        ensure!(
            !exception.reason.trim().is_empty(),
            "reviewed exception reason is empty"
        );
        ensure!(
            parse_timestamp(&exception.expires_at).is_ok(),
            "reviewed exception expiry must be RFC3339"
        );
        let key = (
            exception.advisory_id.as_str(),
            exception.category,
            exception.package_name.as_str(),
            exception.package_version.as_str(),
            exception.target.as_str(),
        );
        ensure!(keys.insert(key), "duplicate exact reviewed exception");
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))?
        .with_timezone(&Utc))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn verify(
    policy_bytes: &[u8],
    schema_bytes: &[u8],
    lock_bytes: &[u8],
    audit_bytes: &[u8],
    source_commit: &str,
    evaluated_at: &str,
    expected_lock_digest: Option<&str>,
    metadata_inputs: &[MetadataInput],
) -> Result<DistributionReport> {
    validate_policy_schema(schema_bytes)?;
    let policy = parse_strict_json::<PolicyDocument>(policy_bytes)
        .context("dependency advisory policy is not strict typed JSON")?;
    validate_policy(&policy)?;
    validate_source_commit(source_commit)?;
    let evaluated_at = parse_timestamp(evaluated_at)?;

    let lockfile_sha256 = sha256_hex(lock_bytes);
    ensure!(
        expected_lock_digest.is_none_or(|expected| expected == lockfile_sha256),
        "Cargo.lock digest drift: expected digest does not match supplied Cargo.lock bytes"
    );
    if let Some(expected) = expected_lock_digest {
        ensure!(
            is_lower_hex(expected, LOCK_DIGEST_LENGTH),
            "expected Cargo.lock digest must be lowercase SHA-256"
        );
    }

    let audit_receipt_sha256 = sha256_hex(audit_bytes);
    let audit_findings = parse_audit_receipt(audit_bytes, source_commit, &lockfile_sha256)?;
    let parsed_metadata =
        parse_all_target_metadata(&policy, metadata_inputs, source_commit, &lockfile_sha256)?;

    let mut records = Vec::new();
    for finding in audit_findings {
        for target in &parsed_metadata {
            records.push(build_finding_record(
                &finding,
                target,
                &policy,
                source_commit,
                &lockfile_sha256,
                &audit_receipt_sha256,
                evaluated_at,
            )?);
        }
    }
    records.sort_by(|left, right| {
        (
            left.advisory_id.as_str(),
            left.category,
            left.package.name.as_str(),
            left.package.version.as_str(),
            left.target.as_str(),
        )
            .cmp(&(
                right.advisory_id.as_str(),
                right.category,
                right.package.name.as_str(),
                right.package.version.as_str(),
                right.target.as_str(),
            ))
    });

    let code_failure_count = records
        .iter()
        .filter(|record| record.disposition == FindingDisposition::CodeFailure)
        .count();
    let reviewed_exception_count = records
        .iter()
        .filter(|record| record.disposition == FindingDisposition::ReviewedException)
        .count();
    let informational_warning_count = records
        .iter()
        .filter(|record| record.disposition == FindingDisposition::InformationalWarning)
        .count();
    let target_metadata = parsed_metadata
        .iter()
        .map(|target| TargetMetadataSummary {
            target: target.target_id.clone(),
            target_triple: target.target_triple.clone(),
            role: policy_graph(&policy, &target.target_id)
                .expect("validated target graph must exist")
                .role,
            release: policy_graph(&policy, &target.target_id)
                .expect("validated target graph must exist")
                .release,
            metadata_sha256: target.raw_sha256.clone(),
            package_count: target.metadata.packages.len(),
            release_root_packages: target.release_root_packages.clone(),
        })
        .collect();

    Ok(DistributionReport {
        schema_version: VALIDATION_SCHEMA_VERSION,
        policy_id: policy.policy_id,
        status: if code_failure_count == 0 {
            "PASS"
        } else {
            "CODE_FAILURE"
        },
        release_decision: RELEASE_DECISION,
        release: false,
        deployment: false,
        source_commit: source_commit.to_owned(),
        lockfile_sha256,
        audit_receipt_sha256,
        policy_sha256: sha256_hex(policy_bytes),
        evaluated_at: evaluated_at.to_rfc3339(),
        target_metadata,
        finding_count: records.len(),
        code_failure_count,
        informational_warning_count,
        reviewed_exception_count,
        findings: records,
        no_blanket_ignore: policy.no_blanket_ignore,
    })
}

fn validate_source_commit(source_commit: &str) -> Result<()> {
    ensure!(
        is_lower_hex(source_commit, SOURCE_COMMIT_LENGTH)
            || is_lower_hex(source_commit, LOCK_DIGEST_LENGTH),
        "source commit must be a lowercase 40- or 64-hex Git object id"
    );
    Ok(())
}

fn policy_graph<'a>(policy: &'a PolicyDocument, target_id: &str) -> Option<&'a TargetGraphPolicy> {
    policy
        .target_graphs
        .iter()
        .find(|graph| graph.id == target_id)
}

fn parse_all_target_metadata(
    policy: &PolicyDocument,
    inputs: &[MetadataInput],
    source_commit: &str,
    lockfile_sha256: &str,
) -> Result<Vec<ParsedTargetMetadata>> {
    let expected_ids = policy
        .target_graphs
        .iter()
        .map(|graph| graph.id.as_str())
        .collect::<BTreeSet<_>>();
    let actual_ids = inputs
        .iter()
        .map(|input| input.target_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        inputs.len() == actual_ids.len(),
        "metadata inputs contain duplicate target ids"
    );
    ensure!(
        actual_ids == expected_ids,
        "metadata inputs must exactly match policy target graphs"
    );

    let mut parsed = Vec::with_capacity(inputs.len());
    for graph in &policy.target_graphs {
        let input = inputs
            .iter()
            .find(|input| input.target_id == graph.id)
            .expect("validated target id set must contain every policy graph");
        parsed.push(parse_target_metadata(
            graph,
            input,
            source_commit,
            lockfile_sha256,
        )?);
    }
    Ok(parsed)
}

fn parse_target_metadata(
    graph: &TargetGraphPolicy,
    input: &MetadataInput,
    source_commit: &str,
    lockfile_sha256: &str,
) -> Result<ParsedTargetMetadata> {
    let root = parse_strict_json::<Value>(&input.bytes)
        .with_context(|| format!("metadata for target {} is not strict JSON", graph.id))?;
    let (metadata_value, declared_target, declared_source, declared_lock) =
        if let Some(metadata) = root.get("cargoMetadata") {
            let envelope = root
                .as_object()
                .context("metadata envelope must be a JSON object")?;
            for key in envelope.keys() {
                ensure!(
                    matches!(
                        key.as_str(),
                        "schemaVersion"
                            | "target"
                            | "sourceCommit"
                            | "lockfileSha256"
                            | "cargoMetadata"
                    ),
                    "unknown metadata envelope field {key}; fail closed"
                );
            }
            ensure!(
                envelope.get("schemaVersion").and_then(Value::as_str)
                    == Some(EXPECTED_METADATA_ENVELOPE_SCHEMA),
                "metadata envelope schema drift"
            );
            (
                metadata.clone(),
                optional_string(&root, "target")?,
                optional_string(&root, "sourceCommit")?,
                optional_string(&root, "lockfileSha256")?,
            )
        } else {
            (root.clone(), None, None, None)
        };
    if let Some(declared_target) = declared_target {
        ensure!(
            declared_target == graph.target,
            "metadata target attestation does not match policy target {}",
            graph.id
        );
    }
    if let Some(declared_source) = declared_source {
        ensure!(
            declared_source == source_commit,
            "metadata sourceCommit binding drift for target {}",
            graph.id
        );
    }
    if let Some(declared_lock) = declared_lock {
        ensure!(
            declared_lock == lockfile_sha256,
            "metadata lockfileSha256 binding drift for target {}",
            graph.id
        );
    }
    let metadata = serde_json::from_value::<CargoMetadata>(metadata_value)
        .with_context(|| format!("cargo metadata shape is invalid for target {}", graph.id))?;
    let release_root_packages = validate_metadata(&metadata, graph)
        .with_context(|| format!("cargo metadata graph is invalid for target {}", graph.id))?;
    Ok(ParsedTargetMetadata {
        target_id: graph.id.clone(),
        target_triple: graph.target.clone(),
        raw_sha256: sha256_hex(&input.bytes),
        metadata,
        release_root_packages,
    })
}

fn optional_string(root: &Value, field: &str) -> Result<Option<String>> {
    match root.get(field) {
        None => Ok(None),
        Some(value) => Ok(Some(
            value
                .as_str()
                .with_context(|| format!("metadata envelope field {field} must be a string"))?
                .to_owned(),
        )),
    }
}

fn validate_metadata(metadata: &CargoMetadata, graph: &TargetGraphPolicy) -> Result<Vec<String>> {
    ensure!(
        !metadata.packages.is_empty(),
        "cargo metadata packages array is empty"
    );
    ensure!(
        !metadata.workspace_members.is_empty(),
        "cargo metadata workspace_members array is empty"
    );
    let resolve = metadata
        .resolve
        .as_ref()
        .context("cargo metadata resolve graph is missing")?;
    ensure!(
        !resolve.nodes.is_empty(),
        "cargo metadata resolve nodes are empty"
    );

    let packages_by_id = unique_packages(&metadata.packages)?;
    let workspace_members = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for member in &workspace_members {
        ensure!(
            packages_by_id.contains_key(*member),
            "workspace member is not present in cargo metadata packages: {member}"
        );
    }
    let nodes_by_id = unique_nodes(resolve)?;
    for node in nodes_by_id.values() {
        ensure!(
            packages_by_id.contains_key(node.id.as_str()),
            "resolve node is not present in cargo metadata packages: {}",
            node.id
        );
        ensure!(
            node.dependencies.is_empty() || !node.deps.is_empty(),
            "resolve node {} has dependency ids without dep_kinds",
            node.id
        );
        let mut dependency_ids = node.dependencies.clone();
        dependency_ids.sort();
        ensure!(
            dependency_ids.windows(2).all(|pair| pair[0] != pair[1]),
            "resolve node {} contains duplicate dependency ids",
            node.id
        );
        let mut dep_package_ids = node
            .deps
            .iter()
            .map(|dependency| dependency.pkg.clone())
            .collect::<Vec<_>>();
        dep_package_ids.sort();
        ensure!(
            dependency_ids == dep_package_ids,
            "resolve node {} dependency ids do not match dep_kinds package ids",
            node.id
        );
        for dependency in &node.deps {
            ensure!(
                packages_by_id.contains_key(dependency.pkg.as_str()),
                "dependency package is not present in cargo metadata packages: {}",
                dependency.pkg
            );
            ensure!(
                !dependency.dep_kinds.is_empty(),
                "dependency {} on node {} is missing dep_kinds",
                dependency.pkg,
                node.id
            );
        }
    }
    if let Some(root) = resolve.root.as_deref() {
        ensure!(
            packages_by_id.contains_key(root),
            "cargo metadata resolve root is not present in packages"
        );
    }

    let mut roots = Vec::new();
    for root_name in &graph.release_roots {
        let matches = metadata
            .packages
            .iter()
            .filter(|package| {
                package.name == *root_name && workspace_members.contains(package.id.as_str())
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "release root {} must resolve to exactly one workspace package, got {}",
            root_name,
            matches.len()
        );
        roots.push(matches[0].id.clone());
    }
    roots.sort_by_key(|id| package_display(packages_by_id.get(id.as_str()).expect("root package")));
    Ok(roots
        .iter()
        .map(|id| package_display(packages_by_id.get(id.as_str()).expect("root package")))
        .collect())
}

fn unique_packages(packages: &[CargoPackage]) -> Result<BTreeMap<&str, &CargoPackage>> {
    let mut by_id = BTreeMap::new();
    for package in packages {
        ensure!(
            !package.id.is_empty() && !package.name.is_empty() && !package.version.is_empty(),
            "cargo metadata package identity is empty"
        );
        ensure!(
            by_id.insert(package.id.as_str(), package).is_none(),
            "duplicate cargo metadata package id: {}",
            package.id
        );
    }
    Ok(by_id)
}

fn unique_nodes(resolve: &CargoResolve) -> Result<BTreeMap<&str, &crate::model::CargoNode>> {
    let mut by_id = BTreeMap::new();
    for node in &resolve.nodes {
        ensure!(!node.id.is_empty(), "cargo resolve node id is empty");
        ensure!(
            by_id.insert(node.id.as_str(), node).is_none(),
            "duplicate cargo resolve node id: {}",
            node.id
        );
    }
    Ok(by_id)
}

fn package_display(package: &CargoPackage) -> String {
    format!("{}@{}", package.name, package.version)
}

fn parse_audit_receipt(
    audit_bytes: &[u8],
    source_commit: &str,
    lockfile_sha256: &str,
) -> Result<Vec<AuditFindingInput>> {
    let root = parse_strict_json::<Value>(audit_bytes)
        .context("cargo-audit receipt is not strict JSON")?;
    ensure!(
        root.is_object(),
        "cargo-audit receipt must be a JSON object"
    );
    ensure!(
        root.get("vulnerabilities").is_some() && root.get("warnings").is_some(),
        "cargo-audit receipt must contain vulnerabilities and warnings sections"
    );
    if let Some(object) = root.as_object() {
        for key in object.keys() {
            ensure!(
                matches!(
                    key.as_str(),
                    "database"
                        | "lockfile"
                        | "settings"
                        | "vulnerabilities"
                        | "warnings"
                        | "sourceCommit"
                        | "lockfileSha256"
                ),
                "unknown cargo-audit receipt field {key}; fail closed"
            );
        }
    }
    validate_optional_receipt_binding(&root, "sourceCommit", source_commit)?;
    validate_optional_receipt_binding(&root, "lockfileSha256", lockfile_sha256)?;

    let mut findings = Vec::new();
    if let Some(vulnerabilities) = root.get("vulnerabilities") {
        let object = vulnerabilities
            .as_object()
            .context("cargo-audit vulnerabilities must be an object")?;
        for key in object.keys() {
            ensure!(
                matches!(key.as_str(), "found" | "count" | "list"),
                "unknown cargo-audit vulnerabilities field: {key}; fail closed"
            );
        }
        let list: &[Value] = match object.get("list") {
            Some(value) => value
                .as_array()
                .map(Vec::as_slice)
                .context("cargo-audit vulnerabilities.list must be an array")?,
            None => &[],
        };
        let found = match object.get("found") {
            None => list.len() as u64,
            Some(value) if value.as_u64().is_some() => {
                value.as_u64().expect("checked numeric vulnerability count")
            }
            Some(value) if value.as_bool().is_some() => {
                let found = value
                    .as_bool()
                    .expect("checked boolean vulnerability count");
                ensure!(
                    found != list.is_empty(),
                    "cargo-audit vulnerability boolean count does not match receipt list"
                );
                list.len() as u64
            }
            Some(_) => bail!("cargo-audit vulnerabilities.found must be a number or boolean"),
        };
        if let Some(count) = object.get("count") {
            ensure!(
                count.as_u64() == Some(found),
                "cargo-audit vulnerability count does not match the receipt list"
            );
        }
        ensure!(
            found == list.len() as u64,
            "cargo-audit vulnerability count does not match the receipt list"
        );
        for item in list {
            findings.push(parse_audit_item(item, AdvisoryCategory::Vulnerability)?);
        }
    }
    if let Some(warnings) = root.get("warnings") {
        let object = warnings
            .as_object()
            .context("cargo-audit warnings must be an object")?;
        for (category, value) in object {
            let category = parse_category(category)?;
            let list = value
                .as_array()
                .with_context(|| format!("cargo-audit warnings.{category:?} must be an array"))?;
            for item in list {
                findings.push(parse_audit_item(item, category)?);
            }
        }
    }
    let unique = findings.iter().collect::<BTreeSet<_>>();
    ensure!(
        unique.len() == findings.len(),
        "cargo-audit receipt contains duplicate advisory records; fail closed"
    );
    findings.sort();
    Ok(findings)
}

fn validate_optional_receipt_binding(root: &Value, field: &str, expected: &str) -> Result<()> {
    if let Some(actual) = root.get(field) {
        ensure!(
            actual.as_str() == Some(expected),
            "cargo-audit receipt {field} binding drift"
        );
    }
    Ok(())
}

fn parse_category(value: &str) -> Result<AdvisoryCategory> {
    match value {
        "notice" => Ok(AdvisoryCategory::Notice),
        "unmaintained" => Ok(AdvisoryCategory::Unmaintained),
        "unsound" => Ok(AdvisoryCategory::Unsound),
        "vulnerability" => Ok(AdvisoryCategory::Vulnerability),
        other => bail!("unknown advisory category {other}; fail closed"),
    }
}

fn parse_audit_item(
    item: &Value,
    fallback_category: AdvisoryCategory,
) -> Result<AuditFindingInput> {
    let object = item
        .as_object()
        .context("cargo-audit advisory item must be an object")?;
    let package = object
        .get("package")
        .and_then(Value::as_object)
        .context("cargo-audit advisory item package is missing")?;
    let advisory = object
        .get("advisory")
        .and_then(Value::as_object)
        .context("cargo-audit advisory item advisory is missing")?;
    let package_name = required_string(package, "name", "audit package")?;
    let package_version = required_string(package, "version", "audit package")?;
    let package_source = package
        .get("source")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("audit package source must be a string or omitted")
        })
        .transpose()?;
    let advisory_package = required_string(advisory, "package", "audit advisory")?;
    ensure!(
        advisory_package == package_name,
        "cargo-audit advisory package does not match affected package"
    );
    let kind = object
        .get("kind")
        .map(|value| {
            value
                .as_str()
                .context("cargo-audit item kind must be a string")
                .and_then(parse_category)
        })
        .transpose()?;
    let informational = advisory
        .get("informational")
        .map(|value| {
            value
                .as_str()
                .context("cargo-audit advisory informational category must be a string")
                .and_then(parse_category)
        })
        .transpose()?;
    if let (Some(kind), Some(informational)) = (kind, informational) {
        ensure!(
            kind == informational,
            "cargo-audit item category disagrees with advisory informational category"
        );
    }
    let category = kind.or(informational).unwrap_or(fallback_category);
    Ok(AuditFindingInput {
        advisory_id: required_string(advisory, "id", "audit advisory")?,
        category,
        package_name,
        package_version,
        package_source,
    })
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{label} field {field} must be a non-null string"))
}

fn build_finding_record(
    finding: &AuditFindingInput,
    target: &ParsedTargetMetadata,
    policy: &PolicyDocument,
    source_commit: &str,
    lockfile_sha256: &str,
    audit_receipt_sha256: &str,
    evaluated_at: DateTime<Utc>,
) -> Result<FindingRecord> {
    let graph = policy_graph(policy, &target.target_id)
        .context("target metadata does not have a policy graph")?;
    let package_key = PackageKey {
        name: finding.package_name.clone(),
        version: finding.package_version.clone(),
        source: finding.package_source.clone(),
    };
    let (target_reachability, dependency_path, mut proof) =
        prove_reachability(&target.metadata, graph, &package_key)?;
    proof
        .release_root_packages
        .clone_from(&target.release_root_packages);
    let exact_exception = if graph.release
        && target_reachability == TargetReachability::Reachable
        && finding
            .category
            .is_release_failure(&policy.failure_categories)
    {
        find_exact_exception(policy, finding, graph.id.as_str())
    } else {
        None
    };
    let (disposition, reason_code, exception) = match target_reachability {
        TargetReachability::TargetUnreachable => (
            FindingDisposition::InformationalWarning,
            "target-unreachable-from-release-roots",
            None,
        ),
        TargetReachability::Reachable if !graph.release => (
            FindingDisposition::InformationalWarning,
            "reachable-non-release-target",
            None,
        ),
        TargetReachability::Reachable
            if !finding
                .category
                .is_release_failure(&policy.failure_categories) =>
        {
            (
                FindingDisposition::InformationalWarning,
                "reachable-informational-category",
                None,
            )
        }
        TargetReachability::Reachable => match exact_exception {
            Some(exception) if exception.expires_at > evaluated_at => (
                FindingDisposition::ReviewedException,
                "active-reviewed-exception",
                Some(exception_evidence(exception, true)),
            ),
            Some(exception) => (
                FindingDisposition::CodeFailure,
                "reviewed-exception-expired",
                Some(exception_evidence(exception, false)),
            ),
            None => (
                FindingDisposition::CodeFailure,
                "reachable-release-failure",
                None,
            ),
        },
    };
    let release_impact = disposition;
    Ok(FindingRecord {
        advisory_id: finding.advisory_id.clone(),
        category: finding.category,
        package: PackageRecord {
            name: finding.package_name.clone(),
            version: finding.package_version.clone(),
            source: finding.package_source.clone(),
        },
        dependency_path,
        target: graph.id.clone(),
        target_triple: graph.target.clone(),
        target_role: graph.role,
        target_reachability,
        release_impact,
        disposition,
        reason_code,
        exception,
        reachability_proof: proof,
        source_commit: source_commit.to_owned(),
        lockfile_sha256: lockfile_sha256.to_owned(),
        audit_receipt_sha256: audit_receipt_sha256.to_owned(),
        metadata_sha256: target.raw_sha256.clone(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExceptionMatch {
    owner: String,
    reason: String,
    expires_at_raw: String,
    expires_at: DateTime<Utc>,
}

fn find_exact_exception(
    policy: &PolicyDocument,
    finding: &AuditFindingInput,
    target_id: &str,
) -> Option<ExceptionMatch> {
    policy
        .reviewed_exceptions
        .iter()
        .find(|exception| {
            exception.advisory_id == finding.advisory_id
                && exception.category == finding.category
                && exception.package_name == finding.package_name
                && exception.package_version == finding.package_version
                && exception.target == target_id
        })
        .map(|exception| ExceptionMatch {
            owner: exception.owner.clone(),
            reason: exception.reason.clone(),
            expires_at_raw: exception.expires_at.clone(),
            expires_at: parse_timestamp(&exception.expires_at)
                .expect("validated reviewed exception timestamp"),
        })
}

fn exception_evidence(exception: ExceptionMatch, active: bool) -> ExceptionEvidence {
    ExceptionEvidence {
        owner: exception.owner,
        reason: exception.reason,
        expires_at: exception.expires_at_raw,
        active,
    }
}

fn prove_reachability(
    metadata: &CargoMetadata,
    graph: &TargetGraphPolicy,
    package_key: &PackageKey,
) -> Result<(TargetReachability, Vec<String>, ReachabilityProof)> {
    let packages_by_id = unique_packages(&metadata.packages)?;
    let resolve = metadata
        .resolve
        .as_ref()
        .context("cargo metadata resolve graph is missing")?;
    let nodes_by_id = unique_nodes(resolve)?;
    let mut candidate_ids = packages_by_id
        .values()
        .filter(|package| {
            package.name == package_key.name
                && package.version == package_key.version
                && package.source == package_key.source
        })
        .map(|package| package.id.as_str())
        .collect::<Vec<_>>();
    candidate_ids.sort_unstable();
    let candidate_ids = candidate_ids.into_iter().collect::<BTreeSet<_>>();
    let roots = graph_root_ids(metadata, graph, &packages_by_id)?;
    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();
    for root in roots {
        queue.push_back((root, Vec::<String>::new()));
    }
    while let Some((node_id, prior_path)) = queue.pop_front() {
        if !visited.insert(node_id) {
            continue;
        }
        let package = packages_by_id
            .get(node_id)
            .expect("validated resolve node package");
        let mut path = prior_path;
        path.push(package_display(package));
        if candidate_ids.contains(node_id) {
            return Ok((
                TargetReachability::Reachable,
                path,
                ReachabilityProof {
                    method: "cargo-metadata-resolve-bfs/v1",
                    release_root_packages: Vec::new(),
                    visited_package_count: visited.len(),
                    package_present_in_target_metadata: true,
                    reason: "reachable-from-release-root",
                },
            ));
        }
        let mut neighbors = normal_or_build_dependencies(
            nodes_by_id.get(node_id).expect("validated resolve node"),
            &packages_by_id,
        )?;
        neighbors.sort_by(|left, right| {
            package_display(packages_by_id.get(left).expect("validated dependency"))
                .cmp(&package_display(
                    packages_by_id.get(right).expect("validated dependency"),
                ))
                .then_with(|| left.cmp(right))
        });
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                queue.push_back((neighbor, path.clone()));
            }
        }
    }
    let present = !candidate_ids.is_empty();
    Ok((
        TargetReachability::TargetUnreachable,
        Vec::new(),
        ReachabilityProof {
            method: "cargo-metadata-resolve-bfs/v1",
            release_root_packages: Vec::new(),
            visited_package_count: visited.len(),
            package_present_in_target_metadata: present,
            reason: if present {
                "not-reachable-from-release-root"
            } else {
                "package-not-present-in-target-metadata"
            },
        },
    ))
}

fn graph_root_ids<'a>(
    metadata: &'a CargoMetadata,
    graph: &TargetGraphPolicy,
    packages_by_id: &BTreeMap<&'a str, &'a CargoPackage>,
) -> Result<Vec<&'a str>> {
    let workspace_members = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut root_ids = Vec::new();
    for root_name in &graph.release_roots {
        let mut matches = packages_by_id
            .values()
            .filter(|package| {
                package.name == *root_name && workspace_members.contains(package.id.as_str())
            })
            .map(|package| package.id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "release root {root_name} did not resolve to one workspace package"
        );
        root_ids.append(&mut matches);
    }
    root_ids.sort_unstable();
    Ok(root_ids)
}

fn normal_or_build_dependencies<'a>(
    node: &crate::model::CargoNode,
    packages_by_id: &BTreeMap<&'a str, &'a CargoPackage>,
) -> Result<Vec<&'a str>> {
    let mut dependencies = Vec::new();
    for dependency in &node.deps {
        ensure!(
            packages_by_id.contains_key(dependency.pkg.as_str()),
            "resolve dependency {} is not a package",
            dependency.pkg
        );
        let release_edge = dependency
            .dep_kinds
            .iter()
            .any(|kind| kind.kind.as_deref() != Some("dev"));
        if release_edge {
            dependencies.push(
                packages_by_id
                    .get(dependency.pkg.as_str())
                    .expect("validated dependency package")
                    .id
                    .as_str(),
            );
        }
    }
    Ok(dependencies)
}

#[cfg(test)]
mod tests {
    use super::{
        FindingDisposition, MetadataInput, TargetReachability, validate_policy,
        validate_policy_schema, verify,
    };
    use crate::model::{PolicyDocument, parse_strict_json};

    const SOURCE_COMMIT: &str = "1111111111111111111111111111111111111111";
    const EVALUATED_AT: &str = "2026-08-14T00:00:00Z";
    const LOCK_BYTES: &[u8] = b"fixture-lock-v1\n";

    fn policy_bytes() -> &'static [u8] {
        include_bytes!("../../../../contracts/distribution/dependency-advisory-policy.v1.json")
    }

    fn schema_bytes() -> &'static [u8] {
        include_bytes!(
            "../../../../contracts/distribution/dependency-advisory-policy.schema.v1.json"
        )
    }

    fn audit_bytes() -> &'static [u8] {
        include_bytes!("fixtures/cross-target-audit.json")
    }

    fn metadata_inputs() -> Vec<MetadataInput> {
        vec![
            MetadataInput {
                target_id: "macos-aarch64".to_owned(),
                bytes: include_bytes!("fixtures/macos-aarch64-metadata.json").to_vec(),
            },
            MetadataInput {
                target_id: "macos-x86_64".to_owned(),
                bytes: include_bytes!("fixtures/macos-x86_64-metadata.json").to_vec(),
            },
            MetadataInput {
                target_id: "linux-x86_64-ci".to_owned(),
                bytes: include_bytes!("fixtures/linux-x86_64-metadata.json").to_vec(),
            },
        ]
    }

    #[test]
    fn cross_target_records_prove_linux_only_unsound_findings_are_not_release_failures() {
        let report = verify(
            policy_bytes(),
            schema_bytes(),
            LOCK_BYTES,
            audit_bytes(),
            SOURCE_COMMIT,
            EVALUATED_AT,
            None,
            &metadata_inputs(),
        )
        .expect("cross-target report");

        assert_eq!(report.status, "PASS");
        assert_eq!(report.release_decision, "NOT_EVALUATED");
        assert!(!report.release);
        assert!(!report.deployment);
        assert_eq!(report.finding_count, 6);
        assert_eq!(report.code_failure_count, 0);
        assert_eq!(report.informational_warning_count, 6);

        let glib_linux = report
            .findings
            .iter()
            .find(|finding| finding.package.name == "glib" && finding.target == "linux-x86_64-ci")
            .expect("Linux glib record");
        assert_eq!(
            glib_linux.target_reachability,
            TargetReachability::Reachable
        );
        assert_eq!(
            glib_linux.disposition,
            FindingDisposition::InformationalWarning
        );
        assert_eq!(
            glib_linux.dependency_path,
            vec![
                "hartevo-desktop@0.1.0",
                "dioxus@0.7.10",
                "gtk@0.18.2",
                "glib@0.18.5"
            ]
        );

        let glib_macos = report
            .findings
            .iter()
            .find(|finding| finding.package.name == "glib" && finding.target == "macos-aarch64")
            .expect("macOS glib record");
        assert_eq!(
            glib_macos.target_reachability,
            TargetReachability::TargetUnreachable
        );
        assert_eq!(
            glib_macos.reachability_proof.reason,
            "package-not-present-in-target-metadata"
        );
        assert!(glib_macos.dependency_path.is_empty());

        let rand_linux = report
            .findings
            .iter()
            .find(|finding| finding.package.name == "rand" && finding.target == "linux-x86_64-ci")
            .expect("Linux rand record");
        assert_eq!(
            rand_linux.dependency_path,
            vec!["hartevo-desktop@0.1.0", "dioxus@0.7.10", "rand@0.7.3"]
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.source_commit == SOURCE_COMMIT)
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.lockfile_sha256 == report.lockfile_sha256)
        );
        let second_report = verify(
            policy_bytes(),
            schema_bytes(),
            LOCK_BYTES,
            audit_bytes(),
            SOURCE_COMMIT,
            EVALUATED_AT,
            None,
            &metadata_inputs(),
        )
        .expect("second deterministic cross-target report");
        assert_eq!(
            serde_json::to_vec(&report).expect("serialize first report"),
            serde_json::to_vec(&second_report).expect("serialize second report")
        );
    }

    #[test]
    fn expired_exact_exception_is_a_code_failure() {
        let report = verify(
            include_bytes!("fixtures/expired-exception-policy.json"),
            schema_bytes(),
            LOCK_BYTES,
            include_bytes!("fixtures/expired-exception-audit.json"),
            SOURCE_COMMIT,
            EVALUATED_AT,
            None,
            &metadata_inputs(),
        )
        .expect("expired-exception report");

        let expired = report
            .findings
            .iter()
            .find(|finding| finding.target == "macos-aarch64")
            .expect("expired exception record");
        assert_eq!(expired.disposition, FindingDisposition::CodeFailure);
        assert_eq!(expired.reason_code, "reviewed-exception-expired");
        assert_eq!(
            expired.exception.as_ref().map(|exception| exception.active),
            Some(false)
        );
        assert_eq!(report.status, "CODE_FAILURE");
        assert!(report.code_failure_count >= 1);
    }

    #[test]
    fn metadata_lock_digest_drift_fails_before_graph_evaluation() {
        let mut inputs = metadata_inputs();
        inputs[0].bytes = include_bytes!("fixtures/digest-drift-metadata.json").to_vec();
        let error = verify(
            policy_bytes(),
            schema_bytes(),
            LOCK_BYTES,
            audit_bytes(),
            SOURCE_COMMIT,
            EVALUATED_AT,
            None,
            &inputs,
        )
        .expect_err("digest drift must fail closed");
        assert!(error.to_string().contains("lockfileSha256 binding drift"));
    }

    #[test]
    fn unknown_audit_category_fails_closed() {
        let error = verify(
            policy_bytes(),
            schema_bytes(),
            LOCK_BYTES,
            include_bytes!("fixtures/unknown-category-audit.json"),
            SOURCE_COMMIT,
            EVALUATED_AT,
            None,
            &metadata_inputs(),
        )
        .expect_err("unknown advisory category must fail closed");
        assert!(error.to_string().contains("unknown advisory category"));
    }

    #[test]
    fn policy_and_schema_are_closed_contracts() {
        validate_policy_schema(schema_bytes()).expect("policy schema");
        let policy = parse_strict_json::<PolicyDocument>(policy_bytes()).expect("policy document");
        validate_policy(&policy).expect("policy document validation");
    }
}
