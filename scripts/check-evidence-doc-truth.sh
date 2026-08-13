#!/usr/bin/env bash
set -euo pipefail

emit_blocked_env() {
  local code="$1"
  local message="$2"
  printf '{"code":"%s","message":"%s","missionEvidenceLevelPromoted":false,"releaseDecision":"NOT_EVALUATED","releasePassed":false,"schema":"hartevo.current-evidence-truth-verification/v1","status":"BLOCKED_ENV","testMode":false}\n' \
    "$code" "$message"
  exit 2
}

command -v git >/dev/null 2>&1 || emit_blocked_env "GIT_NOT_AVAILABLE" "git is required"
command -v python3 >/dev/null 2>&1 || emit_blocked_env "PYTHON_NOT_AVAILABLE" "python3 is required"
command -v bash >/dev/null 2>&1 || emit_blocked_env "BASH_NOT_AVAILABLE" "bash is required"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || \
  emit_blocked_env "REPOSITORY_NOT_AVAILABLE" "run inside the Hartevo Git worktree"
mode="${1:-}"

case "$mode" in
  verify|self-test) ;;
  *)
    printf '%s\n' \
      '{"code":"USAGE","message":"usage: check-evidence-doc-truth.sh verify|self-test","missionEvidenceLevelPromoted":false,"releaseDecision":"NOT_EVALUATED","releasePassed":false,"schema":"hartevo.current-evidence-truth-verification/v1","status":"FAIL","testMode":false}'
    exit 2
    ;;
esac

python3 - "$repo_root" "$mode" <<'PY'
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "hartevo.current-evidence-truth-verification/v1"
CONTRACT_REL = "contracts/evidence/current-evidence-truth.v1.json"
CONTRACT_SHA256 = "f5a5f6486b865311a79f1a6f162ee8c9fc3a7e95938904d487d3e800536ba30e"
EXPECTED_CLAIM_IDS = (
    "EVDOC-EV03M-01",
    "EVDOC-B2-01",
    "EVDOC-B2P-01",
    "EVDOC-GAPS-01",
)


class GateError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GateError(code, message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GateError("DUPLICATE_OBJECT_KEY", f"duplicate object key: {key}")
        value[key] = item
    return value


def load_json(raw: bytes, label: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError("INVALID_JSON", f"{label} is not strict UTF-8 JSON: {error}") from error
    require(isinstance(parsed, dict), "INVALID_JSON_ROOT", f"{label} root must be an object")
    return parsed


def exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual_set = set(value.keys())
    require(
        actual_set == expected_set,
        "CONTRACT_SHAPE_MISMATCH",
        f"{label} keys differ: expected {sorted(expected_set)}, got {sorted(actual_set)}",
    )


def string_list(value: Any, label: str, *, sorted_values: bool = False) -> List[str]:
    require(isinstance(value, list), "CONTRACT_TYPE_MISMATCH", f"{label} must be an array")
    require(all(isinstance(item, str) and item for item in value), "CONTRACT_TYPE_MISMATCH", f"{label} must contain non-empty strings")
    result = list(value)
    require(len(result) == len(set(result)), "CONTRACT_DUPLICATE_VALUE", f"{label} contains duplicates")
    if sorted_values:
        require(result == sorted(result), "CONTRACT_UNSORTED_VALUE", f"{label} must be sorted")
    return result


REPO = Path(sys.argv[1]).resolve()
MODE = sys.argv[2]


def sanitize(message: str) -> str:
    return message.replace(str(REPO), "<repo>").replace(os.path.expanduser("~"), "<home>")


def run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(command),
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise GateError("COMMAND_FAILED", sanitize(f"command failed ({' '.join(command)}): {stderr}"))
    return completed


def git_bytes(*args: str) -> bytes:
    return run(("git",) + args).stdout


def git_text(*args: str) -> str:
    return git_bytes(*args).decode("utf-8", errors="strict").strip()


def git_ancestor(ancestor: str, descendant: str) -> bool:
    return run(("git", "merge-base", "--is-ancestor", ancestor, descendant), check=False).returncode == 0


def git_blob(commit: str, path: str) -> bytes:
    completed = run(("git", "show", f"{commit}:{path}"), check=False)
    require(completed.returncode == 0, "GIT_BLOB_MISSING", f"regular blob is missing at {commit}:{path}")
    return completed.stdout


def git_entry(commit: str, path: str) -> Tuple[str, str, str]:
    line = git_text("ls-tree", commit, "--", path)
    require(bool(line), "GIT_BLOB_MISSING", f"tree entry is missing at {commit}:{path}")
    match = re.fullmatch(r"([0-7]{6}) ([a-z]+) ([0-9a-f]+)\t(.+)", line)
    require(match is not None, "GIT_TREE_ENTRY_INVALID", f"cannot parse tree entry for {path}")
    mode, object_type, _object_id, actual_path = match.groups()
    require(actual_path == path, "GIT_TREE_ENTRY_INVALID", f"tree entry path drift for {path}")
    return mode, object_type, _object_id


def validate_contract(contract: Mapping[str, Any]) -> None:
    exact_keys(
        contract,
        ("schemaVersion", "contractId", "source", "commitBoundManifest", "runtimeRender", "unprovenEvidence", "documents", "gate"),
        "contract",
    )
    require(contract["schemaVersion"] == "hartevo.current-evidence-truth/v1", "CONTRACT_SCHEMA_MISMATCH", "unexpected contract schema")
    require(contract["contractId"] == "ev-doc-runtime-render-b2-v1", "CONTRACT_ID_MISMATCH", "unexpected contract id")

    source = contract["source"]
    require(isinstance(source, dict), "CONTRACT_TYPE_MISMATCH", "source must be an object")
    exact_keys(source, ("objectFormat", "commit", "tree"), "source")
    require(source["objectFormat"] == "sha1", "CONTRACT_OBJECT_FORMAT_MISMATCH", "source object format must be sha1")
    for field in ("commit", "tree"):
        require(bool(re.fullmatch(r"[0-9a-f]{40}", source[field])), "CONTRACT_GIT_ID_INVALID", f"source.{field} must be a SHA-1 object id")

    manifest = contract["commitBoundManifest"]
    require(isinstance(manifest, dict), "CONTRACT_TYPE_MISMATCH", "commitBoundManifest must be an object")
    exact_keys(
        manifest,
        ("claimId", "path", "sourceCommit", "materializationCommit", "rawSha256", "bytes", "verifier", "expectedVerification"),
        "commitBoundManifest",
    )
    require(manifest["claimId"] == "EVDOC-EV03M-01", "CONTRACT_CLAIM_MISMATCH", "unexpected manifest claim id")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", manifest["rawSha256"])), "CONTRACT_DIGEST_INVALID", "manifest digest must be SHA-256")
    require(isinstance(manifest["bytes"], int) and manifest["bytes"] > 0, "CONTRACT_TYPE_MISMATCH", "manifest bytes must be positive")

    verifier = manifest["verifier"]
    require(isinstance(verifier, dict), "CONTRACT_TYPE_MISMATCH", "manifest verifier must be an object")
    exact_keys(verifier, ("path", "mode", "rawSha256", "bytes"), "commitBoundManifest.verifier")
    require(verifier["mode"] == "100755", "CONTRACT_MODE_MISMATCH", "manifest verifier must be mode 100755")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", verifier["rawSha256"])), "CONTRACT_DIGEST_INVALID", "verifier digest must be SHA-256")
    require(isinstance(verifier["bytes"], int) and verifier["bytes"] > 0, "CONTRACT_TYPE_MISMATCH", "verifier bytes must be positive")

    expected = manifest["expectedVerification"]
    require(isinstance(expected, dict), "CONTRACT_TYPE_MISMATCH", "expectedVerification must be an object")
    exact_keys(
        expected,
        ("code", "verificationStatus", "releaseDecision", "testMode", "artifactCount", "claimCount", "requiredClaimCount", "authority"),
        "commitBoundManifest.expectedVerification",
    )
    require(expected["code"] == "COMMIT_BOUND_MANIFEST_VERIFIED", "MANIFEST_AUTHORITY_ESCALATION", "manifest verifier code drift")
    require(expected["verificationStatus"] == "VERIFIED", "MANIFEST_AUTHORITY_ESCALATION", "manifest integrity status drift")
    require(expected["releaseDecision"] == "NOT_EVALUATED", "MANIFEST_AUTHORITY_ESCALATION", "manifest cannot grant Release authority")
    require(expected["testMode"] is False, "MANIFEST_AUTHORITY_ESCALATION", "tracked manifest verification must not be test mode")
    require(expected["authority"] == "MANIFEST_INTEGRITY_ONLY", "MANIFEST_AUTHORITY_ESCALATION", "manifest authority must remain integrity-only")
    for field in ("artifactCount", "claimCount", "requiredClaimCount"):
        require(isinstance(expected[field], int) and expected[field] >= 0, "CONTRACT_TYPE_MISMATCH", f"{field} must be a non-negative integer")

    runtime = contract["runtimeRender"]
    require(isinstance(runtime, dict), "CONTRACT_TYPE_MISMATCH", "runtimeRender must be an object")
    exact_keys(runtime, ("implementationStatus", "b2", "b2p"), "runtimeRender")
    require(runtime["implementationStatus"] == "CODE_WIRED", "RUNTIME_AUTHORITY_ESCALATION", "runtime render authority must remain CODE_WIRED")
    for unit_name, expected_claim in (("b2", "EVDOC-B2-01"), ("b2p", "EVDOC-B2P-01")):
        unit = runtime[unit_name]
        require(isinstance(unit, dict), "CONTRACT_TYPE_MISMATCH", f"runtimeRender.{unit_name} must be an object")
        exact_keys(unit, ("claimId", "commit", "parent", "changedFiles", "requiredAnchors"), f"runtimeRender.{unit_name}")
        require(unit["claimId"] == expected_claim, "CONTRACT_CLAIM_MISMATCH", f"unexpected {unit_name} claim id")
        for field in ("commit", "parent"):
            require(bool(re.fullmatch(r"[0-9a-f]{40}", unit[field])), "CONTRACT_GIT_ID_INVALID", f"{unit_name}.{field} must be a SHA-1 id")
        changed_files = string_list(unit["changedFiles"], f"runtimeRender.{unit_name}.changedFiles", sorted_values=True)
        anchors = unit["requiredAnchors"]
        require(isinstance(anchors, dict), "CONTRACT_TYPE_MISMATCH", f"runtimeRender.{unit_name}.requiredAnchors must be an object")
        require(set(anchors.keys()).issubset(set(changed_files)), "CONTRACT_SCOPE_MISMATCH", f"{unit_name} anchors must belong to changed files")
        for path, values in anchors.items():
            string_list(values, f"runtimeRender.{unit_name}.requiredAnchors[{path}]")

    gaps = contract["unprovenEvidence"]
    require(isinstance(gaps, dict), "CONTRACT_TYPE_MISMATCH", "unprovenEvidence must be an object")
    exact_keys(
        gaps,
        ("claimId", "scope", "nativeVisual", "nativeAccessibility", "processRestart", "releaseEvidence", "releasePassed", "releaseDecision", "missionEvidenceLevelPromoted", "legacyVisualOrAccessibilityMaySatisfy"),
        "unprovenEvidence",
    )
    require(gaps["claimId"] == "EVDOC-GAPS-01", "CONTRACT_CLAIM_MISMATCH", "unexpected gap claim id")
    require(gaps["scope"] == "CURRENT_B2_B2P_FLOW", "CONTRACT_SCOPE_MISMATCH", "unproven evidence must stay scoped to the current B2/B2P flow")
    for field in ("nativeVisual", "nativeAccessibility", "processRestart", "releaseEvidence"):
        require(gaps[field] == "NOT_PROVEN", "CONTRACT_EVIDENCE_ESCALATION", f"{field} must remain NOT_PROVEN")
    require(gaps["releasePassed"] is False, "CONTRACT_RELEASE_ESCALATION", "Release passed must remain false")
    require(gaps["releaseDecision"] == "NOT_EVALUATED", "CONTRACT_RELEASE_ESCALATION", "Release decision must remain NOT_EVALUATED")
    require(gaps["missionEvidenceLevelPromoted"] is False, "CONTRACT_ELEVEL_ESCALATION", "Mission evidence level must not be promoted")
    require(gaps["legacyVisualOrAccessibilityMaySatisfy"] is False, "CONTRACT_EVIDENCE_ESCALATION", "legacy visual/AX cannot satisfy current evidence")

    documents = contract["documents"]
    require(isinstance(documents, list) and len(documents) == 2, "CONTRACT_DOCUMENT_SCOPE_MISMATCH", "exactly two document projections are required")
    document_paths: List[str] = []
    for index, document in enumerate(documents):
        require(isinstance(document, dict), "CONTRACT_TYPE_MISMATCH", f"documents[{index}] must be an object")
        exact_keys(document, ("path", "requiredLines"), f"documents[{index}]")
        require(isinstance(document["path"], str) and document["path"], "CONTRACT_TYPE_MISMATCH", f"documents[{index}].path must be a string")
        document_paths.append(document["path"])
        required_lines = string_list(document["requiredLines"], f"documents[{index}].requiredLines")
        projected_ids = [claim_id for line in required_lines for claim_id in EXPECTED_CLAIM_IDS if claim_id in line]
        require(sorted(projected_ids) == sorted(EXPECTED_CLAIM_IDS), "CONTRACT_CLAIM_MISMATCH", f"{document['path']} must project every claim exactly once")
    require(document_paths == sorted(document_paths), "CONTRACT_UNSORTED_VALUE", "document paths must be sorted")

    gate = contract["gate"]
    require(isinstance(gate, dict), "CONTRACT_TYPE_MISMATCH", "gate must be an object")
    exact_keys(gate, ("command", "selfTestCommand", "successCode", "successStatus", "releaseDecision", "releasePassed", "missionEvidenceLevelPromoted"), "gate")
    require(gate["command"] == "bash scripts/check-evidence-doc-truth.sh verify", "CONTRACT_GATE_MISMATCH", "verify command drift")
    require(gate["selfTestCommand"] == "bash scripts/check-evidence-doc-truth.sh self-test", "CONTRACT_GATE_MISMATCH", "self-test command drift")
    require(gate["successCode"] == "EVIDENCE_DOC_TRUTH_VERIFIED" and gate["successStatus"] == "VERIFIED", "CONTRACT_GATE_MISMATCH", "success envelope drift")
    require(gate["releaseDecision"] == "NOT_EVALUATED" and gate["releasePassed"] is False, "CONTRACT_RELEASE_ESCALATION", "gate cannot grant Release authority")
    require(gate["missionEvidenceLevelPromoted"] is False, "CONTRACT_ELEVEL_ESCALATION", "gate cannot promote Mission evidence level")


def verify_source(contract: Mapping[str, Any]) -> str:
    source = contract["source"]
    head = git_text("rev-parse", "HEAD")
    object_format = git_text("rev-parse", "--show-object-format")
    require(object_format == source["objectFormat"], "SOURCE_OBJECT_FORMAT_MISMATCH", "repository object format differs from the contract")
    require(git_ancestor(source["commit"], head), "SOURCE_NOT_ANCESTOR", "current HEAD is not based on the contracted source baseline")
    actual_tree = git_text("rev-parse", f"{source['commit']}^{{tree}}")
    require(actual_tree == source["tree"], "SOURCE_TREE_MISMATCH", "source tree does not match the contract")
    return head


def verify_manifest(contract: Mapping[str, Any]) -> Dict[str, Any]:
    manifest = contract["commitBoundManifest"]
    source_commit = manifest["sourceCommit"]
    materialization_commit = manifest["materializationCommit"]
    parents = git_text("rev-list", "--parents", "-n", "1", materialization_commit).split()
    require(parents == [materialization_commit, source_commit], "MANIFEST_PARENT_MISMATCH", "materialization commit must be the direct single child of its source")

    diff_lines = git_text("diff-tree", "--no-commit-id", "--name-status", "-r", source_commit, materialization_commit).splitlines()
    require(diff_lines == [f"A\t{manifest['path']}"], "MANIFEST_COMMIT_SCOPE_MISMATCH", "materialization commit must add exactly the manifest blob")
    mode, object_type, _object_id = git_entry(materialization_commit, manifest["path"])
    require((mode, object_type) == ("100644", "blob"), "MANIFEST_BLOB_MODE_MISMATCH", "tracked manifest must be a regular 100644 blob")
    source_probe = run(("git", "cat-file", "-e", f"{source_commit}:{manifest['path']}"), check=False)
    require(source_probe.returncode != 0, "MANIFEST_SELF_REFERENCE", "manifest path must not exist in its source commit")

    raw = git_blob(materialization_commit, manifest["path"])
    require(len(raw) == manifest["bytes"], "MANIFEST_BYTES_MISMATCH", "manifest byte count differs")
    require(sha256(raw) == manifest["rawSha256"], "MANIFEST_DIGEST_MISMATCH", "manifest raw SHA-256 differs")

    verifier = manifest["verifier"]
    verifier_mode, verifier_type, _verifier_id = git_entry(contract["source"]["commit"], verifier["path"])
    require((verifier_mode, verifier_type) == (verifier["mode"], "blob"), "MANIFEST_VERIFIER_MODE_MISMATCH", "manifest verifier mode differs")
    verifier_raw = git_blob(contract["source"]["commit"], verifier["path"])
    require(len(verifier_raw) == verifier["bytes"], "MANIFEST_VERIFIER_BYTES_MISMATCH", "manifest verifier byte count differs")
    require(sha256(verifier_raw) == verifier["rawSha256"], "MANIFEST_VERIFIER_DIGEST_MISMATCH", "manifest verifier source digest differs")
    working_verifier = REPO / verifier["path"]
    verifier_stat = working_verifier.lstat()
    require(stat.S_ISREG(verifier_stat.st_mode) and not working_verifier.is_symlink(), "MANIFEST_VERIFIER_NOT_REGULAR", "manifest verifier working path must be regular")
    require(working_verifier.read_bytes() == verifier_raw, "MANIFEST_VERIFIER_WORKTREE_DRIFT", "manifest verifier working bytes differ from the source baseline")

    completed = run(
        (
            "bash",
            verifier["path"],
            "verify",
            "--manifest-commit",
            materialization_commit,
            "--expected-source",
            source_commit,
            "--expected-manifest-sha256",
            manifest["rawSha256"],
        ),
        check=False,
    )
    require(completed.returncode == 0, "MANIFEST_VERIFIER_FAILED", sanitize(completed.stderr.decode("utf-8", errors="replace").strip() or "manifest verifier returned nonzero"))
    lines = completed.stdout.decode("utf-8", errors="strict").strip().splitlines()
    require(len(lines) == 1, "MANIFEST_VERIFIER_OUTPUT_INVALID", "manifest verifier must emit exactly one JSON line")
    receipt = load_json(lines[0].encode("utf-8"), "manifest verifier receipt")
    expected = manifest["expectedVerification"]
    comparisons = {
        "code": expected["code"],
        "status": expected["verificationStatus"],
        "releaseDecision": expected["releaseDecision"],
        "testMode": expected["testMode"],
        "artifactCount": expected["artifactCount"],
        "claimCount": expected["claimCount"],
        "requiredClaimCount": expected["requiredClaimCount"],
        "manifestCommit": materialization_commit,
        "sourceCommit": source_commit,
        "manifestPath": manifest["path"],
        "manifestSha256": manifest["rawSha256"],
    }
    for field, expected_value in comparisons.items():
        require(receipt.get(field) == expected_value, "MANIFEST_RECEIPT_MISMATCH", f"manifest receipt {field} differs")
    return receipt


def verify_runtime_unit(unit_name: str, unit: Mapping[str, Any], source_commit: str) -> None:
    commit = unit["commit"]
    parent = unit["parent"]
    parents = git_text("rev-list", "--parents", "-n", "1", commit).split()
    require(parents == [commit, parent], "RUNTIME_COMMIT_PARENT_MISMATCH", f"{unit_name} commit parent differs")
    require(git_ancestor(commit, source_commit), "RUNTIME_COMMIT_NOT_IN_SOURCE", f"{unit_name} commit is not in the source baseline")

    diff_lines = git_text("diff-tree", "--no-commit-id", "--name-status", "-r", parent, commit).splitlines()
    changed: List[str] = []
    for line in diff_lines:
        parts = line.split("\t")
        require(len(parts) == 2 and parts[0] == "M", "RUNTIME_COMMIT_SCOPE_MISMATCH", f"{unit_name} must only modify regular source paths")
        changed.append(parts[1])
    require(sorted(changed) == unit["changedFiles"], "RUNTIME_COMMIT_SCOPE_MISMATCH", f"{unit_name} changed-file set differs")

    anchors: Mapping[str, List[str]] = unit["requiredAnchors"]
    for path in unit["changedFiles"]:
        commit_mode, commit_type, _commit_id = git_entry(commit, path)
        source_mode, source_type, _source_id = git_entry(source_commit, path)
        require((commit_mode, commit_type) == ("100644", "blob"), "RUNTIME_SOURCE_MODE_MISMATCH", f"{unit_name} commit source must be regular 100644")
        require((source_mode, source_type) == ("100644", "blob"), "RUNTIME_SOURCE_MODE_MISMATCH", f"{unit_name} baseline source must be regular 100644")
        commit_text = git_blob(commit, path).decode("utf-8", errors="strict")
        source_text = git_blob(source_commit, path).decode("utf-8", errors="strict")
        for anchor in anchors.get(path, []):
            require(anchor in commit_text, "SOURCE_ANCHOR_MISSING", f"{unit_name} anchor missing from its commit: {path}")
            require(anchor in source_text, "SOURCE_ANCHOR_MISSING", f"{unit_name} anchor missing from the source baseline: {path}")


def read_document(path: str, overrides: Optional[Mapping[str, str]]) -> str:
    if overrides is not None and path in overrides:
        return overrides[path]
    absolute = REPO / path
    try:
        path_stat = absolute.lstat()
    except FileNotFoundError as error:
        raise GateError("DOCUMENT_MISSING", f"document is missing: {path}") from error
    require(stat.S_ISREG(path_stat.st_mode) and not absolute.is_symlink(), "DOCUMENT_NOT_REGULAR", f"document must be a regular file: {path}")
    return absolute.read_text(encoding="utf-8")


def verify_documents(contract: Mapping[str, Any], overrides: Optional[Mapping[str, str]] = None) -> None:
    for document in contract["documents"]:
        path = document["path"]
        text = read_document(path, overrides)
        lines = text.splitlines()
        claim_lines = [line for line in lines if any(claim_id in line for claim_id in EXPECTED_CLAIM_IDS)]

        for line in claim_lines:
            lower = line.lower()
            if re.search(r"passed\s*[:=]\s*true", lower):
                raise GateError("DOCUMENT_RELEASE_ESCALATION", f"Release was promoted in {path}")
            if re.search(r"(?<!not_)\bproven\b", lower):
                raise GateError("DOCUMENT_EVIDENCE_ESCALATION", f"unproven evidence was promoted in {path}")
            if re.search(r"\bE[3-5]\b", line) or "E-level 已提升" in line or "E-level 提升" in line:
                raise GateError("DOCUMENT_ELEVEL_ESCALATION", f"Mission evidence level was promoted in {path}")

        require(claim_lines == document["requiredLines"], "DOCUMENT_CLAIM_PROJECTION_DRIFT", f"machine-gated Claim ID projection differs in {path}")
        for required_line in document["requiredLines"]:
            require(lines.count(required_line) == 1, "DOCUMENT_CLAIM_PROJECTION_DRIFT", f"required claim line must appear exactly once in {path}")

        if path.endswith("DEVELOPMENT-VALIDATION-LADDER.md"):
            require(lines.count("bash scripts/check-evidence-doc-truth.sh verify") == 1, "DOCUMENT_GATE_COMMAND_DRIFT", "validation ladder must list the verify command once")
            require(lines.count("bash scripts/check-evidence-doc-truth.sh self-test") == 1, "DOCUMENT_GATE_COMMAND_DRIFT", "validation ladder must list the self-test command once")
        if path.endswith("CURRENT-WORKTREE-EVIDENCE.md"):
            require(CONTRACT_REL in text, "DOCUMENT_CONTRACT_REFERENCE_MISSING", "current evidence must reference the machine contract")
            require("scripts/check-evidence-doc-truth.sh" in text, "DOCUMENT_GATE_REFERENCE_MISSING", "current evidence must reference the executable gate")


def verify_all(contract: Mapping[str, Any], overrides: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    validate_contract(contract)
    head = verify_source(contract)
    manifest_receipt = verify_manifest(contract)
    source_commit = contract["source"]["commit"]
    verify_runtime_unit("b2", contract["runtimeRender"]["b2"], source_commit)
    verify_runtime_unit("b2p", contract["runtimeRender"]["b2p"], source_commit)
    verify_documents(contract, overrides)
    return {
        "head": head,
        "manifest": manifest_receipt,
    }


def expect_error(checks: List[str], check_id: str, expected_code: str, operation: Any) -> None:
    try:
        operation()
    except GateError as error:
        require(error.code == expected_code, "SELF_TEST_WRONG_FAILURE", f"{check_id} returned {error.code}, expected {expected_code}")
        checks.append(check_id)
        return
    raise GateError("SELF_TEST_FALSE_PASS", f"{check_id} unexpectedly passed")


def load_contract() -> Tuple[bytes, Dict[str, Any]]:
    contract_path = REPO / CONTRACT_REL
    try:
        path_stat = contract_path.lstat()
    except FileNotFoundError as error:
        raise GateError("CONTRACT_MISSING", "current evidence truth contract is missing") from error
    require(stat.S_ISREG(path_stat.st_mode) and not contract_path.is_symlink(), "CONTRACT_NOT_REGULAR", "contract must be a regular file")
    raw = contract_path.read_bytes()
    contract = load_json(raw, CONTRACT_REL)
    require(sha256(raw) == CONTRACT_SHA256, "CONTRACT_DIGEST_MISMATCH", "contract raw SHA-256 differs from the verifier pin")
    return raw, contract


def emit(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


try:
    contract_raw, contract_data = load_contract()
    if MODE == "verify":
        result = verify_all(contract_data)
        gaps = contract_data["unprovenEvidence"]
        emit(
            {
                "claimCount": len(EXPECTED_CLAIM_IDS),
                "code": contract_data["gate"]["successCode"],
                "contractSha256": CONTRACT_SHA256,
                "evidenceScope": gaps["scope"],
                "head": result["head"],
                "manifestCode": result["manifest"]["code"],
                "manifestVerificationStatus": result["manifest"]["status"],
                "missionEvidenceLevelPromoted": gaps["missionEvidenceLevelPromoted"],
                "nativeAccessibility": gaps["nativeAccessibility"],
                "nativeVisual": gaps["nativeVisual"],
                "processRestart": gaps["processRestart"],
                "releaseDecision": gaps["releaseDecision"],
                "releaseEvidence": gaps["releaseEvidence"],
                "releasePassed": gaps["releasePassed"],
                "runtimeRenderStatus": contract_data["runtimeRender"]["implementationStatus"],
                "schema": SCHEMA,
                "sourceCommit": contract_data["source"]["commit"],
                "status": contract_data["gate"]["successStatus"],
                "testMode": False,
            }
        )
    else:
        checks: List[str] = []
        verify_all(contract_data)
        checks.append("positive-current-repository")

        duplicate_raw = contract_raw.replace(b"{", b'{"schemaVersion":"duplicate",', 1)
        expect_error(
            checks,
            "raw-duplicate-object-key",
            "DUPLICATE_OBJECT_KEY",
            lambda: load_json(duplicate_raw, "duplicate contract mutation"),
        )

        release_contract = copy.deepcopy(contract_data)
        release_contract["unprovenEvidence"]["releasePassed"] = True
        expect_error(checks, "contract-release-escalation", "CONTRACT_RELEASE_ESCALATION", lambda: verify_all(release_contract))

        manifest_contract = copy.deepcopy(contract_data)
        manifest_contract["commitBoundManifest"]["expectedVerification"]["releaseDecision"] = "VERIFIED"
        expect_error(checks, "manifest-authority-escalation", "MANIFEST_AUTHORITY_ESCALATION", lambda: verify_all(manifest_contract))

        runtime_contract = copy.deepcopy(contract_data)
        runtime_contract["runtimeRender"]["implementationStatus"] = "NATIVE_PROVEN"
        expect_error(checks, "runtime-authority-escalation", "RUNTIME_AUTHORITY_ESCALATION", lambda: verify_all(runtime_contract))

        gap_contract = copy.deepcopy(contract_data)
        gap_contract["unprovenEvidence"]["nativeVisual"] = "PROVEN"
        expect_error(checks, "native-evidence-escalation", "CONTRACT_EVIDENCE_ESCALATION", lambda: verify_all(gap_contract))

        anchor_contract = copy.deepcopy(contract_data)
        anchor_contract["runtimeRender"]["b2"]["requiredAnchors"]["hartevo-rs/desktop/src/lib.rs"].append("fn fabricated_native_release_authority()")
        expect_error(checks, "missing-source-anchor", "SOURCE_ANCHOR_MISSING", lambda: verify_all(anchor_contract))

        scope_contract = copy.deepcopy(contract_data)
        scope_contract["runtimeRender"]["b2p"]["changedFiles"].append("hartevo-rs/desktop/src/runtime_subscription.rs")
        expect_error(checks, "commit-scope-drift", "RUNTIME_COMMIT_SCOPE_MISMATCH", lambda: verify_all(scope_contract))

        source_contract = copy.deepcopy(contract_data)
        source_contract["source"]["tree"] = "0" * 40
        expect_error(checks, "source-tree-drift", "SOURCE_TREE_MISMATCH", lambda: verify_all(source_contract))

        object_format_contract = copy.deepcopy(contract_data)
        object_format_contract["source"]["objectFormat"] = "sha256"
        expect_error(checks, "source-object-format-drift", "CONTRACT_OBJECT_FORMAT_MISMATCH", lambda: verify_all(object_format_contract))

        doc_texts = {document["path"]: read_document(document["path"], None) for document in contract_data["documents"]}
        current_path = "docs/quality/CURRENT-WORKTREE-EVIDENCE.md"
        release_doc = dict(doc_texts)
        release_doc[current_path] = release_doc[current_path].replace("Release `passed=false`", "Release `passed=true`", 1)
        expect_error(checks, "document-release-escalation", "DOCUMENT_RELEASE_ESCALATION", lambda: verify_documents(contract_data, release_doc))

        evidence_doc = dict(doc_texts)
        evidence_doc[current_path] = evidence_doc[current_path].replace("均为 `NOT_PROVEN`", "均为 `PROVEN`", 1)
        expect_error(checks, "document-native-evidence-escalation", "DOCUMENT_EVIDENCE_ESCALATION", lambda: verify_documents(contract_data, evidence_doc))

        elevel_doc = dict(doc_texts)
        elevel_doc[current_path] = elevel_doc[current_path].replace("Mission E-level 未提升", "Mission E3", 1)
        expect_error(checks, "document-elevel-escalation", "DOCUMENT_ELEVEL_ESCALATION", lambda: verify_documents(contract_data, elevel_doc))

        claim_doc = dict(doc_texts)
        claim_doc[current_path] = claim_doc[current_path].replace("EVDOC-B2P-01", "REMOVED-B2P-CLAIM", 1)
        expect_error(checks, "document-claim-removal", "DOCUMENT_CLAIM_PROJECTION_DRIFT", lambda: verify_documents(contract_data, claim_doc))

        checks.sort()
        require(checks == sorted(checks), "SELF_TEST_CHECK_ORDER", "self-test checks must be sorted and unique")
        require(len(checks) == len(set(checks)), "SELF_TEST_CHECK_DUPLICATE", "self-test checks must be unique")
        emit(
            {
                "checks": checks,
                "checksPassed": len(checks),
                "code": "EVIDENCE_DOC_TRUTH_SELF_TEST_VERIFIED",
                "contractSha256": CONTRACT_SHA256,
                "missionEvidenceLevelPromoted": False,
                "releaseDecision": "NOT_EVALUATED",
                "releasePassed": False,
                "schema": SCHEMA,
                "status": "VERIFIED",
                "testMode": True,
            }
        )
except GateError as error:
    emit(
        {
            "code": error.code,
            "message": sanitize(error.message),
            "missionEvidenceLevelPromoted": False,
            "releaseDecision": "NOT_EVALUATED",
            "releasePassed": False,
            "schema": SCHEMA,
            "status": "FAIL",
            "testMode": MODE == "self-test",
        }
    )
    sys.exit(1)
except Exception as error:  # Fail closed on unexpected parser, filesystem, or process errors.
    emit(
        {
            "code": "INTERNAL_ERROR",
            "message": sanitize(str(error)),
            "missionEvidenceLevelPromoted": False,
            "releaseDecision": "NOT_EVALUATED",
            "releasePassed": False,
            "schema": SCHEMA,
            "status": "FAIL",
            "testMode": MODE == "self-test",
        }
    )
    sys.exit(1)
PY
