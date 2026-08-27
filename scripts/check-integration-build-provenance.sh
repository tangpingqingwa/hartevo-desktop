#!/usr/bin/env bash
set -euo pipefail

emit_blocked_env() {
  local code="$1"
  local message="$2"
  printf '{"authority":"INTEGRATION_BUILD_PROVENANCE_ONLY","code":"%s","message":"%s","missionEvidenceLevelPromoted":false,"releaseDecision":"NOT_EVALUATED","releasePassed":false,"schema":"hartevo.integration-build-provenance-verification/v1","status":"BLOCKED_ENV","testMode":false}\n' \
    "$code" "$message"
  exit 2
}

command -v git >/dev/null 2>&1 || emit_blocked_env "GIT_NOT_AVAILABLE" "git is required"
command -v python3 >/dev/null 2>&1 || emit_blocked_env "PYTHON_NOT_AVAILABLE" "python3 is required"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || \
  emit_blocked_env "REPOSITORY_NOT_AVAILABLE" "run inside the Hartevo Git worktree"
mode="${1:-}"

case "$mode" in
  verify|self-test) ;;
  *)
    printf '%s\n' \
      '{"authority":"INTEGRATION_BUILD_PROVENANCE_ONLY","code":"USAGE","message":"usage: check-integration-build-provenance.sh verify|self-test","missionEvidenceLevelPromoted":false,"releaseDecision":"NOT_EVALUATED","releasePassed":false,"schema":"hartevo.integration-build-provenance-verification/v1","status":"FAIL","testMode":false}'
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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "hartevo.integration-build-provenance-verification/v1"
AUTHORITY = "INTEGRATION_BUILD_PROVENANCE_ONLY"
CONTRACT_REL = "contracts/evidence/integration-build-provenance.v1.json"
CONTRACT_SHA256 = "084d0549c2cb98f46fa48ed8d54209b38850b917f1cd7fa8d2f91b24de4e6bb3"
EXPECTED_FAIL_CODES = [
    "CANDIDATE_CI_HEAD_MISMATCH",
    "CANDIDATE_CI_NOT_EXECUTED",
    "CI_CONCLUSION_NOT_SUCCESS",
    "CI_HEAD_MISMATCH",
    "CI_JOB_MISSING",
    "CI_JOB_NOT_SUCCESS",
    "CI_RUN_MISSING",
    "CI_RUN_POLICY_MISMATCH",
    "CI_STATUS_NOT_COMPLETED",
    "CONTRACT_DIGEST_MISMATCH",
    "CURRENT_COMMIT_MISMATCH",
    "EVIDENCE_ROLE_MISSING",
    "HEAD_NOT_DESCENDANT",
    "HISTORICAL_ARTIFACT_STALE",
    "INTEGRATION_HEAD_MISMATCH",
    "MANIFEST_DIGEST_MISMATCH",
    "MANIFEST_SOURCE_MISMATCH",
    "NATIVE_EVIDENCE_ESCALATION",
    "PR_BASE_ANCESTRY_MISMATCH",
    "PR_BASE_MISMATCH",
    "PR_DRAFT",
    "PR_HEAD_MISMATCH",
    "PR_MERGE_CHAIN_MISMATCH",
    "PR_NOT_MERGED",
    "RAW_ARTIFACT_DIGEST_MISMATCH",
    "RELEASE_AUTHORITY_ESCALATION",
    "REVERT_HISTORY_MISMATCH",
]
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
ISO_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


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
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError("DUPLICATE_OBJECT_KEY", f"duplicate object key: {key}")
        result[key] = value
    return result


def load_json(raw: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError("INVALID_JSON", f"{label} is not strict UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), "INVALID_JSON_ROOT", f"{label} root must be an object")
    return value


def exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value.keys())
    wanted = set(expected)
    require(actual == wanted, "SCHEMA_SHAPE_MISMATCH", f"{label} keys differ: expected {sorted(wanted)}, got {sorted(actual)}")


def nonempty_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value), "SCHEMA_TYPE_MISMATCH", f"{label} must be a non-empty string")
    return value


def positive_int(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0, "SCHEMA_TYPE_MISMATCH", f"{label} must be a positive integer")
    return value


def git_id(value: Any, label: str) -> str:
    text = nonempty_string(value, label)
    require(bool(HEX_40.fullmatch(text)), "SCHEMA_GIT_ID_INVALID", f"{label} must be a 40-character SHA-1 id")
    return text


def digest(value: Any, label: str) -> str:
    text = nonempty_string(value, label)
    require(bool(HEX_64.fullmatch(text)), "SCHEMA_DIGEST_INVALID", f"{label} must be a SHA-256 digest")
    return text


def safe_relative_path(value: Any, label: str) -> str:
    text = nonempty_string(value, label)
    path = PurePosixPath(text)
    require(not path.is_absolute() and ".." not in path.parts and text == path.as_posix(), "SCHEMA_PATH_INVALID", f"{label} must be a normalized relative path")
    return text


def utc_time(value: Any, label: str) -> datetime:
    text = nonempty_string(value, label)
    require(bool(ISO_UTC.fullmatch(text)), "SCHEMA_TIME_INVALID", f"{label} must be second-precision UTC")
    return datetime.fromisoformat(text[:-1] + "+00:00").astimezone(timezone.utc)


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


def git_text(*args: str) -> str:
    return run(("git",) + args).stdout.decode("utf-8", errors="strict").strip()


def git_ancestor(ancestor: str, descendant: str) -> bool:
    return run(("git", "merge-base", "--is-ancestor", ancestor, descendant), check=False).returncode == 0


def read_regular(relative: str, missing_code: str) -> bytes:
    absolute = REPO / relative
    try:
        path_stat = absolute.lstat()
    except FileNotFoundError as error:
        raise GateError(missing_code, f"required file is missing: {relative}") from error
    require(stat.S_ISREG(path_stat.st_mode) and not absolute.is_symlink(), "ARTIFACT_NOT_REGULAR", f"required path must be a regular file: {relative}")
    return absolute.read_bytes()


def validate_instance_ref(instance: Mapping[str, Any], label: str) -> None:
    require(isinstance(instance, dict), "SCHEMA_TYPE_MISMATCH", f"{label} must be an object")
    exact_keys(instance, ("manifestPath", "manifestSha256", "manifestBytes", "rawArtifactPath", "rawArtifactSha256", "rawArtifactBytes"), label)
    safe_relative_path(instance["manifestPath"], f"{label}.manifestPath")
    digest(instance["manifestSha256"], f"{label}.manifestSha256")
    positive_int(instance["manifestBytes"], f"{label}.manifestBytes")
    safe_relative_path(instance["rawArtifactPath"], f"{label}.rawArtifactPath")
    digest(instance["rawArtifactSha256"], f"{label}.rawArtifactSha256")
    positive_int(instance["rawArtifactBytes"], f"{label}.rawArtifactBytes")


def validate_contract(contract: Mapping[str, Any]) -> None:
    exact_keys(
        contract,
        ("schemaVersion", "contractId", "authority", "currentInstance", "historicalInstance", "currentBaseline", "candidatePolicy", "nativeEvidencePolicy", "evidenceRolePolicy", "source", "pullRequestPolicy", "integrationHistoryPolicy", "ciPolicy", "resultPolicy", "failClosedCodes", "gate"),
        "contract",
    )
    require(contract["schemaVersion"] == "hartevo.integration-build-provenance-contract/v1", "CONTRACT_SCHEMA_MISMATCH", "unexpected contract schema")
    require(contract["contractId"] == "ev-04-integration-build-provenance-v1", "CONTRACT_ID_MISMATCH", "unexpected contract id")
    require(contract["authority"] == AUTHORITY, "RELEASE_AUTHORITY_ESCALATION", "contract authority must remain integration provenance only")

    validate_instance_ref(contract["currentInstance"], "currentInstance")
    validate_instance_ref(contract["historicalInstance"], "historicalInstance")

    baseline = contract["currentBaseline"]
    require(isinstance(baseline, dict), "SCHEMA_TYPE_MISMATCH", "currentBaseline must be an object")
    exact_keys(
        baseline,
        ("ref", "commit", "tree", "requireExactCheckout", "artifactStatus", "historicalArtifactHead", "staleReason"),
        "currentBaseline",
    )
    require(baseline["ref"] == "origin/bootstrap/macos-r0", "CURRENT_COMMIT_MISMATCH", "current baseline ref differs")
    git_id(baseline["commit"], "currentBaseline.commit")
    git_id(baseline["tree"], "currentBaseline.tree")
    require(baseline["requireExactCheckout"] is True, "CURRENT_COMMIT_MISMATCH", "current baseline must require exact checkout")
    require(baseline["artifactStatus"] == "CURRENT_CANDIDATE_DRAFT_CI_GREEN", "HISTORICAL_ARTIFACT_STALE", "artifact status must remain draft-pending despite green candidate CI")
    git_id(baseline["historicalArtifactHead"], "currentBaseline.historicalArtifactHead")
    require(baseline["historicalArtifactHead"] == contract["source"]["headCommit"], "HISTORICAL_ARTIFACT_STALE", "historical artifact head must match source head")
    nonempty_string(baseline["staleReason"], "currentBaseline.staleReason")

    source = contract["source"]
    require(isinstance(source, dict), "SCHEMA_TYPE_MISMATCH", "source must be an object")
    exact_keys(source, ("repository", "branch", "objectFormat", "rangeBaseCommit", "headCommit", "headTree", "expectedFirstParentCommitCount", "expectedFeaturePullRequestMergeCount", "expectedRevertCommitCount"), "source")
    require(source["repository"] == "tangpingqingwa/hartevo-desktop", "MANIFEST_SOURCE_MISMATCH", "repository differs")
    require(source["branch"] == "bootstrap/macos-r0", "PR_BASE_MISMATCH", "integration branch differs")
    require(source["objectFormat"] == "sha1", "MANIFEST_SOURCE_MISMATCH", "object format differs")
    git_id(source["rangeBaseCommit"], "source.rangeBaseCommit")
    git_id(source["headCommit"], "source.headCommit")
    git_id(source["headTree"], "source.headTree")
    positive_int(source["expectedFirstParentCommitCount"], "source.expectedFirstParentCommitCount")
    positive_int(source["expectedFeaturePullRequestMergeCount"], "source.expectedFeaturePullRequestMergeCount")
    positive_int(source["expectedRevertCommitCount"], "source.expectedRevertCommitCount")

    pr_policy = contract["pullRequestPolicy"]
    require(isinstance(pr_policy, dict), "SCHEMA_TYPE_MISMATCH", "pullRequestPolicy must be an object")
    exact_keys(pr_policy, ("state", "merged", "draft", "baseRef", "headRefPrefix", "mergeParentCount", "featureHeadMustEqualSecondParent", "observedBaseMustBeAncestorOfIntegrationParent"), "pullRequestPolicy")
    require(pr_policy == {
        "state": "closed",
        "merged": True,
        "draft": False,
        "baseRef": "bootstrap/macos-r0",
        "headRefPrefix": "codex/",
        "mergeParentCount": 2,
        "featureHeadMustEqualSecondParent": True,
        "observedBaseMustBeAncestorOfIntegrationParent": True,
    }, "PR_POLICY_MISMATCH", "pull request policy differs from the frozen fail-closed policy")

    history_policy = contract["integrationHistoryPolicy"]
    require(isinstance(history_policy, dict), "SCHEMA_TYPE_MISMATCH", "integrationHistoryPolicy must be an object")
    exact_keys(history_policy, ("allowedKinds", "revertMustTargetPriorFeatureMerge", "revertedFeatureMayCountActive"), "integrationHistoryPolicy")
    require(history_policy == {
        "allowedKinds": ["FEATURE_PR_MERGE", "REVERT"],
        "revertMustTargetPriorFeatureMerge": True,
        "revertedFeatureMayCountActive": False,
    }, "REVERT_HISTORY_MISMATCH", "integration history policy differs")

    ci_policy = contract["ciPolicy"]
    require(isinstance(ci_policy, dict), "SCHEMA_TYPE_MISMATCH", "ciPolicy must be an object")
    exact_keys(ci_policy, ("provider", "workflowId", "workflowName", "workflowPath", "event", "status", "conclusion", "runAttemptPolicy", "requiredJobs"), "ciPolicy")
    require(ci_policy["provider"] == "github-actions", "CI_RUN_POLICY_MISMATCH", "CI provider differs")
    positive_int(ci_policy["workflowId"], "ciPolicy.workflowId")
    require(ci_policy["workflowName"] == "ci" and ci_policy["workflowPath"] == ".github/workflows/ci.yml", "CI_RUN_POLICY_MISMATCH", "CI workflow differs")
    require(ci_policy["event"] == "pull_request", "CI_RUN_POLICY_MISMATCH", "CI event differs")
    require(ci_policy["status"] == "completed" and ci_policy["conclusion"] == "success" and ci_policy["runAttemptPolicy"] == "POSITIVE_EXACT_MATCH", "CI_RUN_POLICY_MISMATCH", "CI terminal policy differs")
    jobs = ci_policy["requiredJobs"]
    require(isinstance(jobs, list) and jobs == sorted(jobs) and len(jobs) == len(set(jobs)) and jobs == ["PostgreSQL 18 Cell contract", "Rust workspace"], "CI_JOB_MISSING", "required CI jobs differ")

    result = contract["resultPolicy"]
    require(isinstance(result, dict), "SCHEMA_TYPE_MISMATCH", "resultPolicy must be an object")
    exact_keys(result, ("verificationCode", "verificationStatus", "releaseDecision", "releasePassed", "missionEvidenceLevelPromoted", "maySatisfyReleaseEvidence", "mayPromoteMissionEvidenceLevel"), "resultPolicy")
    require(result["verificationCode"] == "INTEGRATION_BUILD_PROVENANCE_PENDING" and result["verificationStatus"] == "NOT_VERIFIED", "RESULT_POLICY_MISMATCH", "verification result differs")
    require(
        result["releaseDecision"] == "NOT_EVALUATED"
        and result["releasePassed"] is False
        and result["missionEvidenceLevelPromoted"] is False
        and result["maySatisfyReleaseEvidence"] is False
        and result["mayPromoteMissionEvidenceLevel"] is False,
        "RELEASE_AUTHORITY_ESCALATION",
        "integration evidence must not grant Release or Mission evidence-level authority",
    )
    validate_candidate_contract_sections(contract)
    require(contract["failClosedCodes"] == EXPECTED_FAIL_CODES, "CONTRACT_FAIL_CODES_MISMATCH", "fail-closed code set must be sorted and exact")
    gate = contract["gate"]
    require(isinstance(gate, dict), "SCHEMA_TYPE_MISMATCH", "gate must be an object")
    exact_keys(gate, ("verifyCommand", "selfTestCommand"), "gate")
    require(gate["verifyCommand"] == "bash scripts/check-integration-build-provenance.sh verify", "CONTRACT_GATE_MISMATCH", "verify command differs")
    require(gate["selfTestCommand"] == "bash scripts/check-integration-build-provenance.sh self-test", "CONTRACT_GATE_MISMATCH", "self-test command differs")


def validate_candidate_policy(policy: Mapping[str, Any], contract: Mapping[str, Any]) -> None:
    require(isinstance(policy, dict), "SCHEMA_TYPE_MISMATCH", "candidatePolicy must be an object")
    exact_keys(policy, ("pullRequest", "ci", "protectedIntegrationRun"), "candidatePolicy")
    candidate = policy["pullRequest"]
    require(isinstance(candidate, dict), "SCHEMA_TYPE_MISMATCH", "candidatePolicy.pullRequest must be an object")
    exact_keys(candidate, ("number", "state", "merged", "draft", "baseRef", "baseCommit", "headRef", "headCommit", "headTree", "mergeCommit"), "candidatePolicy.pullRequest")
    positive_int(candidate["number"], "candidatePolicy.pullRequest.number")
    git_id(candidate["baseCommit"], "candidatePolicy.pullRequest.baseCommit")
    git_id(candidate["headCommit"], "candidatePolicy.pullRequest.headCommit")
    git_id(candidate["headTree"], "candidatePolicy.pullRequest.headTree")
    require(candidate["state"] == "OPEN" and candidate["merged"] is False and candidate["draft"] is True, "PR_POLICY_MISMATCH", "current candidate must remain open+draft+unmerged")
    require(candidate["baseRef"] == contract["currentBaseline"]["ref"].removeprefix("origin/"), "PR_BASE_MISMATCH", "candidate base ref differs")
    require(git_ancestor(candidate["baseCommit"], contract["currentBaseline"]["commit"]), "PR_BASE_ANCESTRY_MISMATCH", "candidate base commit is not an ancestor of the protected baseline")
    require(candidate["headRef"].startswith("codex/"), "PR_HEAD_MISMATCH", "candidate head ref is outside the feature namespace")
    require(candidate["mergeCommit"] is None, "PR_MERGE_CHAIN_MISMATCH", "unmerged candidate must not have a merge commit")

    ci = policy["ci"]
    require(isinstance(ci, dict), "SCHEMA_TYPE_MISMATCH", "candidatePolicy.ci must be an object")
    exact_keys(ci, ("provider", "workflowId", "workflowName", "workflowPath", "event", "requiredStatus", "requiredConclusion", "requiredJobs"), "candidatePolicy.ci")
    require(ci["provider"] == "github-actions" and ci["workflowName"] == "PR / Fast CI" and ci["workflowPath"] == ".github/workflows/ci.yml" and ci["event"] == "pull_request", "CI_RUN_POLICY_MISMATCH", "candidate CI policy differs")
    positive_int(ci["workflowId"], "candidatePolicy.ci.workflowId")
    require(ci["requiredStatus"] == "completed" and ci["requiredConclusion"] == "success", "CI_RUN_POLICY_MISMATCH", "candidate CI terminal policy differs")
    require(ci["requiredJobs"] == [
        "PR / Scope plan",
        "PR / Workflow policy",
        "PR / Fast Rust matrix / PR / Fast Rust / fmt",
        "PR / Fast Rust matrix / PR / Fast Rust / test (ubuntu-24.04)",
        "PR / Fast Rust matrix / PR / Fast Rust / clippy (ubuntu-24.04)",
        "PR / Fast Rust matrix / PR / Fast Rust / test (macos-15)",
        "PR / Fast Rust matrix / PR / Fast Rust / clippy (macos-15)",
        "PR / Result taxonomy",
    ], "CI_JOB_MISSING", "candidate CI required jobs differ")

    protected = policy["protectedIntegrationRun"]
    require(isinstance(protected, dict), "SCHEMA_TYPE_MISMATCH", "candidatePolicy.protectedIntegrationRun must be an object")
    exact_keys(protected, ("provider", "workflowId", "workflowName", "workflowPath", "event", "runId", "runAttempt", "headCommit", "status", "conclusion", "requiredJobs"), "candidatePolicy.protectedIntegrationRun")
    require(protected["provider"] == "github-actions" and protected["workflowName"] == "Integration / Bootstrap CI" and protected["workflowPath"] == ".github/workflows/integration.yml" and protected["event"] == "push", "CI_RUN_POLICY_MISMATCH", "protected integration workflow differs")
    positive_int(protected["workflowId"], "candidatePolicy.protectedIntegrationRun.workflowId")
    positive_int(protected["runId"], "candidatePolicy.protectedIntegrationRun.runId")
    require(protected["runAttempt"] == 1 and protected["status"] == "completed" and protected["conclusion"] == "success", "CI_STATUS_NOT_COMPLETED", "protected integration run must be the exact completed success receipt")
    require(protected["headCommit"] == contract["currentBaseline"]["commit"], "CURRENT_COMMIT_MISMATCH", "protected integration run head differs")
    require(protected["requiredJobs"] == [
        "Integration / Reviewed gate",
        "Integration / PostgreSQL 18 Cell",
        "Integration / Catalog and evidence",
        "Integration / Dependency and SBOM",
        "Integration / OpenInterpreter contract",
        "Integration / Dioxus build and receipt",
        "Integration / Full Rust matrix / Integration / Full Rust / test shard 1 of 2 (ubuntu-24.04)",
        "Integration / Full Rust matrix / Integration / Full Rust / clippy (ubuntu-24.04)",
        "Integration / Full Rust matrix / Integration / Full Rust / clippy (macos-15)",
        "Integration / Full Rust matrix / Integration / Full Rust / test (macos-15)",
        "Integration / Full Rust matrix / Integration / Full Rust / fmt",
        "Integration / Full Rust matrix / Integration / Full Rust / test shard 0 of 2 (ubuntu-24.04)",
        "Integration / Full Rust matrix / Integration / Full Rust / test (ubuntu-24.04)",
        "Integration / Result taxonomy",
    ], "CI_JOB_MISSING", "protected integration required jobs differ")


def validate_native_policy(policy: Mapping[str, Any]) -> None:
    require(isinstance(policy, dict), "SCHEMA_TYPE_MISMATCH", "nativeEvidencePolicy must be an object")
    exact_keys(policy, ("path", "sourceCommit", "sha256", "bytes", "status", "nativeVisual", "nativeAccessibility", "processRestart", "releaseEvidence", "releasePassed", "releaseDecision", "missionEvidenceLevelPromoted"), "nativeEvidencePolicy")
    safe_relative_path(policy["path"], "nativeEvidencePolicy.path")
    git_id(policy["sourceCommit"], "nativeEvidencePolicy.sourceCommit")
    digest(policy["sha256"], "nativeEvidencePolicy.sha256")
    positive_int(policy["bytes"], "nativeEvidencePolicy.bytes")
    require(all(policy[key] == "NOT_PROVEN" for key in ("status", "nativeVisual", "nativeAccessibility", "processRestart", "releaseEvidence")), "NATIVE_EVIDENCE_ESCALATION", "native evidence must remain NOT_PROVEN")
    require(policy["releasePassed"] is False and policy["releaseDecision"] == "NOT_EVALUATED" and policy["missionEvidenceLevelPromoted"] is False, "RELEASE_AUTHORITY_ESCALATION", "native evidence policy cannot grant Release authority")


def validate_role_policy(policy: Mapping[str, Any], candidate_commit: str) -> None:
    require(isinstance(policy, dict), "SCHEMA_TYPE_MISMATCH", "evidenceRolePolicy must be an object")
    exact_keys(policy, ("service", "provider", "consumer"), "evidenceRolePolicy")
    expected = {
        "service": ("evidence-query", "EVIDENCE_QUERY", "catalog_snapshot"),
        "provider": ("evidence-producer", "EVIDENCE_PRODUCER", "wave_zero_baseline"),
        "consumer": ("release-gate-consumer", "RELEASE_GATE_CONSUMER", "validate_fail_closed"),
    }
    for name, (role_id, kind, symbol) in expected.items():
        role = policy[name]
        require(isinstance(role, dict), "SCHEMA_TYPE_MISMATCH", f"evidenceRolePolicy.{name} must be an object")
        exact_keys(role, ("id", "kind", "path", "symbol", "sourceCommit", "sha256", "bytes"), f"evidenceRolePolicy.{name}")
        require(role["id"] == role_id and role["kind"] == kind and role["symbol"] == symbol, "EVIDENCE_ROLE_MISSING", f"evidence role {name} identity differs")
        safe_relative_path(role["path"], f"evidenceRolePolicy.{name}.path")
        require(role["sourceCommit"] == candidate_commit, "EVIDENCE_ROLE_MISSING", f"evidence role {name} is not bound to candidate commit")
        git_id(role["sourceCommit"], f"evidenceRolePolicy.{name}.sourceCommit")
        digest(role["sha256"], f"evidenceRolePolicy.{name}.sha256")
        positive_int(role["bytes"], f"evidenceRolePolicy.{name}.bytes")


def validate_candidate_contract_sections(contract: Mapping[str, Any]) -> None:
    candidate = contract["candidatePolicy"]["pullRequest"]
    validate_candidate_policy(contract["candidatePolicy"], contract)
    validate_native_policy(contract["nativeEvidencePolicy"])
    require(contract["nativeEvidencePolicy"]["sourceCommit"] == contract["currentBaseline"]["commit"], "NATIVE_EVIDENCE_ESCALATION", "native evidence must be bound to the protected baseline")
    validate_role_policy(contract["evidenceRolePolicy"], candidate["headCommit"])


def load_contract() -> Tuple[bytes, Dict[str, Any]]:
    raw = read_regular(CONTRACT_REL, "CONTRACT_MISSING")
    require(sha256(raw) == CONTRACT_SHA256, "CONTRACT_DIGEST_MISMATCH", "contract raw SHA-256 differs from the verifier pin")
    contract = load_json(raw, CONTRACT_REL)
    validate_contract(contract)
    return raw, contract


def load_instance_ref(
    instance: Mapping[str, Any],
    *,
    manifest_override: Optional[bytes] = None,
    raw_override: Optional[bytes] = None,
    manifest_missing_code: str = "MANIFEST_MISSING",
    raw_missing_code: str = "RAW_ARTIFACT_MISSING",
) -> Tuple[bytes, Dict[str, Any], bytes, Dict[str, Any]]:
    manifest_raw = manifest_override if manifest_override is not None else read_regular(instance["manifestPath"], manifest_missing_code)
    require(sha256(manifest_raw) == instance["manifestSha256"], "MANIFEST_DIGEST_MISMATCH", "manifest raw SHA-256 differs")
    require(len(manifest_raw) == instance["manifestBytes"], "MANIFEST_DIGEST_MISMATCH", "manifest byte count differs")
    manifest = load_json(manifest_raw, instance["manifestPath"])

    raw_artifact = raw_override if raw_override is not None else read_regular(instance["rawArtifactPath"], raw_missing_code)
    require(sha256(raw_artifact) == instance["rawArtifactSha256"], "RAW_ARTIFACT_DIGEST_MISMATCH", "raw artifact SHA-256 differs")
    require(len(raw_artifact) == instance["rawArtifactBytes"], "RAW_ARTIFACT_DIGEST_MISMATCH", "raw artifact byte count differs")
    observation = load_json(raw_artifact, instance["rawArtifactPath"])
    return manifest_raw, manifest, raw_artifact, observation


def load_instance(
    contract: Mapping[str, Any],
    *,
    manifest_override: Optional[bytes] = None,
    raw_override: Optional[bytes] = None,
) -> Tuple[bytes, Dict[str, Any], bytes, Dict[str, Any]]:
    return load_instance_ref(
        contract["historicalInstance"],
        manifest_override=manifest_override,
        raw_override=raw_override,
    )


def load_candidate_instance(contract: Mapping[str, Any]) -> Tuple[bytes, Dict[str, Any], bytes, Dict[str, Any]]:
    return load_instance_ref(
        contract["currentInstance"],
        manifest_missing_code="CANDIDATE_MANIFEST_MISSING",
        raw_missing_code="CANDIDATE_RAW_ARTIFACT_MISSING",
    )


def validate_manifest(contract: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    exact_keys(manifest, ("schemaVersion", "manifestId", "authority", "source", "rawArtifact", "featurePullRequests", "integrationHistory", "summary"), "manifest")
    require(manifest["schemaVersion"] == "hartevo.integration-build-provenance-manifest/v1", "MANIFEST_SCHEMA_MISMATCH", "manifest schema differs")
    require(manifest["manifestId"] == f"ev-04-{contract['source']['headCommit']}", "MANIFEST_SOURCE_MISMATCH", "manifest id is not source-bound")
    require(manifest["authority"] == AUTHORITY, "RELEASE_AUTHORITY_ESCALATION", "manifest authority must remain integration provenance only")

    source = manifest["source"]
    require(isinstance(source, dict), "SCHEMA_TYPE_MISMATCH", "manifest.source must be an object")
    exact_keys(source, ("repository", "branch", "objectFormat", "rangeBaseCommit", "headCommit", "headTree"), "manifest.source")
    expected_source = {key: contract["source"][key] for key in source.keys()}
    require(source == expected_source, "MANIFEST_SOURCE_MISMATCH", "manifest source differs from the contract")

    raw_ref = manifest["rawArtifact"]
    require(isinstance(raw_ref, dict), "SCHEMA_TYPE_MISMATCH", "manifest.rawArtifact must be an object")
    exact_keys(raw_ref, ("kind", "path", "sha256", "bytes"), "manifest.rawArtifact")
    instance = contract["historicalInstance"]
    require(raw_ref == {
        "kind": "GITHUB_PR_CI_OBSERVATION",
        "path": instance["rawArtifactPath"],
        "sha256": instance["rawArtifactSha256"],
        "bytes": instance["rawArtifactBytes"],
    }, "RAW_ARTIFACT_DIGEST_MISMATCH", "manifest raw-artifact reference differs from the contract")

    records = manifest["featurePullRequests"]
    require(isinstance(records, list) and bool(records), "PR_MERGE_CHAIN_MISMATCH", "manifest feature PR list must be non-empty")
    numbers: List[int] = []
    for index, record in enumerate(records):
        require(isinstance(record, dict), "SCHEMA_TYPE_MISMATCH", f"manifest.featurePullRequests[{index}] must be an object")
        exact_keys(record, ("number", "integrationParent", "mergeCommit", "featureHead", "baseRef", "headRef", "actionsRunId", "ciConclusion", "requiredJobs"), f"manifest.featurePullRequests[{index}]")
        numbers.append(positive_int(record["number"], f"manifest.featurePullRequests[{index}].number"))
        git_id(record["integrationParent"], f"manifest.featurePullRequests[{index}].integrationParent")
        git_id(record["mergeCommit"], f"manifest.featurePullRequests[{index}].mergeCommit")
        git_id(record["featureHead"], f"manifest.featurePullRequests[{index}].featureHead")
        nonempty_string(record["baseRef"], f"manifest.featurePullRequests[{index}].baseRef")
        nonempty_string(record["headRef"], f"manifest.featurePullRequests[{index}].headRef")
        positive_int(record["actionsRunId"], f"manifest.featurePullRequests[{index}].actionsRunId")
        require(record["ciConclusion"] == "SUCCESS", "CI_CONCLUSION_NOT_SUCCESS", f"manifest CI conclusion is not SUCCESS for PR #{record['number']}")
        jobs = record["requiredJobs"]
        require(isinstance(jobs, list), "CI_JOB_MISSING", f"manifest jobs missing for PR #{record['number']}")
        names: List[str] = []
        for job in jobs:
            require(isinstance(job, dict), "SCHEMA_TYPE_MISMATCH", "manifest job must be an object")
            exact_keys(job, ("id", "name", "conclusion"), "manifest required job")
            positive_int(job["id"], "manifest job id")
            names.append(nonempty_string(job["name"], "manifest job name"))
            require(job["conclusion"] == "SUCCESS", "CI_JOB_NOT_SUCCESS", f"manifest job is not SUCCESS for PR #{record['number']}")
        require(names == contract["ciPolicy"]["requiredJobs"], "CI_JOB_MISSING", f"manifest required jobs differ for PR #{record['number']}")
    require(len(numbers) == len(set(numbers)), "PR_MERGE_CHAIN_MISMATCH", "manifest PR numbers must be unique")

    history = manifest["integrationHistory"]
    require(isinstance(history, list) and bool(history), "REVERT_HISTORY_MISMATCH", "manifest integration history must be non-empty")
    history_commits: List[str] = []
    feature_events: List[int] = []
    revert_events: List[int] = []
    for index, event in enumerate(history):
        require(isinstance(event, dict), "SCHEMA_TYPE_MISMATCH", f"integrationHistory[{index}] must be an object")
        kind = event.get("kind")
        require(kind in contract["integrationHistoryPolicy"]["allowedKinds"], "REVERT_HISTORY_MISMATCH", f"integrationHistory[{index}] kind differs")
        if kind == "FEATURE_PR_MERGE":
            exact_keys(event, ("kind", "commit", "pullRequest"), f"integrationHistory[{index}]")
            feature_events.append(positive_int(event["pullRequest"], f"integrationHistory[{index}].pullRequest"))
        else:
            exact_keys(event, ("kind", "commit", "parent", "revertsCommit", "revertedPullRequest"), f"integrationHistory[{index}]")
            git_id(event["parent"], f"integrationHistory[{index}].parent")
            git_id(event["revertsCommit"], f"integrationHistory[{index}].revertsCommit")
            revert_events.append(positive_int(event["revertedPullRequest"], f"integrationHistory[{index}].revertedPullRequest"))
        history_commits.append(git_id(event["commit"], f"integrationHistory[{index}].commit"))
    require(len(history_commits) == len(set(history_commits)), "REVERT_HISTORY_MISMATCH", "integration history commits must be unique")
    require(feature_events == numbers, "PR_MERGE_CHAIN_MISMATCH", "integration history feature events differ from feature PR records")
    require(len(revert_events) == len(set(revert_events)), "REVERT_HISTORY_MISMATCH", "a feature PR may be explicitly reverted only once in this receipt")

    summary = manifest["summary"]
    require(isinstance(summary, dict), "SCHEMA_TYPE_MISMATCH", "manifest.summary must be an object")
    exact_keys(summary, ("featurePullRequestCount", "activeFeaturePullRequestCount", "revertedFeaturePullRequestCount", "mergeCommitCount", "firstParentCommitCount", "revertCommitCount", "actionsRunCount", "requiredJobCount", "integrationProvenanceStatus", "releaseDecision", "releasePassed", "missionEvidenceLevelPromoted"), "manifest.summary")
    count = len(records)
    require(
        count == contract["source"]["expectedFeaturePullRequestMergeCount"]
        and len(history) == contract["source"]["expectedFirstParentCommitCount"]
        and len(revert_events) == contract["source"]["expectedRevertCommitCount"],
        "MANIFEST_SUMMARY_MISMATCH",
        "manifest history counts differ from the contract",
    )
    require(
        summary["featurePullRequestCount"] == count
        and summary["activeFeaturePullRequestCount"] == count - len(revert_events)
        and summary["revertedFeaturePullRequestCount"] == len(revert_events)
        and summary["mergeCommitCount"] == count
        and summary["firstParentCommitCount"] == len(history)
        and summary["revertCommitCount"] == len(revert_events)
        and summary["actionsRunCount"] == count
        and summary["requiredJobCount"] == count * len(contract["ciPolicy"]["requiredJobs"]),
        "MANIFEST_SUMMARY_MISMATCH",
        "manifest summary counts differ",
    )
    require(summary["integrationProvenanceStatus"] == "VERIFIED", "MANIFEST_SUMMARY_MISMATCH", "integration provenance status differs")
    require(
        summary["releaseDecision"] == "NOT_EVALUATED"
        and summary["releasePassed"] is False
        and summary["missionEvidenceLevelPromoted"] is False,
        "RELEASE_AUTHORITY_ESCALATION",
        "manifest summary must not grant Release or Mission evidence-level authority",
    )


def validate_observation(observation: Mapping[str, Any]) -> None:
    exact_keys(observation, ("schemaVersion", "repository", "capturedAt", "sourceApi", "pullRequests"), "raw observation")
    require(observation["schemaVersion"] == "hartevo.github-pr-ci-observation/v1", "RAW_ARTIFACT_SCHEMA_MISMATCH", "raw observation schema differs")
    require(observation["repository"] == "tangpingqingwa/hartevo-desktop", "MANIFEST_SOURCE_MISMATCH", "raw observation repository differs")
    require(observation["sourceApi"] == "github-rest-v3", "RAW_ARTIFACT_SCHEMA_MISMATCH", "raw observation source API differs")
    utc_time(observation["capturedAt"], "raw observation capturedAt")
    require(isinstance(observation["pullRequests"], list), "PR_MERGE_CHAIN_MISMATCH", "raw observation pullRequests must be an array")


def validate_candidate_object(candidate: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    require(isinstance(candidate, dict), "SCHEMA_TYPE_MISMATCH", f"{label} must be an object")
    exact_keys(candidate, ("number", "state", "merged", "draft", "baseRef", "baseCommit", "headRef", "headCommit", "headTree", "mergeCommit"), label)
    require(candidate == dict(expected), "MANIFEST_SOURCE_MISMATCH", f"{label} differs from the pinned candidate policy")
    positive_int(candidate["number"], f"{label}.number")
    git_id(candidate["baseCommit"], f"{label}.baseCommit")
    git_id(candidate["headCommit"], f"{label}.headCommit")
    git_id(candidate["headTree"], f"{label}.headTree")
    nonempty_string(candidate["baseRef"], f"{label}.baseRef")
    nonempty_string(candidate["headRef"], f"{label}.headRef")
    require(candidate["mergeCommit"] is None, "PR_MERGE_CHAIN_MISMATCH", f"{label}.mergeCommit must be null while unmerged")


def validate_candidate_ci(ci: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    require(isinstance(ci, dict), "SCHEMA_TYPE_MISMATCH", f"{label} must be an object")
    exact_keys(ci, ("provider", "workflowId", "workflowName", "workflowPath", "event", "status", "conclusion", "runId", "runAttempt", "headBranch", "headCommit", "jobs"), label)
    require(ci["provider"] == expected["provider"] and ci["workflowId"] == expected["workflowId"] and ci["workflowName"] == expected["workflowName"] and ci["workflowPath"] == expected["workflowPath"] and ci["event"] == expected["event"], "CI_RUN_POLICY_MISMATCH", f"{label} workflow identity differs")
    require(ci["status"] in {"NOT_EXECUTED_EXTERNAL", "queued", "in_progress", "completed"}, "CI_RUN_POLICY_MISMATCH", f"{label}.status is unknown")
    require(ci["conclusion"] in {None, "NOT_RUN", "success", "failure", "cancelled"}, "CI_RUN_POLICY_MISMATCH", f"{label}.conclusion is unknown")
    if ci["runId"] is not None:
        positive_int(ci["runId"], f"{label}.runId")
    if ci["runAttempt"] is not None:
        positive_int(ci["runAttempt"], f"{label}.runAttempt")
    nonempty_string(ci["headBranch"], f"{label}.headBranch")
    git_id(ci["headCommit"], f"{label}.headCommit")
    require(isinstance(ci["jobs"], list), "CI_JOB_MISSING", f"{label}.jobs must be an array")
    if ci["status"] == "NOT_EXECUTED_EXTERNAL":
        require(ci["runId"] is None and ci["runAttempt"] is None and ci["conclusion"] == "NOT_RUN" and ci["jobs"] == [], "CANDIDATE_CI_NOT_EXECUTED", f"{label} not-executed envelope must not contain a run or jobs")
    elif ci["status"] == "completed":
        require(ci["runId"] is not None and ci["runAttempt"] is not None and ci["conclusion"] in {"success", "failure", "cancelled"}, "CI_RUN_MISSING", f"{label} completed envelope is missing run identity")
        names = []
        for index, job in enumerate(ci["jobs"]):
            require(isinstance(job, dict), "CI_JOB_MISSING", f"{label}.jobs[{index}] must be an object")
            exact_keys(job, ("id", "name", "status", "conclusion", "runAttempt", "headCommit"), f"{label}.jobs[{index}]")
            positive_int(job["id"], f"{label}.jobs[{index}].id")
            names.append(nonempty_string(job["name"], f"{label}.jobs[{index}].name"))
            require(job["status"] == "completed" and job["conclusion"] in {"success", "failure", "cancelled"}, "CI_JOB_NOT_SUCCESS", f"{label}.jobs[{index}] is not terminal")
            positive_int(job["runAttempt"], f"{label}.jobs[{index}].runAttempt")
            git_id(job["headCommit"], f"{label}.jobs[{index}].headCommit")
            require(job["runAttempt"] == ci["runAttempt"] and job["headCommit"] == ci["headCommit"], "CANDIDATE_CI_HEAD_MISMATCH", f"{label}.jobs[{index}] is not bound to the run")
        require(names == list(expected["requiredJobs"]), "CI_JOB_MISSING", f"{label} required job names differ")


def validate_protected_run(run_record: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    require(isinstance(run_record, dict), "SCHEMA_TYPE_MISMATCH", f"{label} must be an object")
    exact_keys(run_record, ("provider", "workflowId", "workflowName", "workflowPath", "event", "runId", "runAttempt", "headCommit", "status", "conclusion", "jobs"), label)
    require(run_record["provider"] == expected["provider"] and run_record["workflowId"] == expected["workflowId"] and run_record["workflowName"] == expected["workflowName"] and run_record["workflowPath"] == expected["workflowPath"] and run_record["event"] == expected["event"], "CI_RUN_POLICY_MISMATCH", f"{label} workflow identity differs")
    positive_int(run_record["runId"], f"{label}.runId")
    positive_int(run_record["runAttempt"], f"{label}.runAttempt")
    git_id(run_record["headCommit"], f"{label}.headCommit")
    require(run_record["status"] in {"queued", "in_progress", "completed"}, "CI_RUN_POLICY_MISMATCH", f"{label}.status is unknown")
    require(run_record["conclusion"] in {None, "success", "failure", "cancelled"}, "CI_RUN_POLICY_MISMATCH", f"{label}.conclusion is unknown")
    require(isinstance(run_record["jobs"], list), "CI_JOB_MISSING", f"{label}.jobs must be an array")
    if run_record["status"] != "completed":
        require(run_record["conclusion"] is None and run_record["jobs"] == [], "CI_STATUS_NOT_COMPLETED", f"{label} incomplete run must not contain a conclusion or jobs")
    else:
        require(run_record["conclusion"] in {"success", "failure", "cancelled"}, "CI_CONCLUSION_NOT_SUCCESS", f"{label} completed run has no terminal conclusion")
        names = []
        for index, job in enumerate(run_record["jobs"]):
            require(isinstance(job, dict), "CI_JOB_MISSING", f"{label}.jobs[{index}] must be an object")
            exact_keys(job, ("id", "name", "status", "conclusion", "runAttempt", "headCommit"), f"{label}.jobs[{index}]")
            positive_int(job["id"], f"{label}.jobs[{index}].id")
            names.append(nonempty_string(job["name"], f"{label}.jobs[{index}].name"))
            require(job["status"] == "completed" and job["conclusion"] in {"success", "failure", "cancelled"}, "CI_JOB_NOT_SUCCESS", f"{label}.jobs[{index}] is not terminal")
            positive_int(job["runAttempt"], f"{label}.jobs[{index}].runAttempt")
            git_id(job["headCommit"], f"{label}.jobs[{index}].headCommit")
            require(job["runAttempt"] == run_record["runAttempt"] and job["headCommit"] == run_record["headCommit"], "CANDIDATE_CI_HEAD_MISMATCH", f"{label}.jobs[{index}] is not bound to the run")
        require(names == list(expected["requiredJobs"]), "CI_JOB_MISSING", f"{label} required job names differ")


def git_blob_bytes(commit: str, relative: str) -> bytes:
    safe_relative_path(relative, "evidence role path")
    tree_line = git_text("ls-tree", commit, "--", relative)
    require(tree_line.startswith("100644 blob ") and tree_line.endswith(f"\t{relative}"), "EVIDENCE_ROLE_MISSING", f"evidence role is not a regular tracked blob: {relative}")
    result = run(("git", "show", f"{commit}:{relative}"), check=False)
    require(result.returncode == 0, "EVIDENCE_ROLE_MISSING", f"evidence role blob is unavailable: {relative}")
    return result.stdout


def validate_native_evidence(value: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    require(isinstance(value, dict), "SCHEMA_TYPE_MISMATCH", f"{label} must be an object")
    exact_keys(value, ("path", "sourceCommit", "sha256", "bytes", "status", "nativeVisual", "nativeAccessibility", "processRestart", "releaseEvidence", "releasePassed", "releaseDecision", "missionEvidenceLevelPromoted"), label)
    require(value == dict(expected), "NATIVE_EVIDENCE_ESCALATION", f"{label} differs from the pinned native-evidence policy")
    safe_relative_path(value["path"], f"{label}.path")
    git_id(value["sourceCommit"], f"{label}.sourceCommit")
    digest(value["sha256"], f"{label}.sha256")
    positive_int(value["bytes"], f"{label}.bytes")
    require(value["status"] == "NOT_PROVEN" and value["releasePassed"] is False and value["releaseDecision"] == "NOT_EVALUATED" and value["missionEvidenceLevelPromoted"] is False, "NATIVE_EVIDENCE_ESCALATION", f"{label} cannot grant native or Release authority")


def validate_evidence_roles(value: Mapping[str, Any], expected: Mapping[str, Any], candidate_commit: str, label: str) -> None:
    require(isinstance(value, dict), "SCHEMA_TYPE_MISMATCH", f"{label} must be an object")
    exact_keys(value, ("service", "provider", "consumer"), label)
    for name in ("service", "provider", "consumer"):
        role = value[name]
        expected_role = expected[name]
        require(isinstance(role, dict), "SCHEMA_TYPE_MISMATCH", f"{label}.{name} must be an object")
        exact_keys(role, ("id", "kind", "path", "symbol", "sourceCommit", "sha256", "bytes"), f"{label}.{name}")
        require(role == expected_role, "EVIDENCE_ROLE_MISSING", f"{label}.{name} differs from the pinned role")
        require(role["sourceCommit"] == candidate_commit, "EVIDENCE_ROLE_MISSING", f"{label}.{name} is not candidate-bound")
        blob = git_blob_bytes(candidate_commit, role["path"])
        require(sha256(blob) == role["sha256"] and len(blob) == role["bytes"], "EVIDENCE_ROLE_MISSING", f"{label}.{name} blob digest differs")
        require(role["symbol"].encode("utf-8") in blob, "EVIDENCE_ROLE_MISSING", f"{label}.{name} symbol is absent")


def validate_candidate_manifest(contract: Mapping[str, Any], manifest: Mapping[str, Any], raw_artifact_path: str, raw_artifact_sha: str, raw_artifact_bytes: int) -> None:
    exact_keys(manifest, ("schemaVersion", "manifestId", "authority", "baseline", "candidate", "rawArtifact", "ci", "protectedIntegrationRun", "nativeEvidence", "evidenceRoles", "result"), "candidate manifest")
    require(manifest["schemaVersion"] == "hartevo.integration-build-candidate-manifest/v1", "MANIFEST_SCHEMA_MISMATCH", "candidate manifest schema differs")
    expected_candidate = contract["candidatePolicy"]["pullRequest"]
    require(manifest["manifestId"] == f"ev-04-candidate-{expected_candidate['headCommit']}", "MANIFEST_SOURCE_MISMATCH", "candidate manifest id is not source-bound")
    require(manifest["authority"] == AUTHORITY, "RELEASE_AUTHORITY_ESCALATION", "candidate manifest authority must remain integration provenance only")
    expected_baseline = {"ref": expected_candidate["baseRef"], "commit": contract["currentBaseline"]["commit"], "tree": contract["currentBaseline"]["tree"]}
    require(manifest["baseline"] == expected_baseline, "MANIFEST_SOURCE_MISMATCH", "candidate baseline differs")
    validate_candidate_object(manifest["candidate"], expected_candidate, "candidate manifest.candidate")
    raw_ref = manifest["rawArtifact"]
    require(isinstance(raw_ref, dict), "SCHEMA_TYPE_MISMATCH", "candidate manifest.rawArtifact must be an object")
    exact_keys(raw_ref, ("kind", "path", "sha256", "bytes"), "candidate manifest.rawArtifact")
    require(raw_ref == {"kind": "GITHUB_PR_CI_CANDIDATE_OBSERVATION", "path": raw_artifact_path, "sha256": raw_artifact_sha, "bytes": raw_artifact_bytes}, "RAW_ARTIFACT_DIGEST_MISMATCH", "candidate raw-artifact reference differs")
    validate_candidate_ci(manifest["ci"], contract["candidatePolicy"]["ci"], "candidate manifest.ci")
    require(manifest["ci"]["headBranch"] == expected_candidate["headRef"] and manifest["ci"]["headCommit"] == expected_candidate["headCommit"], "CANDIDATE_CI_HEAD_MISMATCH", "candidate manifest CI is not bound to the candidate head")
    validate_protected_run(manifest["protectedIntegrationRun"], contract["candidatePolicy"]["protectedIntegrationRun"], "candidate manifest.protectedIntegrationRun")
    require(manifest["protectedIntegrationRun"]["headCommit"] == contract["currentBaseline"]["commit"], "CANDIDATE_CI_HEAD_MISMATCH", "protected integration run is not bound to the protected base")
    validate_native_evidence(manifest["nativeEvidence"], contract["nativeEvidencePolicy"], "candidate manifest.nativeEvidence")
    validate_evidence_roles(manifest["evidenceRoles"], contract["evidenceRolePolicy"], expected_candidate["headCommit"], "candidate manifest.evidenceRoles")
    result = manifest["result"]
    require(isinstance(result, dict), "SCHEMA_TYPE_MISMATCH", "candidate manifest.result must be an object")
    exact_keys(result, ("status", "verificationStatus", "releaseDecision", "releasePassed", "missionEvidenceLevelPromoted", "maySatisfyReleaseEvidence", "mayPromoteMissionEvidenceLevel"), "candidate manifest.result")
    require(result == {"status": "PR_DRAFT", "verificationStatus": "NOT_VERIFIED", "releaseDecision": "NOT_EVALUATED", "releasePassed": False, "missionEvidenceLevelPromoted": False, "maySatisfyReleaseEvidence": False, "mayPromoteMissionEvidenceLevel": False}, "RELEASE_AUTHORITY_ESCALATION", "candidate manifest result must remain draft-pending and non-release")


def validate_candidate_observation(contract: Mapping[str, Any], observation: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    exact_keys(observation, ("schemaVersion", "repository", "capturedAt", "sourceApi", "observationStatus", "baseline", "candidate", "ci", "protectedIntegrationRun", "nativeEvidence", "evidenceRoles"), "candidate observation")
    require(observation["schemaVersion"] == "hartevo.github-pr-ci-candidate-observation/v1", "RAW_ARTIFACT_SCHEMA_MISMATCH", "candidate observation schema differs")
    require(observation["repository"] == "tangpingqingwa/hartevo-desktop" and observation["sourceApi"] == "github-rest-v3+local-git" and observation["observationStatus"] in {"OBSERVED_EXTERNAL", "NOT_EXECUTED_EXTERNAL"}, "RAW_ARTIFACT_SCHEMA_MISMATCH", "candidate observation provenance differs")
    utc_time(observation["capturedAt"], "candidate observation capturedAt")
    expected_candidate = contract["candidatePolicy"]["pullRequest"]
    expected_baseline = {"ref": expected_candidate["baseRef"], "commit": contract["currentBaseline"]["commit"], "tree": contract["currentBaseline"]["tree"]}
    require(observation["baseline"] == expected_baseline and observation["baseline"] == manifest["baseline"], "MANIFEST_SOURCE_MISMATCH", "candidate observation baseline differs")
    validate_candidate_object(observation["candidate"], expected_candidate, "candidate observation.candidate")
    require(observation["candidate"] == manifest["candidate"], "PR_HEAD_MISMATCH", "candidate raw/manifest identity differs")
    validate_candidate_ci(observation["ci"], contract["candidatePolicy"]["ci"], "candidate observation.ci")
    require(observation["ci"] == manifest["ci"], "CANDIDATE_CI_HEAD_MISMATCH", "candidate raw/manifest CI differs")
    validate_protected_run(observation["protectedIntegrationRun"], contract["candidatePolicy"]["protectedIntegrationRun"], "candidate observation.protectedIntegrationRun")
    require(observation["protectedIntegrationRun"] == manifest["protectedIntegrationRun"], "CANDIDATE_CI_HEAD_MISMATCH", "protected raw/manifest run differs")
    validate_native_evidence(observation["nativeEvidence"], contract["nativeEvidencePolicy"], "candidate observation.nativeEvidence")
    require(observation["nativeEvidence"] == manifest["nativeEvidence"], "NATIVE_EVIDENCE_ESCALATION", "native raw/manifest provenance differs")
    validate_evidence_roles(observation["evidenceRoles"], contract["evidenceRolePolicy"], expected_candidate["headCommit"], "candidate observation.evidenceRoles")
    require(observation["evidenceRoles"] == manifest["evidenceRoles"], "EVIDENCE_ROLE_MISSING", "evidence raw/manifest roles differ")


def verify_candidate_receipt(contract: Mapping[str, Any], manifest: Mapping[str, Any], observation: Mapping[str, Any], manifest_raw: bytes, raw_artifact: bytes) -> None:
    instance = contract["currentInstance"]
    require(sha256(manifest_raw) == instance["manifestSha256"] and len(manifest_raw) == instance["manifestBytes"], "MANIFEST_DIGEST_MISMATCH", "candidate manifest digest differs")
    require(sha256(raw_artifact) == instance["rawArtifactSha256"] and len(raw_artifact) == instance["rawArtifactBytes"], "RAW_ARTIFACT_DIGEST_MISMATCH", "candidate raw artifact digest differs")
    validate_candidate_manifest(contract, manifest, instance["rawArtifactPath"], instance["rawArtifactSha256"], instance["rawArtifactBytes"])
    validate_candidate_observation(contract, observation, manifest)
    baseline = contract["currentBaseline"]
    observed_base = git_text("rev-parse", "origin/bootstrap/macos-r0")
    require(observed_base == baseline["commit"] and git_text("rev-parse", "origin/bootstrap/macos-r0^{tree}") == baseline["tree"], "CURRENT_COMMIT_MISMATCH", "protected baseline ref/tree differs")
    expected_candidate = contract["candidatePolicy"]["pullRequest"]
    require(git_text("rev-parse", f"{expected_candidate['headCommit']}^{{tree}}") == expected_candidate["headTree"], "CURRENT_COMMIT_MISMATCH", "candidate source tree differs")
    require(git_ancestor(expected_candidate["headCommit"], git_text("rev-parse", "HEAD")), "CURRENT_COMMIT_MISMATCH", "receipt checkout does not descend from candidate source")
    first_parent = git_text("rev-parse", "HEAD^1")
    if first_parent == expected_candidate["headCommit"]:
        second_parent_result = run(("git", "rev-parse", "HEAD^2"), check=False)
        require(second_parent_result.returncode == 0, "CURRENT_COMMIT_MISMATCH", "candidate receipt merge is missing its protected second parent")
        second_parent = second_parent_result.stdout.decode("utf-8", errors="strict").strip()
        require(second_parent == contract["currentBaseline"]["commit"], "CURRENT_COMMIT_MISMATCH", "candidate receipt merge second parent differs from the protected baseline")
        changed_paths = set(git_text("diff", "--name-only", second_parent, "HEAD").splitlines())
    else:
        changed_paths = set(git_text("diff", "--name-only", expected_candidate["headCommit"], "HEAD").splitlines())
    allowed_paths = {
        CONTRACT_REL,
        "scripts/check-integration-build-provenance.sh",
        contract["currentInstance"]["manifestPath"],
        contract["currentInstance"]["rawArtifactPath"],
        contract["historicalInstance"]["manifestPath"],
        contract["historicalInstance"]["rawArtifactPath"],
    }
    require(changed_paths <= allowed_paths, "CURRENT_COMMIT_MISMATCH", "candidate receipt checkout contains unrelated changes")
    native_blob = git_blob_bytes(contract["nativeEvidencePolicy"]["sourceCommit"], contract["nativeEvidencePolicy"]["path"])
    require(sha256(native_blob) == contract["nativeEvidencePolicy"]["sha256"] and len(native_blob) == contract["nativeEvidencePolicy"]["bytes"], "NATIVE_EVIDENCE_ESCALATION", "native evidence contract blob differs")
    candidate = manifest["candidate"]
    if candidate["draft"] is True:
        raise GateError("PR_DRAFT", f"candidate PR #{candidate['number']} is draft")
    if candidate["merged"] is not True or candidate["state"] != "CLOSED":
        raise GateError("PR_NOT_MERGED", f"candidate PR #{candidate['number']} is not closed+merged")
    ci = manifest["ci"]
    if ci["status"] == "NOT_EXECUTED_EXTERNAL":
        raise GateError("CANDIDATE_CI_NOT_EXECUTED", "candidate PR has no external CI run after rebase")
    if ci["status"] != "completed":
        raise GateError("CI_STATUS_NOT_COMPLETED", "candidate PR CI is not completed")
    if ci["conclusion"] != "success":
        raise GateError("CI_CONCLUSION_NOT_SUCCESS", "candidate PR CI conclusion is not success")
    protected = manifest["protectedIntegrationRun"]
    if protected["status"] != "completed":
        raise GateError("CI_STATUS_NOT_COMPLETED", "protected integration run is not completed")
    if protected["conclusion"] != "success":
        raise GateError("CI_CONCLUSION_NOT_SUCCESS", "protected integration conclusion is not success")


def verify_current_baseline(contract: Mapping[str, Any]) -> None:
    baseline = contract["currentBaseline"]
    ref = baseline["ref"]
    ref_commit_result = run(("git", "rev-parse", "--verify", f"{ref}^{{commit}}"), check=False)
    require(
        ref_commit_result.returncode == 0,
        "CURRENT_COMMIT_MISMATCH",
        f"current baseline ref is unavailable: {ref}",
    )
    observed_ref_commit = ref_commit_result.stdout.decode("utf-8", errors="strict").strip()
    require(
        observed_ref_commit == baseline["commit"],
        "CURRENT_COMMIT_MISMATCH",
        f"current baseline ref commit differs: expected {baseline['commit']}, got {observed_ref_commit}",
    )
    observed_ref_tree = git_text("rev-parse", f"{ref}^{{tree}}")
    require(
        observed_ref_tree == baseline["tree"],
        "CURRENT_COMMIT_MISMATCH",
        f"current baseline tree differs: expected {baseline['tree']}, got {observed_ref_tree}",
    )
    observed_head = git_text("rev-parse", "HEAD")
    require(
        observed_head == baseline["commit"],
        "CURRENT_COMMIT_MISMATCH",
        f"current checkout is not the exact published baseline: expected {baseline['commit']}, got {observed_head}",
    )
    require(
        contract["source"]["headCommit"] == baseline["commit"],
        "HISTORICAL_ARTIFACT_STALE",
        f"tracked artifact source {contract['source']['headCommit']} predates current baseline {baseline['commit']}",
    )


def verify_records(contract: Mapping[str, Any], manifest: Mapping[str, Any], observation: Mapping[str, Any]) -> None:
    source = contract["source"]
    require(git_text("rev-parse", "--show-object-format") == source["objectFormat"], "MANIFEST_SOURCE_MISMATCH", "repository object format differs")
    require(git_text("rev-parse", f"{source['headCommit']}^{{tree}}") == source["headTree"], "INTEGRATION_HEAD_MISMATCH", "integration head tree differs")
    require(git_ancestor(source["rangeBaseCommit"], source["headCommit"]), "INTEGRATION_HEAD_MISMATCH", "range base is not an ancestor of integration head")
    head = git_text("rev-parse", "HEAD")
    require(git_ancestor(source["headCommit"], head), "HEAD_NOT_DESCENDANT", "current HEAD does not descend from the integration source")

    records = manifest["featurePullRequests"]
    raw_records = observation["pullRequests"]
    history = manifest["integrationHistory"]
    require(len(records) == source["expectedFeaturePullRequestMergeCount"], "PR_MERGE_CHAIN_MISMATCH", "manifest feature merge count differs from the contract")
    require(len(history) == source["expectedFirstParentCommitCount"], "PR_MERGE_CHAIN_MISMATCH", "manifest first-parent history count differs from the contract")
    require(len(raw_records) == len(records), "PR_MERGE_CHAIN_MISMATCH", "raw PR count differs from the manifest")
    first_parent_commits = git_text("rev-list", "--first-parent", "--reverse", f"{source['rangeBaseCommit']}..{source['headCommit']}").splitlines()
    require(first_parent_commits == [event["commit"] for event in history], "PR_MERGE_CHAIN_MISMATCH", "first-parent integration range differs from the manifest history")

    records_by_number = {record["number"]: record for record in records}
    previous = source["rangeBaseCommit"]
    feature_events: List[int] = []
    reverted_prs: set[int] = set()
    for event in history:
        commit = event["commit"]
        if event["kind"] == "FEATURE_PR_MERGE":
            number = event["pullRequest"]
            record = records_by_number.get(number)
            require(record is not None, "PR_MERGE_CHAIN_MISMATCH", f"history references missing PR #{number}")
            require(record["mergeCommit"] == commit and record["integrationParent"] == previous, "PR_MERGE_CHAIN_MISMATCH", f"PR #{number} history binding differs")
            parents = git_text("rev-list", "--parents", "-n", "1", commit).split()
            require(parents == [commit, previous, record["featureHead"]], "PR_MERGE_CHAIN_MISMATCH", f"PR #{number} merge parents differ")
            owner = source["repository"].split("/", 1)[0]
            expected_subject = f"Merge pull request #{number} from {owner}/{record['headRef']}"
            require(git_text("show", "-s", "--format=%s", commit) == expected_subject, "PR_MERGE_CHAIN_MISMATCH", f"PR #{number} merge subject differs")
            feature_events.append(number)
        else:
            number = event["revertedPullRequest"]
            record = records_by_number.get(number)
            require(record is not None and number in feature_events, "REVERT_HISTORY_MISMATCH", f"revert references non-prior PR #{number}")
            require(number not in reverted_prs, "REVERT_HISTORY_MISMATCH", f"PR #{number} is reverted more than once")
            require(event["parent"] == previous and event["revertsCommit"] == record["mergeCommit"], "REVERT_HISTORY_MISMATCH", f"PR #{number} revert binding differs")
            parents = git_text("rev-list", "--parents", "-n", "1", commit).split()
            require(parents == [commit, previous], "REVERT_HISTORY_MISMATCH", f"PR #{number} revert must be a single-parent commit")
            expected_subject = f'Revert "Merge pull request #{number} from {source["repository"].split("/", 1)[0]}/{record["headRef"]}"'
            require(git_text("show", "-s", "--format=%s", commit) == expected_subject, "REVERT_HISTORY_MISMATCH", f"PR #{number} revert subject differs")
            require(f"This reverts commit {event['revertsCommit']}" in git_text("show", "-s", "--format=%B", commit), "REVERT_HISTORY_MISMATCH", f"PR #{number} revert body differs")
            reverted_prs.add(number)
        previous = commit
    require(feature_events == [record["number"] for record in records], "PR_MERGE_CHAIN_MISMATCH", "feature merge events differ from manifest records")
    require(len(reverted_prs) == source["expectedRevertCommitCount"], "REVERT_HISTORY_MISMATCH", "revert count differs from the contract")
    require(previous == source["headCommit"], "INTEGRATION_HEAD_MISMATCH", "final integration history commit differs from source head")
    require(manifest["summary"]["activeFeaturePullRequestCount"] == len(records) - len(reverted_prs), "REVERT_HISTORY_MISMATCH", "active feature count includes a reverted PR")

    captured_at = utc_time(observation["capturedAt"], "raw observation capturedAt")
    seen_runs: set[int] = set()
    seen_prs: set[int] = set()
    for index, (record, raw_pr) in enumerate(zip(records, raw_records)):
        require(isinstance(raw_pr, dict), "SCHEMA_TYPE_MISMATCH", f"raw pullRequests[{index}] must be an object")
        exact_keys(raw_pr, ("number", "state", "merged", "draft", "baseRef", "baseSha", "headRef", "headSha", "mergeCommit", "mergedAt", "actionsRun"), f"raw pullRequests[{index}]")
        number = positive_int(raw_pr["number"], f"raw pullRequests[{index}].number")
        require(number not in seen_prs, "PR_MERGE_CHAIN_MISMATCH", f"duplicate PR number: {number}")
        seen_prs.add(number)
        require(number == record["number"], "PR_MERGE_CHAIN_MISMATCH", f"raw/manifest PR order differs at index {index}")

        if raw_pr["draft"] is not False:
            raise GateError("PR_DRAFT", f"PR #{number} is draft")
        if raw_pr["merged"] is not True or raw_pr["state"] != contract["pullRequestPolicy"]["state"]:
            raise GateError("PR_NOT_MERGED", f"PR #{number} is not closed+merged")
        require(raw_pr["baseRef"] == contract["pullRequestPolicy"]["baseRef"] == record["baseRef"], "PR_BASE_MISMATCH", f"PR #{number} base ref differs")
        require(isinstance(raw_pr["headRef"], str) and raw_pr["headRef"].startswith(contract["pullRequestPolicy"]["headRefPrefix"]), "PR_HEAD_MISMATCH", f"PR #{number} head ref is outside the feature namespace")
        require(raw_pr["headRef"] == record["headRef"], "PR_HEAD_MISMATCH", f"PR #{number} head ref differs")
        raw_base = git_id(raw_pr["baseSha"], f"PR #{number} baseSha")
        raw_head = git_id(raw_pr["headSha"], f"PR #{number} headSha")
        raw_merge = git_id(raw_pr["mergeCommit"], f"PR #{number} mergeCommit")
        require(raw_head == record["featureHead"], "PR_HEAD_MISMATCH", f"PR #{number} feature head differs")
        require(raw_merge == record["mergeCommit"], "PR_MERGE_CHAIN_MISMATCH", f"PR #{number} merge commit differs")
        require(git_ancestor(raw_base, record["integrationParent"]), "PR_BASE_ANCESTRY_MISMATCH", f"PR #{number} observed base is not an ancestor of the integration parent")

        merged_at = utc_time(raw_pr["mergedAt"], f"PR #{number} mergedAt")
        require(merged_at <= captured_at, "RAW_ARTIFACT_TIME_MISMATCH", f"PR #{number} merge is later than observation capture")
        ci = raw_pr.get("actionsRun")
        if not isinstance(ci, dict):
            raise GateError("CI_RUN_MISSING", f"PR #{number} has no CI run")
        exact_keys(ci, ("provider", "id", "workflowId", "name", "path", "event", "status", "conclusion", "runNumber", "runAttempt", "headBranch", "headSha", "checkSuiteId", "createdAt", "updatedAt", "jobs"), f"PR #{number} actionsRun")
        ci_id = positive_int(ci["id"], f"PR #{number} actionsRun.id")
        require(ci_id not in seen_runs, "CI_RUN_POLICY_MISMATCH", f"duplicate CI run id: {ci_id}")
        seen_runs.add(ci_id)
        require(ci_id == record["actionsRunId"], "CI_RUN_MISSING", f"PR #{number} CI run id differs")
        policy = contract["ciPolicy"]
        require(
            ci["provider"] == policy["provider"]
            and ci["workflowId"] == policy["workflowId"]
            and ci["name"] == policy["workflowName"]
            and ci["path"] == policy["workflowPath"]
            and ci["event"] == policy["event"]
            and isinstance(ci["runAttempt"], int)
            and not isinstance(ci["runAttempt"], bool)
            and ci["runAttempt"] > 0,
            "CI_RUN_POLICY_MISMATCH",
            f"PR #{number} CI run policy differs",
        )
        positive_int(ci["runNumber"], f"PR #{number} actionsRun.runNumber")
        positive_int(ci["checkSuiteId"], f"PR #{number} actionsRun.checkSuiteId")
        require(ci["headBranch"] == raw_pr["headRef"], "CI_HEAD_MISMATCH", f"PR #{number} CI head branch differs")
        require(ci["headSha"] == raw_head, "CI_HEAD_MISMATCH", f"PR #{number} CI head SHA differs")
        if ci["status"] != policy["status"]:
            raise GateError("CI_STATUS_NOT_COMPLETED", f"PR #{number} CI run is not completed")
        if ci["conclusion"] != policy["conclusion"] or record["ciConclusion"] != ci["conclusion"].upper():
            raise GateError("CI_CONCLUSION_NOT_SUCCESS", f"PR #{number} CI conclusion is not success")
        created_at = utc_time(ci["createdAt"], f"PR #{number} CI createdAt")
        updated_at = utc_time(ci["updatedAt"], f"PR #{number} CI updatedAt")
        require(created_at <= updated_at <= merged_at, "RAW_ARTIFACT_TIME_MISMATCH", f"PR #{number} CI chronology differs")

        jobs = ci.get("jobs")
        if not isinstance(jobs, list):
            raise GateError("CI_JOB_MISSING", f"PR #{number} CI jobs are missing")
        expected_names = policy["requiredJobs"]
        actual_names = [job.get("name") if isinstance(job, dict) else None for job in jobs]
        if actual_names != expected_names:
            raise GateError("CI_JOB_MISSING", f"PR #{number} required CI job set differs")
        manifest_jobs = record["requiredJobs"]
        for job, manifest_job in zip(jobs, manifest_jobs):
            require(isinstance(job, dict), "CI_JOB_MISSING", f"PR #{number} job is missing")
            exact_keys(job, ("id", "name", "status", "conclusion", "runAttempt", "headSha", "startedAt", "completedAt"), f"PR #{number} job")
            require(job["id"] == manifest_job["id"] and job["name"] == manifest_job["name"], "CI_JOB_MISSING", f"PR #{number} job identity differs")
            require(job["runAttempt"] == ci["runAttempt"], "CI_RUN_POLICY_MISMATCH", f"PR #{number} job run attempt differs")
            require(job["headSha"] == raw_head, "CI_HEAD_MISMATCH", f"PR #{number} job head SHA differs")
            if job["status"] != policy["status"] or job["conclusion"] != policy["conclusion"] or manifest_job["conclusion"] != job["conclusion"].upper():
                raise GateError("CI_JOB_NOT_SUCCESS", f"PR #{number} job {job['name']} is not completed+success")
            started_at = utc_time(job["startedAt"], f"PR #{number} job startedAt")
            completed_at = utc_time(job["completedAt"], f"PR #{number} job completedAt")
            require(created_at <= started_at <= completed_at <= updated_at, "RAW_ARTIFACT_TIME_MISMATCH", f"PR #{number} job chronology differs")


def verify_all(
    contract: Mapping[str, Any],
    manifest: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    require_current_baseline: bool = False,
) -> None:
    validate_contract(contract)
    validate_manifest(contract, manifest)
    validate_observation(observation)
    if require_current_baseline:
        verify_current_baseline(contract)
    verify_records(contract, manifest, observation)


def expect_error(checks: List[str], check_id: str, expected_code: str, operation: Callable[[], Any]) -> None:
    try:
        operation()
    except GateError as error:
        require(error.code == expected_code, "SELF_TEST_WRONG_FAILURE", f"{check_id} returned {error.code}, expected {expected_code}")
        checks.append(check_id)
        return
    raise GateError("SELF_TEST_FALSE_PASS", f"{check_id} unexpectedly passed")


def emit(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


contract_data: Dict[str, Any] = {}
try:
    contract_raw, contract_data = load_contract()
    manifest_raw, manifest_data, observation_raw, observation_data = load_instance(contract_data)
    candidate_manifest_raw, candidate_manifest_data, candidate_raw, candidate_observation_data = load_candidate_instance(contract_data)

    if MODE == "verify":
        verify_all(contract_data, manifest_data, observation_data, require_current_baseline=False)
        verify_candidate_receipt(contract_data, candidate_manifest_data, candidate_observation_data, candidate_manifest_raw, candidate_raw)
        result = contract_data["resultPolicy"]
        emit({
            "artifactStatus": contract_data["currentBaseline"]["artifactStatus"],
            "authority": AUTHORITY,
            "code": result["verificationCode"],
            "contractSha256": CONTRACT_SHA256,
            "currentBaselineCommit": contract_data["currentBaseline"]["commit"],
            "candidateHead": contract_data["candidatePolicy"]["pullRequest"]["headCommit"],
            "candidateManifestSha256": contract_data["currentInstance"]["manifestSha256"],
            "candidateRawArtifactSha256": contract_data["currentInstance"]["rawArtifactSha256"],
            "missionEvidenceLevelPromoted": result["missionEvidenceLevelPromoted"],
            "releaseDecision": result["releaseDecision"],
            "releasePassed": result["releasePassed"],
            "schema": SCHEMA,
            "status": result["verificationStatus"],
            "testMode": False,
        })
    else:
        verify_all(contract_data, manifest_data, observation_data, require_current_baseline=False)
        checks: List[str] = ["historical-instance-validated"]
        expect_error(
            checks,
            "current-checkout-mismatch",
            "CURRENT_COMMIT_MISMATCH",
            lambda: verify_current_baseline(contract_data),
        )

        current_head_baseline = copy.deepcopy(contract_data)
        current_head_baseline["currentBaseline"]["ref"] = "HEAD"
        current_head_baseline["currentBaseline"]["commit"] = git_text("rev-parse", "HEAD")
        current_head_baseline["currentBaseline"]["tree"] = git_text("rev-parse", "HEAD^{tree}")
        expect_error(
            checks,
            "historical-artifact-source-mismatch",
            "HISTORICAL_ARTIFACT_STALE",
            lambda: verify_current_baseline(current_head_baseline),
        )
        expect_error(
            checks,
            "current-candidate-draft",
            "PR_DRAFT",
            lambda: verify_candidate_receipt(contract_data, candidate_manifest_data, candidate_observation_data, candidate_manifest_raw, candidate_raw),
        )

        candidate_not_draft = copy.deepcopy(candidate_manifest_data)
        candidate_not_draft["candidate"]["draft"] = False
        candidate_not_draft["candidate"]["merged"] = True
        candidate_not_draft["candidate"]["state"] = "CLOSED"
        candidate_not_draft["ci"]["status"] = "NOT_EXECUTED_EXTERNAL"
        candidate_not_draft_observation = copy.deepcopy(candidate_observation_data)
        candidate_not_draft_observation["candidate"]["draft"] = False
        candidate_not_draft_observation["candidate"]["merged"] = True
        candidate_not_draft_observation["candidate"]["state"] = "CLOSED"
        candidate_not_draft_observation["ci"]["status"] = "NOT_EXECUTED_EXTERNAL"
        candidate_pending_contract = copy.deepcopy(contract_data)
        candidate_pending_contract["candidatePolicy"]["pullRequest"]["draft"] = False
        candidate_pending_contract["candidatePolicy"]["pullRequest"]["merged"] = True
        candidate_pending_contract["candidatePolicy"]["pullRequest"]["state"] = "CLOSED"
        expect_error(
            checks,
            "current-candidate-ci-not-executed",
            "CANDIDATE_CI_NOT_EXECUTED",
            lambda: verify_candidate_receipt(candidate_pending_contract, candidate_not_draft, candidate_not_draft_observation, candidate_manifest_raw, candidate_raw),
        )

        candidate_head = copy.deepcopy(candidate_manifest_data)
        candidate_head["candidate"]["headCommit"] = "0" * 40
        expect_error(
            checks,
            "current-candidate-head-mismatch",
            "MANIFEST_SOURCE_MISMATCH",
            lambda: validate_candidate_manifest(contract_data, candidate_head, contract_data["currentInstance"]["rawArtifactPath"], contract_data["currentInstance"]["rawArtifactSha256"], contract_data["currentInstance"]["rawArtifactBytes"]),
        )

        candidate_role = copy.deepcopy(candidate_manifest_data)
        candidate_role["evidenceRoles"]["consumer"]["sourceCommit"] = "0" * 40
        expect_error(
            checks,
            "current-candidate-role-cross-commit",
            "EVIDENCE_ROLE_MISSING",
            lambda: validate_candidate_manifest(contract_data, candidate_role, contract_data["currentInstance"]["rawArtifactPath"], contract_data["currentInstance"]["rawArtifactSha256"], contract_data["currentInstance"]["rawArtifactBytes"]),
        )

        candidate_ci_head = copy.deepcopy(candidate_manifest_data)
        candidate_ci_head["ci"]["headCommit"] = "0" * 40
        expect_error(
            checks,
            "current-candidate-ci-head-mismatch",
            "CANDIDATE_CI_HEAD_MISMATCH",
            lambda: validate_candidate_manifest(contract_data, candidate_ci_head, contract_data["currentInstance"]["rawArtifactPath"], contract_data["currentInstance"]["rawArtifactSha256"], contract_data["currentInstance"]["rawArtifactBytes"]),
        )

        candidate_release = copy.deepcopy(candidate_manifest_data)
        candidate_release["nativeEvidence"]["releasePassed"] = True
        expect_error(
            checks,
            "current-candidate-native-release-escalation",
            "NATIVE_EVIDENCE_ESCALATION",
            lambda: validate_candidate_manifest(contract_data, candidate_release, contract_data["currentInstance"]["rawArtifactPath"], contract_data["currentInstance"]["rawArtifactSha256"], contract_data["currentInstance"]["rawArtifactBytes"]),
        )

        duplicate_raw = observation_raw.replace(b"{", b'{"schemaVersion":"duplicate",', 1)
        expect_error(checks, "raw-duplicate-object-key", "DUPLICATE_OBJECT_KEY", lambda: load_json(duplicate_raw, "duplicate raw observation"))
        expect_error(checks, "raw-artifact-digest-drift", "RAW_ARTIFACT_DIGEST_MISMATCH", lambda: load_instance(contract_data, raw_override=observation_raw + b" "))
        expect_error(checks, "manifest-digest-drift", "MANIFEST_DIGEST_MISMATCH", lambda: load_instance(contract_data, manifest_override=manifest_raw + b" "))

        missing_ci = copy.deepcopy(observation_data)
        missing_ci["pullRequests"][0]["actionsRun"] = None
        expect_error(checks, "missing-ci-run", "CI_RUN_MISSING", lambda: verify_all(contract_data, manifest_data, missing_ci))

        pending_ci = copy.deepcopy(observation_data)
        pending_ci["pullRequests"][0]["actionsRun"]["status"] = "in_progress"
        expect_error(checks, "incomplete-ci-run", "CI_STATUS_NOT_COMPLETED", lambda: verify_all(contract_data, manifest_data, pending_ci))

        failed_ci = copy.deepcopy(observation_data)
        failed_ci["pullRequests"][0]["actionsRun"]["conclusion"] = "failure"
        expect_error(checks, "failed-ci-run", "CI_CONCLUSION_NOT_SUCCESS", lambda: verify_all(contract_data, manifest_data, failed_ci))

        wrong_workflow = copy.deepcopy(observation_data)
        wrong_workflow["pullRequests"][0]["actionsRun"]["workflowId"] += 1
        expect_error(checks, "wrong-ci-workflow", "CI_RUN_POLICY_MISMATCH", lambda: verify_all(contract_data, manifest_data, wrong_workflow))

        wrong_attempt = copy.deepcopy(observation_data)
        wrong_attempt["pullRequests"][-1]["actionsRun"]["jobs"][0]["runAttempt"] = 1
        expect_error(checks, "ci-run-attempt-mismatch", "CI_RUN_POLICY_MISMATCH", lambda: verify_all(contract_data, manifest_data, wrong_attempt))

        missing_job = copy.deepcopy(observation_data)
        missing_job["pullRequests"][0]["actionsRun"]["jobs"].pop()
        expect_error(checks, "missing-ci-job", "CI_JOB_MISSING", lambda: verify_all(contract_data, manifest_data, missing_job))

        failed_job = copy.deepcopy(observation_data)
        failed_job["pullRequests"][0]["actionsRun"]["jobs"][0]["conclusion"] = "failure"
        expect_error(checks, "failed-ci-job", "CI_JOB_NOT_SUCCESS", lambda: verify_all(contract_data, manifest_data, failed_job))

        ci_head = copy.deepcopy(observation_data)
        ci_head["pullRequests"][0]["actionsRun"]["headSha"] = "0" * 40
        expect_error(checks, "ci-head-mismatch", "CI_HEAD_MISMATCH", lambda: verify_all(contract_data, manifest_data, ci_head))

        draft_pr = copy.deepcopy(observation_data)
        draft_pr["pullRequests"][0]["draft"] = True
        expect_error(checks, "draft-pr", "PR_DRAFT", lambda: verify_all(contract_data, manifest_data, draft_pr))

        unmerged_pr = copy.deepcopy(observation_data)
        unmerged_pr["pullRequests"][0]["merged"] = False
        expect_error(checks, "unmerged-pr", "PR_NOT_MERGED", lambda: verify_all(contract_data, manifest_data, unmerged_pr))

        wrong_base = copy.deepcopy(observation_data)
        wrong_base["pullRequests"][0]["baseRef"] = "main"
        expect_error(checks, "pr-base-mismatch", "PR_BASE_MISMATCH", lambda: verify_all(contract_data, manifest_data, wrong_base))

        base_ancestry = copy.deepcopy(observation_data)
        base_ancestry["pullRequests"][0]["baseSha"] = base_ancestry["pullRequests"][0]["headSha"]
        expect_error(checks, "pr-base-ancestry-mismatch", "PR_BASE_ANCESTRY_MISMATCH", lambda: verify_all(contract_data, manifest_data, base_ancestry))

        wrong_head = copy.deepcopy(observation_data)
        wrong_head["pullRequests"][0]["headSha"] = "0" * 40
        expect_error(checks, "pr-head-mismatch", "PR_HEAD_MISMATCH", lambda: verify_all(contract_data, manifest_data, wrong_head))

        broken_chain = copy.deepcopy(manifest_data)
        broken_chain["featurePullRequests"][1]["integrationParent"] = contract_data["source"]["rangeBaseCommit"]
        expect_error(checks, "pr-merge-chain-mismatch", "PR_MERGE_CHAIN_MISMATCH", lambda: verify_all(contract_data, broken_chain, observation_data))

        broken_revert = copy.deepcopy(manifest_data)
        broken_revert["integrationHistory"][-2]["revertsCommit"] = "0" * 40
        expect_error(checks, "revert-history-mismatch", "REVERT_HISTORY_MISMATCH", lambda: verify_all(contract_data, broken_revert, observation_data))

        manifest_source = copy.deepcopy(manifest_data)
        manifest_source["source"]["headCommit"] = contract_data["source"]["rangeBaseCommit"]
        expect_error(checks, "manifest-source-mismatch", "MANIFEST_SOURCE_MISMATCH", lambda: verify_all(contract_data, manifest_source, observation_data))

        release_manifest = copy.deepcopy(manifest_data)
        release_manifest["summary"]["releasePassed"] = True
        expect_error(checks, "manifest-release-escalation", "RELEASE_AUTHORITY_ESCALATION", lambda: verify_all(contract_data, release_manifest, observation_data))

        release_contract = copy.deepcopy(contract_data)
        release_contract["resultPolicy"]["missionEvidenceLevelPromoted"] = True
        expect_error(checks, "contract-elevel-escalation", "RELEASE_AUTHORITY_ESCALATION", lambda: verify_all(release_contract, manifest_data, observation_data))

        checks.sort()
        require(len(checks) == len(set(checks)), "SELF_TEST_CHECK_DUPLICATE", "self-test check ids must be unique")
        emit(
            {
                "authority": AUTHORITY,
                "artifactStatus": contract_data["currentBaseline"]["artifactStatus"],
                "checks": checks,
                "checksPassed": len(checks),
                "code": "INTEGRATION_BUILD_PROVENANCE_SELF_TEST_VERIFIED",
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
            "artifactStatus": contract_data.get("currentBaseline", {}).get("artifactStatus", "UNKNOWN"),
            "authority": AUTHORITY,
            "code": error.code,
            "currentBaselineCommit": contract_data.get("currentBaseline", {}).get("commit"),
            "integrationHead": contract_data.get("source", {}).get("headCommit"),
            "candidateHead": contract_data.get("candidatePolicy", {}).get("pullRequest", {}).get("headCommit"),
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
except Exception as error:  # Fail closed on unexpected parser, Git, or filesystem failures.
    emit(
        {
            "artifactStatus": contract_data.get("currentBaseline", {}).get("artifactStatus", "UNKNOWN"),
            "authority": AUTHORITY,
            "code": "INTERNAL_ERROR",
            "currentBaselineCommit": contract_data.get("currentBaseline", {}).get("commit"),
            "integrationHead": contract_data.get("source", {}).get("headCommit"),
            "candidateHead": contract_data.get("candidatePolicy", {}).get("pullRequest", {}).get("headCommit"),
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
