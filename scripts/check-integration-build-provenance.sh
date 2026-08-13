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
CONTRACT_SHA256 = "7e8dc63ec75a70242991c63499e4d51095fa021c4ecbcc3cf7f5b859cde24a3d"
EXPECTED_FAIL_CODES = [
    "CI_CONCLUSION_NOT_SUCCESS",
    "CI_HEAD_MISMATCH",
    "CI_JOB_MISSING",
    "CI_JOB_NOT_SUCCESS",
    "CI_RUN_MISSING",
    "CI_RUN_POLICY_MISMATCH",
    "CI_STATUS_NOT_COMPLETED",
    "CONTRACT_DIGEST_MISMATCH",
    "HEAD_NOT_DESCENDANT",
    "INTEGRATION_HEAD_MISMATCH",
    "MANIFEST_DIGEST_MISMATCH",
    "MANIFEST_SOURCE_MISMATCH",
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


def validate_contract(contract: Mapping[str, Any]) -> None:
    exact_keys(
        contract,
        ("schemaVersion", "contractId", "authority", "currentInstance", "source", "pullRequestPolicy", "integrationHistoryPolicy", "ciPolicy", "resultPolicy", "failClosedCodes", "gate"),
        "contract",
    )
    require(contract["schemaVersion"] == "hartevo.integration-build-provenance-contract/v1", "CONTRACT_SCHEMA_MISMATCH", "unexpected contract schema")
    require(contract["contractId"] == "ev-04-integration-build-provenance-v1", "CONTRACT_ID_MISMATCH", "unexpected contract id")
    require(contract["authority"] == AUTHORITY, "RELEASE_AUTHORITY_ESCALATION", "contract authority must remain integration provenance only")

    instance = contract["currentInstance"]
    require(isinstance(instance, dict), "SCHEMA_TYPE_MISMATCH", "currentInstance must be an object")
    exact_keys(instance, ("manifestPath", "manifestSha256", "manifestBytes", "rawArtifactPath", "rawArtifactSha256", "rawArtifactBytes"), "currentInstance")
    safe_relative_path(instance["manifestPath"], "currentInstance.manifestPath")
    digest(instance["manifestSha256"], "currentInstance.manifestSha256")
    positive_int(instance["manifestBytes"], "currentInstance.manifestBytes")
    safe_relative_path(instance["rawArtifactPath"], "currentInstance.rawArtifactPath")
    digest(instance["rawArtifactSha256"], "currentInstance.rawArtifactSha256")
    positive_int(instance["rawArtifactBytes"], "currentInstance.rawArtifactBytes")

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
    require(result["verificationCode"] == "INTEGRATION_BUILD_PROVENANCE_VERIFIED" and result["verificationStatus"] == "VERIFIED", "RESULT_POLICY_MISMATCH", "verification result differs")
    require(
        result["releaseDecision"] == "NOT_EVALUATED"
        and result["releasePassed"] is False
        and result["missionEvidenceLevelPromoted"] is False
        and result["maySatisfyReleaseEvidence"] is False
        and result["mayPromoteMissionEvidenceLevel"] is False,
        "RELEASE_AUTHORITY_ESCALATION",
        "integration evidence must not grant Release or Mission evidence-level authority",
    )
    require(contract["failClosedCodes"] == EXPECTED_FAIL_CODES, "CONTRACT_FAIL_CODES_MISMATCH", "fail-closed code set must be sorted and exact")
    gate = contract["gate"]
    require(isinstance(gate, dict), "SCHEMA_TYPE_MISMATCH", "gate must be an object")
    exact_keys(gate, ("verifyCommand", "selfTestCommand"), "gate")
    require(gate["verifyCommand"] == "bash scripts/check-integration-build-provenance.sh verify", "CONTRACT_GATE_MISMATCH", "verify command differs")
    require(gate["selfTestCommand"] == "bash scripts/check-integration-build-provenance.sh self-test", "CONTRACT_GATE_MISMATCH", "self-test command differs")


def load_contract() -> Tuple[bytes, Dict[str, Any]]:
    raw = read_regular(CONTRACT_REL, "CONTRACT_MISSING")
    require(sha256(raw) == CONTRACT_SHA256, "CONTRACT_DIGEST_MISMATCH", "contract raw SHA-256 differs from the verifier pin")
    contract = load_json(raw, CONTRACT_REL)
    validate_contract(contract)
    return raw, contract


def load_instance(
    contract: Mapping[str, Any],
    *,
    manifest_override: Optional[bytes] = None,
    raw_override: Optional[bytes] = None,
) -> Tuple[bytes, Dict[str, Any], bytes, Dict[str, Any]]:
    instance = contract["currentInstance"]
    manifest_raw = manifest_override if manifest_override is not None else read_regular(instance["manifestPath"], "MANIFEST_MISSING")
    require(sha256(manifest_raw) == instance["manifestSha256"], "MANIFEST_DIGEST_MISMATCH", "manifest raw SHA-256 differs")
    require(len(manifest_raw) == instance["manifestBytes"], "MANIFEST_DIGEST_MISMATCH", "manifest byte count differs")
    manifest = load_json(manifest_raw, instance["manifestPath"])

    raw_artifact = raw_override if raw_override is not None else read_regular(instance["rawArtifactPath"], "RAW_ARTIFACT_MISSING")
    require(sha256(raw_artifact) == instance["rawArtifactSha256"], "RAW_ARTIFACT_DIGEST_MISMATCH", "raw artifact SHA-256 differs")
    require(len(raw_artifact) == instance["rawArtifactBytes"], "RAW_ARTIFACT_DIGEST_MISMATCH", "raw artifact byte count differs")
    observation = load_json(raw_artifact, instance["rawArtifactPath"])
    return manifest_raw, manifest, raw_artifact, observation


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
    instance = contract["currentInstance"]
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


def verify_all(contract: Mapping[str, Any], manifest: Mapping[str, Any], observation: Mapping[str, Any]) -> None:
    validate_contract(contract)
    validate_manifest(contract, manifest)
    validate_observation(observation)
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


try:
    contract_raw, contract_data = load_contract()
    manifest_raw, manifest_data, observation_raw, observation_data = load_instance(contract_data)
    verify_all(contract_data, manifest_data, observation_data)

    if MODE == "verify":
        count = len(manifest_data["featurePullRequests"])
        result = contract_data["resultPolicy"]
        emit(
            {
                "activeFeaturePullRequestCount": manifest_data["summary"]["activeFeaturePullRequestCount"],
                "actionsRunCount": count,
                "authority": AUTHORITY,
                "code": result["verificationCode"],
                "contractSha256": CONTRACT_SHA256,
                "featurePullRequestCount": count,
                "integrationHead": contract_data["source"]["headCommit"],
                "manifestSha256": contract_data["currentInstance"]["manifestSha256"],
                "missionEvidenceLevelPromoted": result["missionEvidenceLevelPromoted"],
                "rawArtifactSha256": contract_data["currentInstance"]["rawArtifactSha256"],
                "releaseDecision": result["releaseDecision"],
                "releasePassed": result["releasePassed"],
                "revertedFeaturePullRequestCount": manifest_data["summary"]["revertedFeaturePullRequestCount"],
                "requiredJobCount": manifest_data["summary"]["requiredJobCount"],
                "schema": SCHEMA,
                "status": result["verificationStatus"],
                "testMode": False,
            }
        )
    else:
        checks: List[str] = ["positive-current-instance"]

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
            "authority": AUTHORITY,
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
except Exception as error:  # Fail closed on unexpected parser, Git, or filesystem failures.
    emit(
        {
            "authority": AUTHORITY,
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
