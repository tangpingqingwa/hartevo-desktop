#!/usr/bin/env python3
"""Fail-closed repository governance control plane.

The program separates facts, decisions, and mutations:

* ``snapshot`` reads live GitHub/Git state;
* ``plan`` derives idempotent actions from a snapshot and hash-chained ledger;
* ``verify-pr-event`` enforces admission inside the existing required policy job;
* exact independent review receipts are receipt-only commits;
* destructive lifecycle execution requires a short-lived approval artifact.

No command treats chat, local tests, commits, pushes, or hand-written counts as
proof of readiness or merge throughput.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence


POLICY_PATH = Path(".github/policies/repository-governance-policy.json")
LEDGER_PATH = Path(".github/governance/events.jsonl")
REVIEW_DIRECTORY = Path(".github/governance/reviews")
REPOSITORY = "tangpingqingwa/hartevo-desktop"
BASE_BRANCH = "bootstrap/macos-r0"
TRAIN_PREFIX = "merge-train/"
EVENT_SCHEMA = "hartevo-throughput-event/v1"
SNAPSHOT_SCHEMA = "hartevo-repository-governance-snapshot/v1"
PLAN_SCHEMA = "hartevo-repository-governance-plan/v1"
APPROVAL_SCHEMA = "hartevo-lifecycle-approval/v1"
NOMINATION_SCHEMA = "hartevo-lifecycle-nominations/v1"
REVIEW_SCHEMA = "hartevo-independent-review-receipt/v1"
ADMISSION_SCHEMA = "hartevo-pr-admission/v1"
ZERO_DIGEST = "0" * 64
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADMISSION_BLOCK = re.compile(r"<!--\s*hartevo-governance\s*(\{.*?\})\s*-->", re.DOTALL)
REPOSITORY_LIFECYCLE_FIELDS = {
    "delete_branch_on_merge": "deleteBranchOnMerge",
    "allow_update_branch": "allowUpdateBranch",
    "allow_merge_commit": "mergeCommitAllowed",
    "allow_squash_merge": "squashMergeAllowed",
    "allow_rebase_merge": "rebaseMergeAllowed",
    "allow_auto_merge": "autoMergeAllowed",
}


class GovernanceError(ValueError):
    """A governance fact or contract failed closed."""


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise GovernanceError("timestamp must include a timezone")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise GovernanceError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GovernanceError(f"{label} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise GovernanceError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA1.fullmatch(value) is None:
        raise GovernanceError(f"{label} must be a lowercase 40-character Git SHA")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def run(argv: Sequence[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(argv),
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise GovernanceError(f"command failed ({' '.join(argv)}): {detail}")
    return result


def git(*args: str, root: Path = Path("."), check: bool = True) -> str:
    return run(("git", "-C", str(root), *args), check=check).stdout.strip()


def gh_json(*args: str, input_value: object | None = None) -> object:
    command = ["gh", *args]
    input_text = None
    if input_value is not None:
        command.extend(("--input", "-"))
        input_text = json.dumps(input_value, sort_keys=True)
    result = subprocess.run(
        command,
        check=False,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise GovernanceError(f"GitHub command failed ({' '.join(command)}): {(result.stderr or result.stdout).strip()}")
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise GovernanceError("GitHub returned invalid JSON") from error


def gh_pages(endpoint: str) -> list[dict[str, object]]:
    value = gh_json("api", "--paginate", "--slurp", endpoint)
    if not isinstance(value, list):
        raise GovernanceError(f"paginated response for {endpoint} must be a list")
    flattened: list[dict[str, object]] = []
    for page in value:
        if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
            raise GovernanceError(f"paginated response for {endpoint} contains an invalid page")
        flattened.extend(item for item in page if isinstance(item, dict))
    return flattened


def merge_repository_lifecycle_settings(
    repository: dict[str, object], graph_repository: dict[str, object]
) -> dict[str, object]:
    """Fill REST-invisible lifecycle booleans from authenticated GraphQL truth."""
    merged = dict(repository)
    for rest_field, graph_field in REPOSITORY_LIFECYCLE_FIELDS.items():
        value = merged.get(rest_field)
        if not isinstance(value, bool):
            value = graph_repository.get(graph_field)
        if not isinstance(value, bool):
            raise GovernanceError(f"GitHub repository lifecycle field {rest_field} is unavailable")
        merged[rest_field] = value
    return merged


def hosted_repository(repo: str) -> tuple[dict[str, object], str]:
    repository = gh_json("api", f"repos/{repo}")
    if not isinstance(repository, dict):
        raise GovernanceError("live repository response is invalid")
    if not isinstance(repository.get("default_branch"), str):
        raise GovernanceError("GitHub repository default branch is unavailable")
    missing = [field for field in REPOSITORY_LIFECYCLE_FIELDS if not isinstance(repository.get(field), bool)]
    if not missing:
        return repository, "REST"
    try:
        owner, name = repo.split("/", 1)
    except ValueError as error:
        raise GovernanceError("GitHub repository must be owner/name") from error
    graph = gh_json(
        "api",
        "graphql",
        input_value={
            "query": """
                query RepositoryLifecycle($owner: String!, $name: String!) {
                  repository(owner: $owner, name: $name) {
                    deleteBranchOnMerge
                    allowUpdateBranch
                    mergeCommitAllowed
                    squashMergeAllowed
                    rebaseMergeAllowed
                    autoMergeAllowed
                  }
                }
            """,
            "variables": {"owner": owner, "name": name},
        },
    )
    if not isinstance(graph, dict) or graph.get("errors"):
        raise GovernanceError("GitHub GraphQL repository lifecycle response is unavailable")
    data = graph.get("data")
    graph_repository = data.get("repository") if isinstance(data, dict) else None
    if not isinstance(graph_repository, dict):
        raise GovernanceError("GitHub GraphQL repository lifecycle response must contain a repository")
    return merge_repository_lifecycle_settings(repository, graph_repository), "GRAPHQL_READ_FALLBACK"


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GovernanceError(f"cannot read JSON {path}: {error}") from error


def write_json(value: object, path: Path | None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    print(json.dumps({"status": "WROTE", "path": str(path), "sha256": digest(value)}, sort_keys=True))


def load_policy(path: Path = POLICY_PATH) -> dict[str, object]:
    value = read_json(path)
    if not isinstance(value, dict):
        raise GovernanceError("governance policy must be an object")
    return value


def require_exact_keys(value: dict[str, object], required: set[str], label: str) -> None:
    missing = sorted(required - set(value))
    if missing:
        raise GovernanceError(f"{label} is missing fields: {missing}")


def verify_policy_value(policy: dict[str, object]) -> dict[str, object]:
    if policy.get("schemaVersion") != "hartevo-repository-governance-policy/v1":
        raise GovernanceError("governance policy schema drift")
    if policy.get("repository") != REPOSITORY or policy.get("protectedBranch") != BASE_BRANCH:
        raise GovernanceError("governance policy repository or protected branch drift")
    if policy.get("admissionModeWhenUnpaused") not in {"drain", "normal"}:
        raise GovernanceError("unpaused admission mode must be drain or normal")
    if policy.get("manualCountsAccepted") is not False:
        raise GovernanceError("manual counts must never be accepted as truth")
    truth = policy.get("truthSources")
    expected_truth = {
        "live-github-api",
        "live-git-refs",
        "hash-chained-governance-ledger",
        "exact-review-receipts",
    }
    if not isinstance(truth, list) or set(truth) != expected_truth:
        raise GovernanceError("governance truth sources drifted")
    capacity = policy.get("capacity")
    if not isinstance(capacity, dict) or capacity != {
        "repair": 4,
        "review": 4,
        "integrationWriters": 1,
        "maximumTrainCandidates": 4,
    }:
        raise GovernanceError("governance capacity must remain repair=4/review=4/integration=1/train=4")
    admission = policy.get("admission")
    if not isinstance(admission, dict):
        raise GovernanceError("admission policy is missing")
    required_fields = admission.get("requiredFields")
    expected_fields = {"schema", "changeClass", "issue", "owner", "ownedPaths", "rollback", "externalEffects", "release"}
    if not isinstance(required_fields, list) or set(required_fields) != expected_fields:
        raise GovernanceError("PR admission required fields drifted")
    paused = admission.get("pausedAllowedClasses")
    drain = admission.get("drainAllowedClasses")
    normal = admission.get("normalAllowedClasses")
    if not all(isinstance(item, list) and item and len(item) == len(set(item)) for item in (paused, drain, normal)):
        raise GovernanceError("admission class sets must be non-empty and unique")
    if not set(paused).issubset(set(drain)) or not set(drain).issubset(set(normal)):
        raise GovernanceError("paused/drain/normal admission classes must expand monotonically")
    if "feature" in set(paused) | set(drain) or "feature" not in set(normal):
        raise GovernanceError("feature work must remain blocked outside normal mode")
    if admission.get("exactPathOwnership") is not True or admission.get("externalEffectsDefault") is not False or admission.get("releaseDefault") is not False:
        raise GovernanceError("admission honesty defaults drifted")
    review = policy.get("review")
    if not isinstance(review, dict) or review.get("schema") != REVIEW_SCHEMA or review.get("receiptDirectory") != str(REVIEW_DIRECTORY):
        raise GovernanceError("review receipt policy drifted")
    review_bools = (
        "requireNonAuthorTask",
        "requireExactBaseAndReviewedHead",
        "requireExactChangedPaths",
        "requireReceiptOnlyCommit",
        "syntheticPreflightGreenRequired",
    )
    if any(review.get(key) is not True for key in review_bools) or review.get("acceptedDisposition") != "APPROVE":
        raise GovernanceError("independent review requirements drifted")
    integration = policy.get("integration")
    if not isinstance(integration, dict):
        raise GovernanceError("integration policy is missing")
    expected_integration = {
        "singleOpenTrain": True,
        "readyToTrainSlaSeconds": 120,
        "maximumCandidateCount": 4,
        "requireNonOverlappingPaths": True,
        "requireCurrentProtectedBase": True,
        "requireExactReviewReceipt": True,
        "requireAllHostedChecksSuccess": True,
        "requireTrustedBaseAdmission": True,
        "requireTrainOnlyRequiredCheck": True,
        "manifestDirectory": ".github/merge-train/manifests",
        "nativeQueueStatus": "BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER",
        "normalProtectedPullRequestMergeOnly": True,
    }
    if integration != expected_integration:
        raise GovernanceError("integration policy drifted")
    lifecycle = policy.get("lifecycle")
    if not isinstance(lifecycle, dict):
        raise GovernanceError("lifecycle policy is missing")
    for key in ("draftReviewAgeDays", "stalePullRequestDays", "staleIssueDays", "orphanBranchReviewDays", "approvalMaximumAgeMinutes"):
        if not isinstance(lifecycle.get(key), int) or int(lifecycle[key]) <= 0:
            raise GovernanceError(f"lifecycle {key} must be positive")
    if lifecycle.get("defaultDryRun") is not True or lifecycle.get("explicitApprovalArtifactRequired") is not True:
        raise GovernanceError("lifecycle changes must remain dry-run and approval-bound")
    if lifecycle.get("automaticCloseEnabled") is not False or lifecycle.get("automaticBranchDeleteEnabled") is not False:
        raise GovernanceError("automatic destructive lifecycle execution must remain disabled")
    settings = policy.get("repositorySettings")
    if settings != {
        "defaultBranch": BASE_BRANCH,
        "deleteBranchOnMerge": True,
        "allowUpdateBranch": True,
        "allowMergeCommit": True,
        "allowSquashMerge": False,
        "allowRebaseMerge": False,
        "allowAutoMerge": False,
        "allowForcePushes": False,
        "allowProtectedBranchDeletion": False,
    }:
        raise GovernanceError("repository settings contract drifted")
    metrics = policy.get("metrics")
    if not isinstance(metrics, dict) or metrics.get("mergeThroughputCountsOnlyProtectedBaseAdvances") is not True or metrics.get("commitPushAndLocalGreenDoNotCountAsMergeThroughput") is not True:
        raise GovernanceError("merge-throughput honesty contract drifted")
    required_metrics = metrics.get("required")
    if not isinstance(required_metrics, list) or len(required_metrics) != len(set(required_metrics)):
        raise GovernanceError("required governance metrics must be unique")
    return {
        "schema": "hartevo-repository-governance-policy-verification/v1",
        "status": "PASS",
        "repository": REPOSITORY,
        "protectedBranch": BASE_BRANCH,
        "unpausedMode": policy["admissionModeWhenUnpaused"],
        "maximumTrainCandidates": 4,
        "destructiveDefault": "DRY_RUN",
    }


def verify_policy(path: Path = POLICY_PATH) -> dict[str, object]:
    return verify_policy_value(load_policy(path))


def validate_event(event: dict[str, object]) -> None:
    if event.get("schema") != EVENT_SCHEMA:
        raise GovernanceError("event schema drift")
    if not isinstance(event.get("eventId"), str) or not event["eventId"]:
        raise GovernanceError("eventId is required")
    parse_time(event.get("occurredAt"), "event occurredAt")
    if event.get("kind") not in {
        "LEASE_STARTED",
        "LEASE_HEARTBEAT",
        "LEASE_PAUSED",
        "LEASE_TERMINAL",
        "REPAIR_TERMINAL",
        "REVIEW_TERMINAL",
        "TRAIN_OPENED",
        "TRAIN_TERMINAL",
        "MERGED",
        "GLOBAL_PAUSED",
        "GLOBAL_RESUMED",
    }:
        raise GovernanceError("unsupported governance event kind")
    pr = event.get("pr")
    if pr is not None and (not isinstance(pr, int) or pr <= 0):
        raise GovernanceError("event PR must be null or positive")
    if pr is not None:
        require_sha(event.get("baseSha"), "event baseSha")
        require_sha(event.get("headSha"), "event headSha")
    elif event.get("baseSha") is not None or event.get("headSha") is not None:
        raise GovernanceError("global events must not claim a PR tuple")
    if not isinstance(event.get("actorTaskId"), str) or not event["actorTaskId"]:
        raise GovernanceError("event actorTaskId is required")
    if not isinstance(event.get("payload"), dict):
        raise GovernanceError("event payload must be an object")


def load_ledger(path: Path = LEDGER_PATH) -> list[dict[str, object]]:
    if not path.is_file():
        raise GovernanceError(f"governance ledger is missing: {path}")
    events: list[dict[str, object]] = []
    previous = ZERO_DIGEST
    previous_time: dt.datetime | None = None
    identifiers: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise GovernanceError(f"ledger line {line_number} is invalid JSON") from error
        if not isinstance(event, dict):
            raise GovernanceError(f"ledger line {line_number} must be an object")
        validate_event(event)
        identifier = str(event["eventId"])
        if identifier in identifiers:
            raise GovernanceError(f"duplicate eventId at ledger line {line_number}")
        identifiers.add(identifier)
        if event.get("previousDigest") != previous:
            raise GovernanceError(f"ledger hash chain breaks at line {line_number}")
        claimed = event.get("digest")
        if not isinstance(claimed, str) or SHA256.fullmatch(claimed) is None:
            raise GovernanceError(f"ledger line {line_number} has no SHA-256 digest")
        unsigned = dict(event)
        unsigned.pop("digest")
        if digest(unsigned) != claimed:
            raise GovernanceError(f"ledger line {line_number} digest mismatch")
        occurred = parse_time(event["occurredAt"], "event occurredAt")
        if previous_time is not None and occurred < previous_time:
            raise GovernanceError(f"ledger time moves backwards at line {line_number}")
        previous_time = occurred
        previous = claimed
        events.append(event)
    if not events:
        raise GovernanceError("governance ledger must not be empty")
    return events


def global_paused(events: list[dict[str, object]]) -> bool:
    transition = next(
        (event for event in reversed(events) if event.get("kind") in {"GLOBAL_PAUSED", "GLOBAL_RESUMED"}),
        None,
    )
    if transition is None:
        raise GovernanceError("ledger has no explicit global pause/resume state")
    return transition.get("kind") == "GLOBAL_PAUSED"


def seal_event(raw: dict[str, object], previous_digest: str) -> dict[str, object]:
    if SHA256.fullmatch(previous_digest) is None:
        raise GovernanceError("previous event digest must be SHA-256")
    event = dict(raw)
    event.setdefault("schema", EVENT_SCHEMA)
    event.setdefault("eventId", str(uuid.uuid4()))
    event.setdefault("occurredAt", iso(utc_now()))
    event.setdefault("pr", None)
    event.setdefault("baseSha", None)
    event.setdefault("headSha", None)
    event["previousDigest"] = previous_digest
    event.pop("digest", None)
    validate_event(event)
    event["digest"] = digest(event)
    return event


def append_event(ledger: Path, source: Path) -> dict[str, object]:
    events = load_ledger(ledger)
    raw = read_json(source)
    if not isinstance(raw, dict):
        raise GovernanceError("event input must be an object")
    event = seal_event(raw, str(events[-1]["digest"]))
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    return event


def normalize_owned_paths(value: object) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
        raise GovernanceError("ownedPaths must be a non-empty string array")
    result: list[str] = []
    for raw in value:
        assert isinstance(raw, str)
        path = raw.strip().replace("\\", "/").rstrip("/")
        if not path or path.startswith("/") or path == "." or ".." in Path(path).parts or "*" in path:
            raise GovernanceError(f"owned path is not a normalized repository path: {raw!r}")
        result.append(path)
    if len(result) != len(set(result)):
        raise GovernanceError("ownedPaths contains duplicates")
    return sorted(result)


def path_is_owned(path: str, owned: Sequence[str]) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in owned)


def extract_admission(body: object) -> dict[str, object]:
    if not isinstance(body, str):
        raise GovernanceError("pull request body is missing")
    matches = ADMISSION_BLOCK.findall(body)
    if len(matches) != 1:
        raise GovernanceError("pull request must contain exactly one hartevo-governance JSON block")
    try:
        value = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise GovernanceError(f"hartevo-governance block is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise GovernanceError("hartevo-governance block must be an object")
    return value


def changed_paths(root: Path, base: str, head: str) -> list[str]:
    require_sha(base, "diff base")
    require_sha(head, "diff head")
    merge_base = git("merge-base", base, head, root=root)
    if merge_base != base:
        raise GovernanceError("PR head is not based on the exact event base")
    paths = sorted(line for line in git("diff", "--name-only", f"{base}..{head}", root=root).splitlines() if line)
    if not paths:
        raise GovernanceError("governed PR must change at least one path")
    return paths


def verify_admission_value(
    value: dict[str, object],
    *,
    changed: Sequence[str],
    paused: bool,
    policy: dict[str, object],
) -> dict[str, object]:
    admission = policy["admission"]
    assert isinstance(admission, dict)
    required = set(str(item) for item in admission["requiredFields"] if isinstance(item, str))
    require_exact_keys(value, required, "PR admission block")
    if value.get("schema") != ADMISSION_SCHEMA:
        raise GovernanceError("PR admission schema drift")
    change_class = value.get("changeClass")
    if not isinstance(change_class, str):
        raise GovernanceError("changeClass must be a string")
    mode = "paused" if paused else str(policy["admissionModeWhenUnpaused"])
    allowed_key = "pausedAllowedClasses" if paused else f"{mode}AllowedClasses"
    allowed = admission.get(allowed_key)
    if not isinstance(allowed, list) or change_class not in allowed:
        raise GovernanceError(f"changeClass {change_class!r} is not admitted while mode={mode}")
    issue = value.get("issue")
    if not isinstance(issue, int) or issue <= 0:
        raise GovernanceError("governed PR must bind one positive issue number")
    owner = value.get("owner")
    if not isinstance(owner, str) or not owner.strip() or "replace-" in owner:
        raise GovernanceError("governed PR must bind one accountable owner")
    rollback = value.get("rollback")
    if not isinstance(rollback, str) or len(rollback.strip()) < 12 or "replace-" in rollback:
        raise GovernanceError("rollback must be a concrete recovery statement")
    if value.get("externalEffects") is not False or value.get("release") is not False:
        raise GovernanceError("ordinary governed PRs may not claim external effects or Release")
    owned = normalize_owned_paths(value.get("ownedPaths"))
    outside = sorted(path for path in changed if not path_is_owned(path, owned))
    if outside:
        raise GovernanceError(f"changed paths fall outside the declared path lease: {outside}")
    return {
        "schema": "hartevo-pr-admission-verification/v1",
        "status": "PASS",
        "mode": mode.upper(),
        "changeClass": change_class,
        "issue": issue,
        "owner": owner,
        "ownedPaths": owned,
        "exactChangedPaths": list(changed),
        "pathDigest": digest(list(changed)),
        "externalEffects": False,
        "release": False,
    }


def verify_pr_event(
    root: Path,
    event_path: Path,
    event_name: str,
    *,
    trusted_base: bool = False,
) -> dict[str, object]:
    if event_name == "merge_group":
        return {"schema": "hartevo-pr-admission-verification/v1", "status": "PASS", "mode": "MERGE_GROUP"}
    if event_name != "pull_request":
        raise GovernanceError(f"unsupported admission event: {event_name}")
    event = read_json(event_path)
    if not isinstance(event, dict) or not isinstance(event.get("pull_request"), dict):
        raise GovernanceError("pull_request event payload is missing")
    pr = event["pull_request"]
    assert isinstance(pr, dict)
    number = pr.get("number")
    base = pr.get("base")
    head = pr.get("head")
    if not isinstance(number, int) or number <= 0 or not isinstance(base, dict) or not isinstance(head, dict):
        raise GovernanceError("pull_request event tuple is invalid")
    if base.get("ref") != BASE_BRANCH:
        raise GovernanceError("governance drain accepts root bootstrap pull requests only")
    base_sha = require_sha(base.get("sha"), "event base SHA")
    head_sha = require_sha(head.get("sha"), "event head SHA")
    head_ref = head.get("ref")
    if not isinstance(head_ref, str) or not head_ref:
        raise GovernanceError("event head ref is missing")
    current = git("rev-parse", "HEAD", root=root)
    if trusted_base:
        if current != base_sha:
            raise GovernanceError("trusted admission workflow is not checked out at the exact event base")
        if run(
            ("git", "-C", str(root), "cat-file", "-e", f"{head_sha}^{{commit}}"),
            check=False,
        ).returncode != 0:
            raise GovernanceError("trusted admission workflow has not fetched the exact event head")
    elif current != head_sha and git("rev-parse", "HEAD^2", root=root, check=False) != head_sha:
        raise GovernanceError("checked-out source does not contain the exact event head")
    policy = load_policy(root / POLICY_PATH)
    verify_policy_value(policy)
    events = load_ledger(root / LEDGER_PATH)
    paused = global_paused(events)
    exact = changed_paths(root, base_sha, head_sha)
    admission = extract_admission(pr.get("body"))
    result = verify_admission_value(admission, changed=exact, paused=paused, policy=policy)
    result.update({"pr": number, "baseSha": base_sha, "headSha": head_sha, "headBranch": head_ref})
    return result


def review_path(number: int) -> Path:
    if number <= 0:
        raise GovernanceError("review PR number must be positive")
    return REVIEW_DIRECTORY / f"pr-{number}.json"


def validate_review_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GovernanceError("review receipt must be an object")
    if value.get("schema") != REVIEW_SCHEMA or value.get("repository") != REPOSITORY:
        raise GovernanceError("review receipt schema or repository drift")
    number = value.get("pr")
    if not isinstance(number, int) or number <= 0:
        raise GovernanceError("review receipt PR must be positive")
    require_sha(value.get("baseSha"), "review baseSha")
    require_sha(value.get("reviewedHeadSha"), "review reviewedHeadSha")
    author = value.get("authorTaskId")
    reviewer = value.get("reviewerTaskId")
    if not isinstance(author, str) or not author or not isinstance(reviewer, str) or not reviewer or author == reviewer:
        raise GovernanceError("review receipt must bind distinct author and reviewer task IDs")
    if value.get("disposition") != "APPROVE" or value.get("syntheticPreflightGreen") is not True:
        raise GovernanceError("only independently green APPROVE receipts are trainable")
    parse_time(value.get("reviewedAt"), "reviewedAt")
    exact_paths = value.get("exactPaths")
    if not isinstance(exact_paths, list) or not exact_paths or not all(isinstance(path, str) and path for path in exact_paths):
        raise GovernanceError("review receipt exactPaths must be non-empty")
    if exact_paths != sorted(set(exact_paths)):
        raise GovernanceError("review receipt exactPaths must be sorted and unique")
    claimed = value.get("receiptDigest")
    if not isinstance(claimed, str) or SHA256.fullmatch(claimed) is None:
        raise GovernanceError("review receipt digest is missing")
    unsigned = dict(value)
    unsigned.pop("receiptDigest")
    if digest(unsigned) != claimed:
        raise GovernanceError("review receipt digest mismatch")
    return value


def create_review_receipt(
    root: Path,
    number: int,
    base: str,
    reviewed_head: str,
    author_task: str,
    reviewer_task: str,
    output: Path,
) -> dict[str, object]:
    expected = review_path(number)
    try:
        relative = output.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise GovernanceError("review receipt output must be inside the repository") from error
    if relative != expected:
        raise GovernanceError(f"review receipt must use {expected}")
    if git("rev-parse", "HEAD", root=root) != reviewed_head:
        raise GovernanceError("review receipt must be created from the exact detached reviewed head")
    paths = changed_paths(root, base, reviewed_head)
    value: dict[str, object] = {
        "schema": REVIEW_SCHEMA,
        "repository": REPOSITORY,
        "pr": number,
        "baseSha": require_sha(base, "review base"),
        "reviewedHeadSha": require_sha(reviewed_head, "reviewed head"),
        "authorTaskId": author_task,
        "reviewerTaskId": reviewer_task,
        "disposition": "APPROVE",
        "syntheticPreflightGreen": True,
        "reviewedAt": iso(utc_now()),
        "exactPaths": paths,
    }
    value["receiptDigest"] = digest(value)
    validate_review_value(value)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def git_show_json(root: Path, commit: str, path: Path) -> object:
    raw = git("show", f"{commit}:{path.as_posix()}", root=root)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise GovernanceError(f"{path} at {commit} is invalid JSON") from error


def verify_review_commit(root: Path, number: int, base: str, head: str) -> dict[str, object]:
    base = require_sha(base, "review commit base")
    head = require_sha(head, "review commit head")
    path = review_path(number)
    value = validate_review_value(git_show_json(root, head, path))
    if value.get("pr") != number or value.get("baseSha") != base:
        raise GovernanceError("review receipt PR/base tuple mismatch")
    parents = git("rev-list", "--parents", "-n", "1", head, root=root).split()
    if len(parents) != 2:
        raise GovernanceError("review receipt head must be a single-parent receipt-only commit")
    reviewed_head = str(value["reviewedHeadSha"])
    if parents[1] != reviewed_head:
        raise GovernanceError("review receipt commit parent is not the reviewed head")
    receipt_delta = sorted(line for line in git("diff", "--name-only", f"{reviewed_head}..{head}", root=root).splitlines() if line)
    if receipt_delta != [path.as_posix()]:
        raise GovernanceError(f"review receipt commit changed paths outside {path}: {receipt_delta}")
    expected_paths = changed_paths(root, base, reviewed_head)
    if value.get("exactPaths") != expected_paths:
        raise GovernanceError("review receipt exact path envelope drifted")
    return {
        "schema": REVIEW_SCHEMA,
        "status": "PASS",
        "pr": number,
        "baseSha": base,
        "headSha": head,
        "reviewedHeadSha": reviewed_head,
        "receiptPath": path.as_posix(),
        "receiptDigest": value["receiptDigest"],
        "reviewerTaskId": value["reviewerTaskId"],
        "authorTaskId": value["authorTaskId"],
        "exactPaths": expected_paths,
    }


def protected_head(repo: str) -> str:
    raw = run(("git", "ls-remote", f"https://github.com/{repo}.git", f"refs/heads/{BASE_BRANCH}")).stdout.split()
    if len(raw) != 2:
        raise GovernanceError("protected branch did not resolve exactly once")
    return require_sha(raw[0], "protected head")


def pull_request_ready_at(repo: str, number: int) -> str:
    owner, name = repo.split("/", 1)
    query = (
        "query($owner:String!,$name:String!,$number:Int!){"
        "repository(owner:$owner,name:$name){pullRequest(number:$number){"
        "createdAt timelineItems(last:1,itemTypes:[READY_FOR_REVIEW_EVENT]){"
        "nodes{... on ReadyForReviewEvent{createdAt}}}}}}"
    )
    value = gh_json(
        "api",
        "graphql",
        "-f",
        f"owner={owner}",
        "-f",
        f"name={name}",
        "-F",
        f"number={number}",
        "-f",
        f"query={query}",
    )
    try:
        pull = value["data"]["repository"]["pullRequest"]
        nodes = pull["timelineItems"]["nodes"]
        ready_at = nodes[-1]["createdAt"] if nodes else pull["createdAt"]
    except (KeyError, IndexError, TypeError) as error:
        raise GovernanceError(f"PR #{number} ready transition is unavailable") from error
    parse_time(ready_at, f"PR #{number} readyAt")
    return str(ready_at)


def candidate_required_checks(root: Path = Path(".")) -> tuple[str, ...]:
    policy = read_json(root / Path(".github/policies/branch-ruleset-policy.json"))
    if not isinstance(policy, dict) or not isinstance(policy.get("branches"), list):
        raise GovernanceError("branch required-check policy is missing")
    bootstrap = next(
        (
            item
            for item in policy["branches"]
            if isinstance(item, dict) and item.get("name") == BASE_BRANCH
        ),
        None,
    )
    checks = bootstrap.get("requiredStatusChecks") if isinstance(bootstrap, dict) else None
    if not isinstance(checks, list) or not all(isinstance(item, str) for item in checks):
        raise GovernanceError("bootstrap required-check policy is invalid")
    train_only = "Governance / Train-only merge"
    result = tuple(check for check in checks if check != train_only)
    if train_only not in checks or not result:
        raise GovernanceError("candidate policy must exclude exactly the train-only merge check")
    return result


def exact_train_readiness(repo: str, number: int, base: str, head: str) -> dict[str, object]:
    reasons: list[str] = []
    fetch = run(
        (
            "git",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            f"https://github.com/{repo}.git",
            f"refs/pull/{number}/head",
        ),
        check=False,
    )
    if fetch.returncode != 0 or run(("git", "cat-file", "-e", f"{head}^{{commit}}"), check=False).returncode != 0:
        reasons.append("EXACT_HEAD_FETCH_FAILED")
    else:
        try:
            verify_review_commit(Path("."), number, base, head)
        except GovernanceError:
            reasons.append("EXACT_REVIEW_RECEIPT_NOT_VALID")
    try:
        metadata = gh_json(
            "pr",
            "view",
            str(number),
            "--repo",
            repo,
            "--json",
            "number,state,isDraft,baseRefName,baseRefOid,headRefOid,statusCheckRollup",
        )
        if not isinstance(metadata, dict):
            raise GovernanceError("pull request readiness metadata is invalid")
        if (
            metadata.get("state") != "OPEN"
            or metadata.get("isDraft") is not False
            or metadata.get("baseRefName") != BASE_BRANCH
            or metadata.get("baseRefOid") != base
            or metadata.get("headRefOid") != head
        ):
            reasons.append("EXACT_PR_TUPLE_NOT_READY")
        rollup = metadata.get("statusCheckRollup")
        if not isinstance(rollup, list):
            reasons.append("REQUIRED_CHECK_ROLLUP_UNAVAILABLE")
        else:
            expected = set(candidate_required_checks())
            observed: dict[str, list[dict[str, object]]] = {name: [] for name in expected}
            for item in rollup:
                if isinstance(item, dict) and item.get("name") in expected:
                    observed[str(item["name"])].append(item)
            missing = sorted(name for name, items in observed.items() if not items)
            non_success = sorted(
                name
                for name, items in observed.items()
                if items
                and any(
                    item.get("status") != "COMPLETED" or item.get("conclusion") != "SUCCESS"
                    for item in items
                )
            )
            if missing:
                reasons.append("REQUIRED_CHECKS_MISSING:" + ",".join(missing))
            if non_success:
                reasons.append("REQUIRED_CHECKS_NOT_SUCCESS:" + ",".join(non_success))
    except GovernanceError:
        reasons.append("REQUIRED_CHECK_PROBE_FAILED")
    return {
        "trainReady": not reasons,
        "readinessReasons": sorted(set(reasons)),
    }


def live_snapshot(repo: str, observed_at: dt.datetime) -> dict[str, object]:
    if repo != REPOSITORY:
        raise GovernanceError("governance snapshot is repository-bound")
    base = protected_head(repo)
    pulls = gh_pages(f"repos/{repo}/pulls?state=open&per_page=100")
    issues = [item for item in gh_pages(f"repos/{repo}/issues?state=open&per_page=100") if "pull_request" not in item]
    branches = gh_pages(f"repos/{repo}/branches?per_page=100")
    repository, repository_settings_source = hosted_repository(repo)
    rulesets = gh_json("api", f"repos/{repo}/rulesets?per_page=100")
    if not isinstance(rulesets, list):
        raise GovernanceError("live ruleset response is invalid")
    records: list[dict[str, object]] = []
    open_heads: set[str] = set()
    for item in pulls:
        base_value = item.get("base")
        head_value = item.get("head")
        number = item.get("number")
        if not isinstance(base_value, dict) or not isinstance(head_value, dict) or not isinstance(number, int):
            raise GovernanceError("open pull request list contains an invalid tuple")
        head_branch = head_value.get("ref")
        if isinstance(head_branch, str):
            open_heads.add(head_branch)
        record: dict[str, object] = {
                "number": number,
                "draft": item.get("draft") is True,
                "baseBranch": base_value.get("ref"),
                "baseSha": require_sha(base_value.get("sha"), f"PR #{number} base"),
                "headBranch": head_branch,
                "headSha": require_sha(head_value.get("sha"), f"PR #{number} head"),
                "createdAt": item.get("created_at"),
                "updatedAt": item.get("updated_at"),
                "readyAt": None,
                "trainReady": False,
                "readinessReasons": ["DRAFT" if item.get("draft") is True else "STALE_OR_NON_ROOT_BASE"],
            }
        if item.get("draft") is not True and base_value.get("ref") == BASE_BRANCH and base_value.get("sha") == base:
            try:
                record["readyAt"] = pull_request_ready_at(repo, number)
                record.update(exact_train_readiness(repo, number, base, str(record["headSha"])))
            except GovernanceError as error:
                record["readinessReasons"] = [f"READINESS_PROBE_FAILED:{error}"]
        records.append(record)
    branch_records: list[dict[str, object]] = []
    for item in branches:
        name = item.get("name")
        commit = item.get("commit")
        if not isinstance(name, str) or not isinstance(commit, dict):
            raise GovernanceError("branch list contains an invalid record")
        branch_records.append(
            {
                "name": name,
                "headSha": require_sha(commit.get("sha"), f"branch {name} head"),
                "protected": item.get("protected") is True,
                "hasOpenPullRequest": name in open_heads,
            }
        )
    issue_records = [
        {
            "number": item.get("number"),
            "createdAt": item.get("created_at"),
            "updatedAt": item.get("updated_at"),
            "title": item.get("title"),
        }
        for item in issues
        if isinstance(item.get("number"), int)
    ]
    open_trains = [record for record in records if isinstance(record["headBranch"], str) and str(record["headBranch"]).startswith(TRAIN_PREFIX)]
    orphan_branches = [
        record
        for record in branch_records
        if record["name"] not in {BASE_BRANCH, "main"}
        and not record["hasOpenPullRequest"]
        and not str(record["name"]).startswith(TRAIN_PREFIX)
    ]
    settings = {
        "defaultBranch": repository.get("default_branch"),
        "deleteBranchOnMerge": repository.get("delete_branch_on_merge"),
        "allowUpdateBranch": repository.get("allow_update_branch"),
        "allowMergeCommit": repository.get("allow_merge_commit"),
        "allowSquashMerge": repository.get("allow_squash_merge"),
        "allowRebaseMerge": repository.get("allow_rebase_merge"),
        "allowAutoMerge": repository.get("allow_auto_merge"),
    }
    train_ready = [record for record in records if record.get("trainReady") is True]
    ready_ages = [
        max(0, int((observed_at - parse_time(record.get("readyAt"), f"PR #{record.get('number')} readyAt")).total_seconds()))
        for record in train_ready
    ]
    return {
        "schema": SNAPSHOT_SCHEMA,
        "repository": repo,
        "observedAt": iso(observed_at),
        "protected": {"branch": BASE_BRANCH, "sha": base},
        "inventory": {
            "openPullRequests": len(records),
            "draftPullRequests": sum(1 for record in records if record["draft"]),
            "nonDraftPullRequests": sum(1 for record in records if not record["draft"]),
            "exactBaseDraftPullRequests": sum(1 for record in records if record["draft"] and record["baseBranch"] == BASE_BRANCH and record["baseSha"] == base),
            "exactBaseNonDraftPullRequests": sum(1 for record in records if not record["draft"] and record["baseBranch"] == BASE_BRANCH and record["baseSha"] == base),
            "staleRootPullRequests": sum(1 for record in records if record["baseBranch"] == BASE_BRANCH and record["baseSha"] != base),
            "openIssues": len(issue_records),
            "branches": len(branch_records),
            "orphanBranches": len(orphan_branches),
            "openTrains": len(open_trains),
            "trainReadyPullRequests": len(train_ready),
            "oldestTrainReadySeconds": max(ready_ages) if ready_ages else None,
        },
        "pullRequests": records,
        "issues": issue_records,
        "branches": branch_records,
        "orphanBranches": orphan_branches,
        "openTrains": open_trains,
        "repositorySettings": settings,
        "repositorySettingsSource": repository_settings_source,
        "rulesets": [
            {"id": item.get("id"), "name": item.get("name"), "enforcement": item.get("enforcement")}
            for item in rulesets
            if isinstance(item, dict)
        ],
    }


def action(kind: str, priority: int, **payload: object) -> dict[str, object]:
    unsigned = {"kind": kind, "priority": priority, **payload}
    return {**unsigned, "actionId": digest(unsigned)}


def age_days(timestamp: object, now: dt.datetime) -> int:
    return max(0, int((now - parse_time(timestamp, "inventory timestamp")).total_seconds() // 86400))


def build_plan(snapshot: object, events: list[dict[str, object]], policy: dict[str, object], now: dt.datetime) -> dict[str, object]:
    if not isinstance(snapshot, dict) or snapshot.get("schema") != SNAPSHOT_SCHEMA or snapshot.get("repository") != REPOSITORY:
        raise GovernanceError("snapshot contract drift")
    protected = snapshot.get("protected")
    if not isinstance(protected, dict) or protected.get("branch") != BASE_BRANCH:
        raise GovernanceError("snapshot protected tuple drift")
    base = require_sha(protected.get("sha"), "snapshot protected base")
    paused = global_paused(events)
    lifecycle = policy["lifecycle"]
    settings_policy = policy["repositorySettings"]
    assert isinstance(lifecycle, dict) and isinstance(settings_policy, dict)
    incidents: list[dict[str, object]] = []
    settings = snapshot.get("repositorySettings")
    if not isinstance(settings, dict):
        raise GovernanceError("snapshot repository settings are missing")
    for key in (
        "defaultBranch",
        "deleteBranchOnMerge",
        "allowUpdateBranch",
        "allowMergeCommit",
        "allowSquashMerge",
        "allowRebaseMerge",
        "allowAutoMerge",
    ):
        if settings.get(key) != settings_policy.get(key):
            incidents.append({"code": "REPOSITORY_SETTING_DRIFT", "setting": key, "expected": settings_policy.get(key), "observed": settings.get(key)})
    trains = snapshot.get("openTrains")
    if not isinstance(trains, list):
        raise GovernanceError("snapshot train list is invalid")
    if len(trains) > 1:
        incidents.append({"code": "MULTIPLE_OPEN_TRAINS", "count": len(trains)})
    pulls = snapshot.get("pullRequests")
    issues = snapshot.get("issues")
    orphan_branches = snapshot.get("orphanBranches")
    if not isinstance(pulls, list) or not isinstance(issues, list) or not isinstance(orphan_branches, list):
        raise GovernanceError("snapshot inventory lists are invalid")
    inventory = snapshot.get("inventory")
    if not isinstance(inventory, dict):
        raise GovernanceError("snapshot inventory summary is missing")
    ready_count = inventory.get("trainReadyPullRequests")
    oldest_ready = inventory.get("oldestTrainReadySeconds")
    if not isinstance(ready_count, int) or ready_count < 0:
        raise GovernanceError("snapshot train-ready count is invalid")
    if oldest_ready is not None and (not isinstance(oldest_ready, int) or oldest_ready < 0):
        raise GovernanceError("snapshot oldest train-ready age is invalid")
    if ready_count and paused:
        incidents.append(
            {
                "code": "TRAIN_READY_DEFERRED_BY_GLOBAL_PAUSE",
                "readyCount": ready_count,
                "oldestReadySeconds": oldest_ready,
            }
        )
    elif (
        ready_count
        and len(trains) == 0
        and isinstance(oldest_ready, int)
        and oldest_ready > int(policy["integration"]["readyToTrainSlaSeconds"])
    ):
        incidents.append(
            {
                "code": "READY_TO_TRAIN_SLA_BREACH",
                "readyCount": ready_count,
                "oldestReadySeconds": oldest_ready,
                "slaSeconds": int(policy["integration"]["readyToTrainSlaSeconds"]),
            }
        )
    deferred: list[dict[str, object]] = []
    for pr in pulls:
        if not isinstance(pr, dict):
            continue
        number = pr.get("number")
        if not isinstance(number, int):
            continue
        if pr.get("baseBranch") == BASE_BRANCH and pr.get("baseSha") != base:
            deferred.append(action("BASE_REFRESH", 1 if pr.get("draft") is False else 2, pr=number, expectedHead=pr.get("headSha"), expectedBase=pr.get("baseSha"), destructive=False))
        elif pr.get("draft") is True and age_days(pr.get("updatedAt"), now) >= int(lifecycle["draftReviewAgeDays"]):
            deferred.append(action("REVIEW_STALE_DRAFT", 4, pr=number, expectedHead=pr.get("headSha"), ageDays=age_days(pr.get("updatedAt"), now), destructive=False))
    for issue in issues:
        if not isinstance(issue, dict) or not isinstance(issue.get("number"), int):
            continue
        days = age_days(issue.get("updatedAt"), now)
        if days >= int(lifecycle["staleIssueDays"]):
            deferred.append(action("REVIEW_STALE_ISSUE", 5, issue=issue["number"], ageDays=days, destructive=False))
    for branch in orphan_branches:
        if not isinstance(branch, dict) or not isinstance(branch.get("name"), str):
            continue
        deferred.append(action("REVIEW_ORPHAN_BRANCH", 6, branch=branch["name"], expectedHead=branch.get("headSha"), destructive=False))
    deferred.sort(key=lambda item: (int(item["priority"]), int(item.get("pr", item.get("issue", 0))), str(item.get("branch", ""))))
    actions = [] if paused else deferred
    protected_advances = len(
        {
            str(event["headSha"])
            for event in events
            if event.get("kind") == "MERGED" and isinstance(event.get("headSha"), str)
        }
    )
    metrics = {
        "ready_count": ready_count,
        "oldest_ready_seconds": oldest_ready,
        "open_train_count": len(trains),
        "protected_base_advances": protected_advances,
        "stale_root_count": inventory.get("staleRootPullRequests"),
        "draft_count": inventory.get("draftPullRequests"),
        "orphan_branch_count": inventory.get("orphanBranches"),
    }
    body: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "repository": REPOSITORY,
        "plannedAt": iso(now),
        "snapshotObservedAt": snapshot.get("observedAt"),
        "protectedBase": base,
        "mode": "PAUSED" if paused else str(policy["admissionModeWhenUnpaused"]).upper(),
        "truth": {
            "inventory": inventory,
            "globalPaused": paused,
            "manualCountsAccepted": False,
            "source": "live-github+live-git+hash-ledger",
            "mergeThroughput": "PROTECTED_BASE_ADVANCES_ONLY",
            "metrics": metrics,
        },
        "actions": actions,
        "deferredActions": deferred if paused else [],
        "incidents": incidents,
        "destructiveExecution": "DISABLED_WITHOUT_EXACT_APPROVAL",
    }
    body["planDigest"] = digest(body)
    return body


def build_lifecycle_plan(
    snapshot: object,
    nominations: object,
    events: list[dict[str, object]],
    policy: dict[str, object],
    now: dt.datetime,
) -> dict[str, object]:
    if not isinstance(snapshot, dict) or snapshot.get("schema") != SNAPSHOT_SCHEMA or snapshot.get("repository") != REPOSITORY:
        raise GovernanceError("lifecycle snapshot contract drift")
    if not isinstance(nominations, dict) or nominations.get("schema") != NOMINATION_SCHEMA or nominations.get("repository") != REPOSITORY:
        raise GovernanceError("lifecycle nomination contract drift")
    requested_by = nominations.get("requestedBy")
    if not isinstance(requested_by, str) or not requested_by:
        raise GovernanceError("lifecycle nominations require one accountable requester")
    items = nominations.get("items")
    if not isinstance(items, list) or not items:
        raise GovernanceError("lifecycle nominations must contain at least one item")
    pulls = {item.get("number"): item for item in snapshot.get("pullRequests", []) if isinstance(item, dict)}
    issues = {item.get("number"): item for item in snapshot.get("issues", []) if isinstance(item, dict)}
    branches = {item.get("name"): item for item in snapshot.get("orphanBranches", []) if isinstance(item, dict)}
    actions: list[dict[str, object]] = []
    seen: set[tuple[str, object]] = set()
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    for item in items:
        if not isinstance(item, dict):
            raise GovernanceError("lifecycle nomination items must be objects")
        kind = item.get("kind")
        reason = item.get("reason")
        if kind not in {"CLOSE_PR", "CLOSE_ISSUE", "DELETE_BRANCH"}:
            raise GovernanceError(f"unsupported lifecycle nomination kind: {kind!r}")
        if not isinstance(reason, str) or len(reason.strip()) < 12:
            raise GovernanceError("every lifecycle nomination requires a concrete reason")
        if kind == "CLOSE_PR":
            target = item.get("pr")
            record = pulls.get(target)
            if not isinstance(target, int) or not isinstance(record, dict):
                raise GovernanceError(f"nominated PR #{target} is not in the exact open snapshot")
            key = (kind, target)
            payload = {
                "pr": target,
                "expectedHead": record.get("headSha"),
                "reason": reason.strip(),
                "recovery": "reopen-pull-request",
            }
        elif kind == "CLOSE_ISSUE":
            target = item.get("issue")
            record = issues.get(target)
            if not isinstance(target, int) or not isinstance(record, dict):
                raise GovernanceError(f"nominated issue #{target} is not in the exact open snapshot")
            key = (kind, target)
            payload = {
                "issue": target,
                "expectedUpdatedAt": record.get("updatedAt"),
                "reason": reason.strip(),
                "recovery": "reopen-issue",
            }
        else:
            target = item.get("branch")
            record = branches.get(target)
            if not isinstance(target, str) or not isinstance(record, dict):
                raise GovernanceError(f"nominated branch {target!r} is not an exact orphan in the snapshot")
            if target in {BASE_BRANCH, "main"} or target.startswith(TRAIN_PREFIX):
                raise GovernanceError("protected and merge-train branches cannot enter orphan deletion")
            key = (kind, target)
            safe = re.sub(r"[^A-Za-z0-9._-]+", "-", target).strip("-")
            payload = {
                "branch": target,
                "expectedHead": record.get("headSha"),
                "reason": reason.strip(),
                "recoveryRef": f"refs/tags/governance-recovery/{stamp}/{safe}",
            }
        if key in seen:
            raise GovernanceError(f"duplicate lifecycle nomination: {key}")
        seen.add(key)
        actions.append(action(str(kind), 1, destructive=True, **payload))
    paused = global_paused(events)
    body: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "repository": REPOSITORY,
        "plannedAt": iso(now),
        "snapshotObservedAt": snapshot.get("observedAt"),
        "snapshotDigest": digest(snapshot),
        "protectedBase": snapshot.get("protected", {}).get("sha") if isinstance(snapshot.get("protected"), dict) else None,
        "mode": "PAUSED" if paused else str(policy["admissionModeWhenUnpaused"]).upper(),
        "requestedBy": requested_by,
        "truth": {
            "globalPaused": paused,
            "manualCountsAccepted": False,
            "source": "exact-live-snapshot+explicit-nominations+hash-ledger",
        },
        "actions": [] if paused else actions,
        "deferredActions": actions if paused else [],
        "incidents": [],
        "destructiveExecution": "DISABLED_WITHOUT_EXACT_APPROVAL",
    }
    body["planDigest"] = digest(body)
    return body


def create_approval(plan: object, actor: str, output: Path, now: dt.datetime) -> dict[str, object]:
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise GovernanceError("approval input is not a governance plan")
    if plan.get("mode") == "PAUSED":
        raise GovernanceError("cannot approve lifecycle execution while globally paused")
    claimed = plan.get("planDigest")
    unsigned_plan = dict(plan)
    unsigned_plan.pop("planDigest", None)
    if not isinstance(claimed, str) or digest(unsigned_plan) != claimed:
        raise GovernanceError("plan digest mismatch")
    policy = load_policy()
    lifecycle = policy["lifecycle"]
    assert isinstance(lifecycle, dict)
    actions = plan.get("actions")
    if not isinstance(actions, list):
        raise GovernanceError("plan actions are missing")
    value: dict[str, object] = {
        "schema": APPROVAL_SCHEMA,
        "repository": REPOSITORY,
        "planDigest": claimed,
        "approvedActionIds": [item.get("actionId") for item in actions if isinstance(item, dict)],
        "approvedBy": actor,
        "approvedAt": iso(now),
        "expiresAt": iso(now + dt.timedelta(minutes=int(lifecycle["approvalMaximumAgeMinutes"]))),
        "confirmation": "EXECUTE_EXACT_LIFECYCLE_PLAN",
    }
    value["approvalDigest"] = digest(value)
    write_json(value, output)
    return value


def validate_approval(plan: dict[str, object], approval: object, now: dt.datetime) -> set[str]:
    if not isinstance(approval, dict) or approval.get("schema") != APPROVAL_SCHEMA or approval.get("repository") != REPOSITORY:
        raise GovernanceError("lifecycle approval contract drift")
    claimed = approval.get("approvalDigest")
    unsigned = dict(approval)
    unsigned.pop("approvalDigest", None)
    if not isinstance(claimed, str) or digest(unsigned) != claimed:
        raise GovernanceError("lifecycle approval digest mismatch")
    if approval.get("planDigest") != plan.get("planDigest"):
        raise GovernanceError("lifecycle approval is bound to another plan")
    if approval.get("confirmation") != "EXECUTE_EXACT_LIFECYCLE_PLAN":
        raise GovernanceError("lifecycle approval confirmation is missing")
    if parse_time(approval.get("expiresAt"), "approval expiry") <= now:
        raise GovernanceError("lifecycle approval expired")
    action_ids = approval.get("approvedActionIds")
    if not isinstance(action_ids, list) or not all(isinstance(item, str) and SHA256.fullmatch(item) for item in action_ids):
        raise GovernanceError("approved action IDs are invalid")
    return set(action_ids)


def execute_lifecycle(repo: str, plan_value: object, approval_value: object, action_id: str, now: dt.datetime, execute: bool) -> dict[str, object]:
    if repo != REPOSITORY:
        raise GovernanceError("lifecycle execution is repository-bound")
    if not isinstance(plan_value, dict) or plan_value.get("schema") != PLAN_SCHEMA:
        raise GovernanceError("lifecycle plan contract drift")
    if plan_value.get("mode") == "PAUSED":
        raise GovernanceError("lifecycle execution is forbidden while globally paused")
    approved = validate_approval(plan_value, approval_value, now)
    if action_id not in approved:
        raise GovernanceError("requested action is not approved")
    actions = plan_value.get("actions")
    action_value = next((item for item in actions if isinstance(item, dict) and item.get("actionId") == action_id), None) if isinstance(actions, list) else None
    if not isinstance(action_value, dict):
        raise GovernanceError("approved action is absent from the exact plan")
    kind = action_value.get("kind")
    if kind not in {"CLOSE_PR", "CLOSE_ISSUE", "DELETE_BRANCH"}:
        raise GovernanceError("only explicitly nominated lifecycle actions are executable")
    result = {"schema": "hartevo-lifecycle-execution/v1", "status": "DRY_RUN" if not execute else "APPLIED", "action": action_value}
    if not execute:
        return result
    if kind == "CLOSE_PR":
        number = action_value.get("pr")
        expected_head = require_sha(action_value.get("expectedHead"), "close PR expected head")
        current = gh_json("api", f"repos/{repo}/pulls/{number}")
        if not isinstance(current, dict) or current.get("state") != "open" or not isinstance(current.get("head"), dict) or current["head"].get("sha") != expected_head:
            raise GovernanceError("pull request changed before approved close")
        gh_json("api", f"repos/{repo}/pulls/{number}", "--method", "PATCH", input_value={"state": "closed"})
    elif kind == "CLOSE_ISSUE":
        number = action_value.get("issue")
        current = gh_json("api", f"repos/{repo}/issues/{number}")
        if (
            not isinstance(current, dict)
            or current.get("state") != "open"
            or "pull_request" in current
            or current.get("updated_at") != action_value.get("expectedUpdatedAt")
        ):
            raise GovernanceError("issue changed before approved close")
        gh_json("api", f"repos/{repo}/issues/{number}", "--method", "PATCH", input_value={"state": "closed"})
    else:
        branch = action_value.get("branch")
        expected_head = require_sha(action_value.get("expectedHead"), "delete branch expected head")
        recovery_ref = action_value.get("recoveryRef")
        if not isinstance(branch, str) or not branch or branch in {BASE_BRANCH, "main"} or branch.startswith(TRAIN_PREFIX):
            raise GovernanceError("approved branch deletion target is unsafe")
        if not isinstance(recovery_ref, str) or not recovery_ref.startswith("refs/tags/governance-recovery/"):
            raise GovernanceError("approved branch deletion has no safe recovery tag")
        encoded_branch = urllib.parse.quote(f"heads/{branch}", safe="")
        current = gh_json("api", f"repos/{repo}/git/ref/{encoded_branch}")
        current_object = current.get("object") if isinstance(current, dict) else None
        if not isinstance(current_object, dict) or current_object.get("sha") != expected_head:
            raise GovernanceError("branch changed before approved deletion")
        recovery_payload = {"ref": recovery_ref, "sha": expected_head}
        try:
            created = gh_json("api", f"repos/{repo}/git/refs", "--method", "POST", input_value=recovery_payload)
        except GovernanceError as error:
            encoded_recovery = urllib.parse.quote(recovery_ref.removeprefix("refs/"), safe="")
            existing = gh_json("api", f"repos/{repo}/git/ref/{encoded_recovery}")
            existing_object = existing.get("object") if isinstance(existing, dict) else None
            if not isinstance(existing_object, dict) or existing_object.get("sha") != expected_head:
                raise GovernanceError(f"failed to create exact recovery tag: {error}") from error
        else:
            created_object = created.get("object") if isinstance(created, dict) else None
            if not isinstance(created_object, dict) or created_object.get("sha") != expected_head:
                raise GovernanceError("created recovery tag does not bind the exact branch head")
        gh_json("api", f"repos/{repo}/git/refs/{encoded_branch}", "--method", "DELETE")
        result["recoveryRef"] = recovery_ref
    return result


def verify_repository(root: Path) -> dict[str, object]:
    policy = load_policy(root / POLICY_PATH)
    policy_result = verify_policy_value(policy)
    events = load_ledger(root / LEDGER_PATH)
    if (root / ".github/merge-train/current.json").exists():
        raise GovernanceError("stale merge-train current.json must not exist")
    if not (root / ".github/merge-train/README.md").is_file():
        raise GovernanceError("merge-train historical-manifest contract is missing")
    if not (root / "docs/operations/REPOSITORY-GOVERNANCE-CONTROL-PLANE.md").is_file():
        raise GovernanceError("repository governance operating runbook is missing")
    codeowners = (root / ".github/CODEOWNERS").read_text(encoding="utf-8")
    for required in ("/.github/governance/", "/.github/merge-train/", "/scripts/repository_governance.py"):
        if required not in codeowners:
            raise GovernanceError(f"CODEOWNERS is missing governance ownership for {required}")
    template = (root / ".github/pull_request_template.md").read_text(encoding="utf-8")
    if "hartevo-governance" not in template or ADMISSION_SCHEMA not in template:
        raise GovernanceError("pull request admission template is missing")
    return {
        "schema": "hartevo-repository-governance-verification/v1",
        "status": "PASS",
        "policy": policy_result,
        "ledgerEvents": len(events),
        "globalPaused": global_paused(events),
        "staleCurrentManifestAbsent": True,
    }


def self_test() -> None:
    policy = load_policy()
    verify_policy_value(policy)
    events = load_ledger()
    if global_paused(events) or events[-1].get("kind") != "GLOBAL_RESUMED":
        raise AssertionError("checked-in governance ledger must end in an explicit resume")
    if policy.get("admissionModeWhenUnpaused") != "normal":
        raise AssertionError("resumed governance policy must select normal admission")
    paused_events = events[:-1]
    if not paused_events or not global_paused(paused_events):
        raise AssertionError("resume must extend an explicit checked-in pause")
    admission = {
        "schema": ADMISSION_SCHEMA,
        "changeClass": "governance",
        "issue": 1,
        "owner": "root",
        "ownedPaths": [".github", "scripts/repository_governance.py"],
        "rollback": "Revert the exact governance commit and re-run the live probe.",
        "externalEffects": False,
        "release": False,
    }
    verify_admission_value(admission, changed=[".github/test.json", "scripts/repository_governance.py"], paused=True, policy=policy)
    bad_feature = dict(admission)
    bad_feature["changeClass"] = "feature"
    try:
        verify_admission_value(bad_feature, changed=[".github/test.json"], paused=True, policy=policy)
    except GovernanceError:
        pass
    else:
        raise AssertionError("paused admission accepted feature work")
    normal_feature = verify_admission_value(
        bad_feature,
        changed=[".github/test.json"],
        paused=False,
        policy=policy,
    )
    if normal_feature["mode"] != "NORMAL":
        raise AssertionError("resumed policy did not admit feature work in normal mode")
    bad_path = dict(admission)
    bad_path["ownedPaths"] = ["scripts"]
    try:
        verify_admission_value(bad_path, changed=[".github/test.json"], paused=True, policy=policy)
    except GovernanceError:
        pass
    else:
        raise AssertionError("admission accepted a path outside its lease")
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "repository": REPOSITORY,
        "observedAt": "2026-08-21T01:00:00Z",
        "protected": {"branch": BASE_BRANCH, "sha": "a" * 40},
        "inventory": {
            "openPullRequests": 1,
            "draftPullRequests": 1,
            "openIssues": 1,
            "branches": 2,
            "orphanBranches": 1,
            "openTrains": 0,
            "trainReadyPullRequests": 0,
            "oldestTrainReadySeconds": None,
        },
        "pullRequests": [{"number": 9, "draft": True, "baseBranch": BASE_BRANCH, "baseSha": "b" * 40, "headSha": "c" * 40, "updatedAt": "2026-07-01T00:00:00Z"}],
        "issues": [{"number": 8, "updatedAt": "2026-01-01T00:00:00Z"}],
        "orphanBranches": [{"name": "codex/orphan", "headSha": "d" * 40}],
        "openTrains": [],
        "repositorySettings": {
            "defaultBranch": BASE_BRANCH,
            "deleteBranchOnMerge": False,
            "allowUpdateBranch": False,
            "allowMergeCommit": True,
            "allowSquashMerge": True,
            "allowRebaseMerge": True,
            "allowAutoMerge": False,
        },
    }
    paused_plan = build_plan(
        snapshot,
        paused_events,
        policy,
        dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
    )
    if paused_plan["mode"] != "PAUSED" or paused_plan["actions"] != [] or not paused_plan["deferredActions"]:
        raise AssertionError("global pause did not suppress execution while preserving deferred work")
    resumed_plan = build_plan(snapshot, events, policy, dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc))
    if resumed_plan["mode"] != "NORMAL" or resumed_plan["truth"]["globalPaused"] is not False:
        raise AssertionError("global resume did not restore normal governed execution")
    tampered = dict(events[0])
    tampered["payload"] = {"reason": "forged"}
    unsigned = dict(tampered)
    unsigned.pop("digest")
    if digest(unsigned) == tampered["digest"]:
        raise AssertionError("ledger tamper self-test is ineffective")
    print(json.dumps({"schema": "hartevo-repository-governance-self-test/v1", "status": "PASS"}, sort_keys=True))


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-policy")
    subparsers.add_parser("verify-repository")
    subparsers.add_parser("verify-ledger")
    subparsers.add_parser("self-test")

    admission_parser = subparsers.add_parser("verify-pr-event")
    admission_parser.add_argument("--event", type=Path, required=True)
    admission_parser.add_argument("--event-name", required=True)
    admission_parser.add_argument("--root", type=Path, default=Path("."))
    admission_parser.add_argument("--trusted-base", action="store_true")

    append_parser = subparsers.add_parser("append-event")
    append_parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    append_parser.add_argument("--event", type=Path, required=True)

    create_review = subparsers.add_parser("create-review-receipt")
    create_review.add_argument("--root", type=Path, default=Path("."))
    create_review.add_argument("--pr", type=int, required=True)
    create_review.add_argument("--base", required=True)
    create_review.add_argument("--reviewed-head", required=True)
    create_review.add_argument("--author-task", required=True)
    create_review.add_argument("--reviewer-task", required=True)
    create_review.add_argument("--output", type=Path, required=True)

    verify_review = subparsers.add_parser("verify-review-receipt")
    verify_review.add_argument("--root", type=Path, default=Path("."))
    verify_review.add_argument("--pr", type=int, required=True)
    verify_review.add_argument("--base", required=True)
    verify_review.add_argument("--head", required=True)

    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--repo", default=REPOSITORY)
    snapshot_parser.add_argument("--output", type=Path, required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--snapshot", type=Path, required=True)
    plan_parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    plan_parser.add_argument("--output", type=Path, required=True)
    plan_parser.add_argument("--now")

    lifecycle_plan_parser = subparsers.add_parser("lifecycle-plan")
    lifecycle_plan_parser.add_argument("--snapshot", type=Path, required=True)
    lifecycle_plan_parser.add_argument("--nominations", type=Path, required=True)
    lifecycle_plan_parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    lifecycle_plan_parser.add_argument("--output", type=Path, required=True)
    lifecycle_plan_parser.add_argument("--now")

    approval_parser = subparsers.add_parser("approve-plan")
    approval_parser.add_argument("--plan", type=Path, required=True)
    approval_parser.add_argument("--actor", required=True)
    approval_parser.add_argument("--output", type=Path, required=True)

    execute_parser = subparsers.add_parser("execute-lifecycle")
    execute_parser.add_argument("--repo", default=REPOSITORY)
    execute_parser.add_argument("--plan", type=Path, required=True)
    execute_parser.add_argument("--approval", type=Path, required=True)
    execute_parser.add_argument("--action-id", required=True)
    execute_parser.add_argument("--execute", action="store_true")

    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify-policy":
            write_json(verify_policy(), None)
        elif args.command == "verify-repository":
            write_json(verify_repository(Path(".")), None)
        elif args.command == "verify-ledger":
            events = load_ledger()
            write_json({"schema": "hartevo-governance-ledger-verification/v1", "status": "PASS", "eventCount": len(events), "headDigest": events[-1]["digest"], "globalPaused": global_paused(events)}, None)
        elif args.command == "self-test":
            self_test()
        elif args.command == "verify-pr-event":
            write_json(
                verify_pr_event(
                    args.root.resolve(),
                    args.event.resolve(),
                    args.event_name,
                    trusted_base=args.trusted_base,
                ),
                None,
            )
        elif args.command == "append-event":
            write_json(append_event(args.ledger, args.event), None)
        elif args.command == "create-review-receipt":
            write_json(create_review_receipt(args.root.resolve(), args.pr, args.base, args.reviewed_head, args.author_task, args.reviewer_task, args.output.resolve()), None)
        elif args.command == "verify-review-receipt":
            write_json(verify_review_commit(args.root.resolve(), args.pr, args.base, args.head), None)
        elif args.command == "snapshot":
            write_json(live_snapshot(args.repo, utc_now()), args.output)
        elif args.command == "plan":
            now = parse_time(args.now, "--now") if args.now else utc_now()
            write_json(build_plan(read_json(args.snapshot), load_ledger(args.ledger), load_policy(), now), args.output)
        elif args.command == "lifecycle-plan":
            now = parse_time(args.now, "--now") if args.now else utc_now()
            write_json(
                build_lifecycle_plan(
                    read_json(args.snapshot),
                    read_json(args.nominations),
                    load_ledger(args.ledger),
                    load_policy(),
                    now,
                ),
                args.output,
            )
        elif args.command == "approve-plan":
            create_approval(read_json(args.plan), args.actor, args.output, utc_now())
        elif args.command == "execute-lifecycle":
            write_json(execute_lifecycle(args.repo, read_json(args.plan), read_json(args.approval), args.action_id, utc_now(), args.execute), None)
        else:
            raise AssertionError("unreachable command")
        return 0
    except (GovernanceError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": "hartevo-repository-governance-error/v1", "status": "BLOCKED", "message": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
