#!/usr/bin/env python3
"""Verify, apply, and probe the checked-in GitHub branch/ruleset policy.

The JSON document is both the reviewable desired state and the input to the
idempotent ``apply`` command. ``verify`` validates the document locally;
``probe`` validates the live public-repository ruleset without treating a
successful API call as proof that the desired rules were installed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable


POLICY = Path(".github/policies/branch-ruleset-policy.json")
REQUIRED_BRANCHES = {"main", "bootstrap/macos-r0"}
UNAPPLIED = "desired_active_not_yet_applied"
ACTIVE = "active"
BLOCKED_OWNER = "blocked_owner_type"
DEFAULT_BRANCH = "bootstrap/macos-r0"
RULESET_NAME = "Hartevo protected integration branches"
MERGE_QUEUE_RULESET_NAME = "Hartevo bootstrap merge queue"
MERGE_TRAIN_BRANCH_PREFIX = "merge-train/"
MERGE_TRAIN_MANIFEST_DIRECTORY = ".github/merge-train/manifests"
TRUSTED_ADMISSION_WORKFLOW = Path(".github/workflows/governance-admission.yml")
GITHUB_ACTIONS_INTEGRATION_ID = 15368
EXPECTED_STATUS_CHECKS = (
    "PR / Workflow policy",
    "Governance / PR admission",
    "Governance / Train-only merge",
    "PR / Scope plan",
    "PR / Fast Rust matrix / PR / Fast Rust / fmt",
    "PR / Fast Rust matrix / PR / Fast Rust / clippy (ubuntu-24.04)",
    "PR / Fast Rust matrix / PR / Fast Rust / clippy (macos-15)",
    "PR / Fast Rust matrix / PR / Fast Rust / test (ubuntu-24.04)",
    "PR / Fast Rust matrix / PR / Fast Rust / test (macos-15)",
    "PR / Result taxonomy",
)


def load(path: Path = POLICY) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("branch policy must be a JSON object")
    return value


def branch_entries(policy: dict[str, object]) -> list[dict[str, object]]:
    branches = policy.get("branches")
    if not isinstance(branches, list) or {item.get("name") for item in branches if isinstance(item, dict)} != REQUIRED_BRANCHES:
        raise ValueError("policy must cover exactly main and bootstrap/macos-r0")
    if not all(isinstance(branch, dict) for branch in branches):
        raise ValueError("branch entries must be objects")
    return [branch for branch in branches if isinstance(branch, dict)]


def required_status_checks(policy: dict[str, object]) -> list[str]:
    branches = branch_entries(policy)
    checks_by_branch: list[list[str]] = []
    for branch in branches:
        checks = branch.get("requiredStatusChecks")
        if not isinstance(checks, list) or not all(isinstance(check, str) for check in checks):
            raise ValueError(f"required checks for {branch.get('name')} must be strings")
        checks_by_branch.append(checks)
    if any(checks != checks_by_branch[0] for checks in checks_by_branch[1:]):
        raise ValueError("protected branches must require the same PR checks")
    if tuple(checks_by_branch[0]) != EXPECTED_STATUS_CHECKS:
        raise ValueError("required PR check names do not match the stable workflow check contract")
    return checks_by_branch[0]


def desired_ruleset(policy: dict[str, object]) -> dict[str, object]:
    checks = required_status_checks(policy)
    branches = sorted(branch.get("name") for branch in branch_entries(policy) if isinstance(branch.get("name"), str))
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": [f"refs/heads/{branch}" for branch in branches],
                "exclude": [],
            }
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "dismiss_stale_reviews_on_push": False,
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_approving_review_count": 0,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": check, "integration_id": GITHUB_ACTIONS_INTEGRATION_ID} for check in checks
                    ],
                },
            },
        ],
        "bypass_actors": [],
    }


def desired_merge_queue_ruleset(policy: dict[str, object]) -> dict[str, object]:
    merge_queue = policy.get("mergeQueue")
    if not isinstance(merge_queue, dict):
        raise ValueError("merge queue policy is missing")
    expected = {
        "buildConcurrency": 4,
        "minimumGroupSize": 1,
        "maximumGroupSize": 4,
        "minimumGroupWaitMinutes": 5,
        "requiredCheckTimeoutMinutes": 120,
        "groupingStrategy": "HEADGREEN",
        "mergeMethod": "MERGE",
    }
    if any(merge_queue.get(key) != value for key, value in expected.items()):
        raise ValueError("merge queue throughput settings drifted")
    return {
        "name": MERGE_QUEUE_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": ["refs/heads/bootstrap/macos-r0"],
                "exclude": [],
            }
        },
        "rules": [
            {
                "type": "merge_queue",
                "parameters": {
                    "check_response_timeout_minutes": expected["requiredCheckTimeoutMinutes"],
                    "grouping_strategy": expected["groupingStrategy"],
                    "max_entries_to_build": expected["buildConcurrency"],
                    "max_entries_to_merge": expected["maximumGroupSize"],
                    "merge_method": expected["mergeMethod"],
                    "min_entries_to_merge": expected["minimumGroupSize"],
                    "min_entries_to_merge_wait_minutes": expected["minimumGroupWaitMinutes"],
                },
            }
        ],
        "bypass_actors": [],
    }


def verify(path: Path = POLICY) -> dict[str, object]:
    policy = load(path)
    if policy.get("schemaVersion") != "hartevo-github-branch-ruleset-policy/v1":
        raise ValueError("branch policy schema drift")
    if policy.get("repository") != "tangpingqingwa/hartevo-desktop":
        raise ValueError("branch policy repository drift")
    if policy.get("defaultBranch") != DEFAULT_BRANCH:
        raise ValueError("bootstrap/macos-r0 must remain the repository default branch")
    if policy.get("repositorySettings") != {
        "deleteBranchOnMerge": True,
        "allowUpdateBranch": True,
        "allowMergeCommit": True,
        "allowSquashMerge": False,
        "allowRebaseMerge": False,
        "allowAutoMerge": False,
    }:
        raise ValueError("repository settings must preserve merge-commit-only train integration and branch lifecycle cleanup")
    hosted_enforcement = policy.get("hostedEnforcement")
    if hosted_enforcement not in {UNAPPLIED, ACTIVE}:
        raise ValueError("hosted enforcement must be desired-active or active")
    observed = policy.get("observedHostedStatus")
    if not isinstance(observed, dict):
        raise ValueError("hosted observation must be recorded")
    if hosted_enforcement == ACTIVE:
        if observed.get("rulesetApi") != "ACTIVE" or not isinstance(observed.get("rulesetId"), int) or observed.get("rulesetId", 0) <= 0:
            raise ValueError("active policy must record a verified hosted ruleset id")
    elif observed.get("rulesetApi") != "NOT_APPLIED_AT_CHECKIN":
        raise ValueError("unapplied policy must record that hosted application is pending")

    for branch in branch_entries(policy):
        checks = branch.get("requiredStatusChecks")
        if not isinstance(checks, list) or len(checks) != len(set(checks)):
            raise ValueError(f"required checks for {branch.get('name')} must be non-empty and unique")
        if branch.get("allowForcePushes") is not False or branch.get("allowDeletions") is not False:
            raise ValueError(f"destructive branch operations must be disabled for {branch.get('name')}")
        if branch.get("requirePullRequest") is not True or branch.get("requireConversationResolution") is not True:
            raise ValueError(f"PR and conversation requirements missing for {branch.get('name')}")
        if branch.get("requiredApprovingReviews") != 0 or branch.get("requireCodeOwnerReview") is not False:
            raise ValueError(f"approval settings would deadlock a solo maintainer on {branch.get('name')}")

    ruleset = policy.get("ruleset")
    if not isinstance(ruleset, dict) or ruleset != desired_ruleset(policy):
        raise ValueError("checked-in ruleset payload drifted from the branch policy")
    merge_queue = policy.get("mergeQueue")
    if not isinstance(merge_queue, dict):
        raise ValueError("merge queue policy must be an object")
    merge_queue_enforcement = merge_queue.get("hostedEnforcement")
    if merge_queue_enforcement not in {UNAPPLIED, ACTIVE, BLOCKED_OWNER}:
        raise ValueError("merge queue hosted enforcement must be desired-active, active, or owner-blocked")
    merge_queue_observed = merge_queue.get("observedHostedStatus")
    if not isinstance(merge_queue_observed, dict):
        raise ValueError("merge queue hosted observation must be recorded")
    if merge_queue_enforcement == ACTIVE:
        if merge_queue_observed.get("rulesetApi") != "ACTIVE" or not isinstance(merge_queue_observed.get("rulesetId"), int) or merge_queue_observed.get("rulesetId", 0) <= 0:
            raise ValueError("active merge queue policy must record a verified hosted ruleset id")
    elif merge_queue_enforcement == UNAPPLIED and merge_queue_observed.get("rulesetApi") != "NOT_APPLIED_AT_CHECKIN":
        raise ValueError("unapplied merge queue policy must record that hosted application is pending")
    elif merge_queue_enforcement == BLOCKED_OWNER:
        if (
            merge_queue_observed.get("rulesetApi") != "UNAVAILABLE_PERSONAL_ACCOUNT_OWNER"
            or merge_queue_observed.get("rulesetId") is not None
            or merge_queue_observed.get("ownerType") != "User"
            or merge_queue_observed.get("requiredOwnerType") != "Organization"
        ):
            raise ValueError("owner-blocked merge queue must record GitHub's personal-account limitation")
    merge_queue_ruleset = merge_queue.get("ruleset")
    if not isinstance(merge_queue_ruleset, dict) or merge_queue_ruleset != desired_merge_queue_ruleset(policy):
        raise ValueError("checked-in merge queue ruleset payload drifted from the throughput policy")
    merge_train = policy.get("repositoryMergeTrain")
    if not isinstance(merge_train, dict):
        raise ValueError("repository merge-train fallback is missing")
    expected_train = {
        "enforcement": "active",
        "branchPrefix": MERGE_TRAIN_BRANCH_PREFIX,
        "manifestDirectory": MERGE_TRAIN_MANIFEST_DIRECTORY,
        "baseBranch": DEFAULT_BRANCH,
        "maximumCandidateCount": 4,
    }
    if any(merge_train.get(key) != value for key, value in expected_train.items()):
        raise ValueError("repository merge-train fallback drifted")
    candidate_requirements = merge_train.get("candidateRequirements")
    composite_requirements = merge_train.get("compositeRequirements")
    if not isinstance(candidate_requirements, list) or set(candidate_requirements) != {
        "open",
        "ready",
        "root-bootstrap-base",
        "exact-current-head",
        "candidate-checks-success-excluding-intentional-train-only-block",
    }:
        raise ValueError("repository merge-train candidate requirements drifted")
    if not isinstance(composite_requirements, list) or set(composite_requirements) != {
        "exact-first-parent-history",
        "exact-reconstructed-tree",
        "full-ubuntu-macos-matrix",
        "normal-protected-pull-request-merge",
        "no-bypass",
    }:
        raise ValueError("repository merge-train composite requirements drifted")
    release = policy.get("releaseEnvironment")
    if not isinstance(release, dict) or release.get("name") != "release-promotion" or release.get("oidcOnly") is not True or release.get("longLivedCredentialsAllowed") is not False or release.get("releaseEnabledInThisPr") is not False:
        raise ValueError("release environment must be OIDC-only and disabled in this PR")
    return {
        "schema": "hartevo-ci-branch-policy/v1",
        "status": "VERIFIED",
        "hostedEnforcement": "ACTIVE" if hosted_enforcement == ACTIVE else "DESIRED_ACTIVE",
        "defaultBranch": DEFAULT_BRANCH,
        "branches": sorted(REQUIRED_BRANCHES),
        "requiredChecks": list(EXPECTED_STATUS_CHECKS),
        "mergeQueue": {
            "hostedEnforcement": (
                "ACTIVE"
                if merge_queue_enforcement == ACTIVE
                else "BLOCKED_ENV"
                if merge_queue_enforcement == BLOCKED_OWNER
                else "DESIRED_ACTIVE"
            ),
            "buildConcurrency": 4,
            "maximumGroupSize": 4,
            "fallback": "ACTIVE_REPOSITORY_MERGE_TRAIN",
        },
        "releaseEnabled": False,
    }


def gh_api(endpoint: str, method: str | None = None, payload: dict[str, object] | None = None) -> object:
    command = ["gh", "api", endpoint]
    if method is not None:
        command.extend(["--method", method])
    input_data = None
    if payload is not None:
        command.extend(["--input", "-"])
        input_data = json.dumps(payload, sort_keys=True)
    process = subprocess.run(
        command,
        check=False,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        message = (process.stderr or process.stdout).strip()
        raise ValueError(f"GitHub API {method or 'GET'} {endpoint} failed: {message}")
    return json.loads(process.stdout)


def ruleset_matches(actual: object, desired: dict[str, object]) -> bool:
    if not isinstance(actual, dict):
        return False
    if actual.get("name") != desired["name"] or actual.get("target") != desired["target"] or actual.get("enforcement") != desired["enforcement"]:
        return False
    actual_conditions = actual.get("conditions")
    desired_conditions = desired["conditions"]
    if not isinstance(actual_conditions, dict) or not isinstance(desired_conditions, dict):
        return False
    actual_refs = actual_conditions.get("ref_name")
    desired_refs = desired_conditions.get("ref_name")
    if not isinstance(actual_refs, dict) or not isinstance(desired_refs, dict):
        return False
    if set(actual_refs.get("include", [])) != set(desired_refs.get("include", [])) or set(actual_refs.get("exclude", [])) != set(desired_refs.get("exclude", [])):
        return False

    actual_rules = {rule.get("type"): rule for rule in actual.get("rules", []) if isinstance(rule, dict)}
    desired_rules = {rule.get("type"): rule for rule in desired.get("rules", []) if isinstance(rule, dict)}
    if desired.get("name") == MERGE_QUEUE_RULESET_NAME:
        if set(actual_rules) != {"merge_queue"} or set(desired_rules) != {"merge_queue"}:
            return False
        actual_parameters = actual_rules["merge_queue"].get("parameters", {})
        desired_parameters = desired_rules["merge_queue"].get("parameters", {})
        return (
            isinstance(actual_parameters, dict)
            and isinstance(desired_parameters, dict)
            and all(actual_parameters.get(key) == value for key, value in desired_parameters.items())
            and actual.get("bypass_actors", []) == desired.get("bypass_actors", [])
        )
    if not {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}.issubset(actual_rules):
        return False
    pull_parameters = actual_rules["pull_request"].get("parameters", {})
    desired_pull_parameters = desired_rules["pull_request"].get("parameters", {})
    for key in ("dismiss_stale_reviews_on_push", "require_code_owner_review", "require_last_push_approval", "required_approving_review_count", "required_review_thread_resolution"):
        if pull_parameters.get(key) != desired_pull_parameters.get(key):
            return False
    status_parameters = actual_rules["required_status_checks"].get("parameters", {})
    desired_status_parameters = desired_rules["required_status_checks"].get("parameters", {})
    for key in ("strict_required_status_checks_policy", "do_not_enforce_on_create"):
        if status_parameters.get(key) != desired_status_parameters.get(key):
            return False
    if actual.get("bypass_actors", []) != desired.get("bypass_actors", []):
        return False
    actual_checks = status_parameters.get("required_status_checks", [])
    desired_checks = desired_rules["required_status_checks"].get("parameters", {}).get("required_status_checks", [])
    return {item.get("context") for item in actual_checks if isinstance(item, dict)} == {item.get("context") for item in desired_checks if isinstance(item, dict)}


def hosted_repository(repo: str) -> dict[str, object]:
    response = gh_api(f"repos/{repo}")
    if not isinstance(response, dict):
        raise ValueError("GitHub repository response must be an object")
    owner = response.get("owner")
    if not isinstance(owner, dict) or owner.get("type") not in {"User", "Organization"}:
        raise ValueError("GitHub repository owner type is unavailable")
    if not isinstance(response.get("default_branch"), str):
        raise ValueError("GitHub repository default branch is unavailable")
    return response


def require_trusted_admission_on_protected(repo: str) -> None:
    """Refuse to require train-only checks before their trusted workflow exists."""
    if not TRUSTED_ADMISSION_WORKFLOW.is_file():
        raise ValueError("trusted governance admission workflow is missing locally")
    local_blob = subprocess.run(
        ["git", "hash-object", str(TRUSTED_ADMISSION_WORKFLOW)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    try:
        hosted = gh_api(
            f"repos/{repo}/contents/{TRUSTED_ADMISSION_WORKFLOW.as_posix()}?ref={DEFAULT_BRANCH}"
        )
    except ValueError as error:
        raise ValueError(
            "trusted governance admission is not yet installed on bootstrap/macos-r0; "
            "merge the control-plane PR before applying its required checks"
        ) from error
    if not isinstance(hosted, dict) or hosted.get("sha") != local_blob:
        raise ValueError(
            "protected governance admission workflow does not match the local desired policy"
        )


def probe(repo: str) -> int:
    local = verify()
    policy = load()
    try:
        repository = hosted_repository(repo)
        response = gh_api(f"repos/{repo}/rulesets?per_page=100")
    except ValueError as error:
        message = str(error)
        status = "BLOCKED_ENV" if "403" in message or "forbidden" in message.lower() else "FAIL"
        print(json.dumps({**local, "status": status, "code": "HOSTED_RULESET_API_UNAVAILABLE", "message": message}, sort_keys=True))
        return 2 if status == "BLOCKED_ENV" else 1
    if repository.get("default_branch") != DEFAULT_BRANCH:
        print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_DEFAULT_BRANCH_MISMATCH", "observedDefaultBranch": repository.get("default_branch")}, sort_keys=True))
        return 1
    expected_settings = {
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
        "allow_merge_commit": True,
        "allow_squash_merge": False,
        "allow_rebase_merge": False,
        "allow_auto_merge": False,
    }
    if any(repository.get(key) is not value for key, value in expected_settings.items()):
        print(
            json.dumps(
                {
                    **local,
                    "status": "FAIL",
                    "code": "HOSTED_REPOSITORY_LIFECYCLE_SETTINGS_MISMATCH",
                    "deleteBranchOnMerge": repository.get("delete_branch_on_merge"),
                    "allowUpdateBranch": repository.get("allow_update_branch"),
                    "allowMergeCommit": repository.get("allow_merge_commit"),
                    "allowSquashMerge": repository.get("allow_squash_merge"),
                    "allowRebaseMerge": repository.get("allow_rebase_merge"),
                    "allowAutoMerge": repository.get("allow_auto_merge"),
                },
                sort_keys=True,
            )
        )
        return 1
    if not isinstance(response, list):
        print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_LIST_INVALID"}, sort_keys=True))
        return 1
    owner = repository.get("owner")
    assert isinstance(owner, dict)
    owner_type = owner.get("type")
    protected = policy.get("ruleset")
    merge_queue = policy.get("mergeQueue")
    queue_desired = merge_queue.get("ruleset") if isinstance(merge_queue, dict) else None
    merge_queue_enforcement = merge_queue.get("hostedEnforcement") if isinstance(merge_queue, dict) else None
    if merge_queue_enforcement == BLOCKED_OWNER and owner_type != "User":
        print(json.dumps({**local, "status": "FAIL", "code": "MERGE_QUEUE_OWNER_POLICY_STALE", "observedOwnerType": owner_type}, sort_keys=True))
        return 1
    desired_rulesets = [protected]
    if merge_queue_enforcement != BLOCKED_OWNER:
        desired_rulesets.append(queue_desired)
    observed_rulesets: list[dict[str, object]] = []
    pending: list[str] = []
    for desired in desired_rulesets:
        if not isinstance(desired, dict) or not isinstance(desired.get("name"), str):
            print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_PAYLOAD_MISSING"}, sort_keys=True))
            return 1
        named = [item for item in response if isinstance(item, dict) and item.get("name") == desired["name"]]
        if not named and desired["name"] == MERGE_QUEUE_RULESET_NAME and merge_queue_enforcement == UNAPPLIED:
            pending.append(str(desired["name"]))
            continue
        if len(named) != 1:
            print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_MISMATCH", "rulesetName": desired["name"], "matchingRulesets": len(named)}, sort_keys=True))
            return 1
        ruleset_id = named[0].get("id")
        if not isinstance(ruleset_id, int):
            print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_ID_INVALID", "rulesetName": desired["name"]}, sort_keys=True))
            return 1
        observed = named[0]
        if not ruleset_matches(observed, desired):
            try:
                observed = gh_api(f"repos/{repo}/rulesets/{ruleset_id}")
            except ValueError as error:
                print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_DETAIL_UNAVAILABLE", "message": str(error)}, sort_keys=True))
                return 1
        if not ruleset_matches(observed, desired):
            if desired["name"] == RULESET_NAME and policy.get("hostedEnforcement") == UNAPPLIED:
                pending.append(str(desired["name"]))
                observed_rulesets.append({"id": observed.get("id"), "name": observed.get("name"), "enforcement": observed.get("enforcement"), "state": "PREVIOUS_POLICY_ACTIVE"})
                continue
            print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_MISMATCH", "hostedRuleset": observed}, sort_keys=True))
            return 1
        observed_rulesets.append({"id": observed.get("id"), "name": observed.get("name"), "enforcement": observed.get("enforcement")})
    if merge_queue_enforcement == BLOCKED_OWNER:
        hosted_queue = [item for item in response if isinstance(item, dict) and item.get("name") == MERGE_QUEUE_RULESET_NAME]
        if hosted_queue:
            print(json.dumps({**local, "status": "FAIL", "code": "UNEXPECTED_HOSTED_MERGE_QUEUE_RULESET", "hostedQueueRulesets": len(hosted_queue)}, sort_keys=True))
            return 1
        if pending:
            print(json.dumps({**local, "status": "DESIRED_ACTIVE", "code": "TRUSTED_ADMISSION_ROLLOUT_PENDING", "pendingRulesets": pending, "hostedRulesets": observed_rulesets, "repositoryMergeTrain": "PENDING_REQUIRED_CHECK_ACTIVATION", "mergeMethod": "MERGE_COMMIT_ONLY"}, sort_keys=True))
            return 2
        print(json.dumps({**local, "status": "VERIFIED", "code": "HOSTED_MERGE_QUEUE_BLOCKED_FALLBACK_ACTIVE", "observedOwnerType": owner_type, "hostedRulesets": observed_rulesets, "repositoryMergeTrain": "ACTIVE", "deleteBranchOnMerge": True, "allowUpdateBranch": True, "mergeMethod": "MERGE_COMMIT_ONLY"}, sort_keys=True))
        return 0
    if pending:
        print(json.dumps({**local, "status": "DESIRED_ACTIVE", "code": "HOSTED_MERGE_QUEUE_NOT_APPLIED", "pendingRulesets": pending, "hostedRulesets": observed_rulesets}, sort_keys=True))
        return 2
    print(json.dumps({**local, "status": "VERIFIED", "hostedRulesets": observed_rulesets}, sort_keys=True))
    return 0


def apply(repo: str) -> int:
    policy = load()
    local = verify()
    repository = hosted_repository(repo)
    owner = repository.get("owner")
    assert isinstance(owner, dict)
    owner_type = owner.get("type")
    if repository.get("default_branch") != DEFAULT_BRANCH:
        repository = gh_api(f"repos/{repo}", "PATCH", {"default_branch": DEFAULT_BRANCH})
        if not isinstance(repository, dict) or repository.get("default_branch") != DEFAULT_BRANCH:
            raise ValueError("failed to enforce bootstrap/macos-r0 as the repository default branch")
    expected_settings = {
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
        "allow_merge_commit": True,
        "allow_squash_merge": False,
        "allow_rebase_merge": False,
        "allow_auto_merge": False,
    }
    if any(repository.get(key) is not value for key, value in expected_settings.items()):
        repository = gh_api(
            f"repos/{repo}",
            "PATCH",
            expected_settings,
        )
        if (
            not isinstance(repository, dict)
            or any(repository.get(key) is not value for key, value in expected_settings.items())
        ):
            raise ValueError("failed to enforce repository integration and branch lifecycle settings")
    require_trusted_admission_on_protected(repo)
    protected = policy.get("ruleset")
    merge_queue = policy.get("mergeQueue")
    queue_desired = merge_queue.get("ruleset") if isinstance(merge_queue, dict) else None
    merge_queue_enforcement = merge_queue.get("hostedEnforcement") if isinstance(merge_queue, dict) else None
    if merge_queue_enforcement == BLOCKED_OWNER and owner_type != "User":
        raise ValueError("owner-blocked merge queue policy is stale for a non-User repository owner")
    if merge_queue_enforcement != BLOCKED_OWNER and owner_type != "Organization":
        raise ValueError("GitHub hosted merge queue requires an Organization-owned repository")
    desired_rulesets = [protected]
    if merge_queue_enforcement != BLOCKED_OWNER:
        desired_rulesets.append(queue_desired)
    if not all(isinstance(desired, dict) for desired in desired_rulesets):
        raise ValueError("protected or merge queue ruleset payload is missing")
    response = gh_api(f"repos/{repo}/rulesets?per_page=100")
    if not isinstance(response, list):
        raise ValueError("GitHub ruleset list response must be an array")
    operations: list[dict[str, object]] = []
    for desired in desired_rulesets:
        assert isinstance(desired, dict)
        matches = [item for item in response if isinstance(item, dict) and item.get("name") == desired.get("name")]
        if len(matches) > 1:
            raise ValueError(f"multiple rulesets named {desired.get('name')!r} exist; refusing ambiguous update")
        if matches:
            ruleset_id = matches[0].get("id")
            if not isinstance(ruleset_id, int) or ruleset_id <= 0:
                raise ValueError("existing ruleset has no valid numeric id")
            applied = gh_api(f"repos/{repo}/rulesets/{ruleset_id}", "PUT", desired)
            operation = "updated"
        else:
            applied = gh_api(f"repos/{repo}/rulesets", "POST", desired)
            operation = "created"
        if not isinstance(applied, dict) or not isinstance(applied.get("id"), int):
            raise ValueError("GitHub ruleset apply response has no numeric id")
        operations.append({"operation": operation, "rulesetId": applied["id"], "rulesetName": applied.get("name")})
    print(json.dumps({**local, "status": "APPLIED", "operations": operations, "observedOwnerType": owner_type, "nativeMergeQueue": "BLOCKED_ENV" if merge_queue_enforcement == BLOCKED_OWNER else "ACTIVE", "repositoryMergeTrain": "ACTIVE", "deleteBranchOnMerge": True, "allowUpdateBranch": True, "mergeMethod": "MERGE_COMMIT_ONLY"}, sort_keys=True))
    return 0


def self_test() -> None:
    policy = load()
    mutated = json.loads(json.dumps(policy))
    mutated["hostedEnforcement"] = "unclaimed"
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted an unclaimed hosted-enforcement mutation")
    mutated = json.loads(json.dumps(policy))
    mutated["branches"][0]["requiredApprovingReviews"] = 1
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted a solo-maintainer approval deadlock")
    mutated = json.loads(json.dumps(policy))
    mutated["mergeQueue"]["buildConcurrency"] = 5
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted merge queue build concurrency above four")
    mutated = json.loads(json.dumps(policy))
    mutated["mergeQueue"]["hostedEnforcement"] = "unclaimed"
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted an unclaimed merge queue enforcement state")
    mutated = json.loads(json.dumps(policy))
    mutated["repositoryMergeTrain"]["maximumCandidateCount"] = 5
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted a repository merge train above four candidates")
    mutated = json.loads(json.dumps(policy))
    mutated["defaultBranch"] = "main"
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted main as the default development branch")
    mutated = json.loads(json.dumps(policy))
    mutated["repositorySettings"]["deleteBranchOnMerge"] = False
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted disabled post-merge branch deletion")
    mutated = json.loads(json.dumps(policy))
    mutated["repositorySettings"]["allowSquashMerge"] = True
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted a merge method that bypasses exact train topology")
    print(json.dumps({"schema": "hartevo-ci-branch-policy-self-test/v1", "status": "PASS"}, sort_keys=True))


def verify_policy_value(policy: dict[str, object]) -> None:
    temporary = Path(".github/policies/.ci-branch-policy-self-test.json")
    temporary.write_text(json.dumps(policy), encoding="utf-8")
    try:
        verify(temporary)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["verify", "probe", "apply", "self-test"])
    parser.add_argument("--repo", default="tangpingqingwa/hartevo-desktop")
    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify":
            print(json.dumps(verify(), sort_keys=True))
            return 0
        if args.command == "probe":
            return probe(args.repo)
        if args.command == "apply":
            return apply(args.repo)
        self_test()
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": "hartevo-ci-branch-policy/v1", "status": "FAIL", "message": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
