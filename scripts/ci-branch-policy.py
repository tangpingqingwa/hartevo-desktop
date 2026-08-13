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
RULESET_NAME = "Hartevo protected integration branches"
GITHUB_ACTIONS_INTEGRATION_ID = 15368
EXPECTED_STATUS_CHECKS = (
    "PR / Workflow policy",
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


def verify(path: Path = POLICY) -> dict[str, object]:
    policy = load(path)
    if policy.get("schemaVersion") != "hartevo-github-branch-ruleset-policy/v1":
        raise ValueError("branch policy schema drift")
    if policy.get("repository") != "tangpingqingwa/hartevo-desktop":
        raise ValueError("branch policy repository drift")
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
    release = policy.get("releaseEnvironment")
    if not isinstance(release, dict) or release.get("name") != "release-promotion" or release.get("oidcOnly") is not True or release.get("longLivedCredentialsAllowed") is not False or release.get("releaseEnabledInThisPr") is not False:
        raise ValueError("release environment must be OIDC-only and disabled in this PR")
    return {
        "schema": "hartevo-ci-branch-policy/v1",
        "status": "VERIFIED",
        "hostedEnforcement": "ACTIVE" if hosted_enforcement == ACTIVE else "DESIRED_ACTIVE",
        "branches": sorted(REQUIRED_BRANCHES),
        "requiredChecks": list(EXPECTED_STATUS_CHECKS),
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


def probe(repo: str) -> int:
    local = verify()
    try:
        response = gh_api(f"repos/{repo}/rulesets?per_page=100")
    except ValueError as error:
        message = str(error)
        status = "BLOCKED_ENV" if "403" in message or "forbidden" in message.lower() else "FAIL"
        print(json.dumps({**local, "status": status, "code": "HOSTED_RULESET_API_UNAVAILABLE", "message": message}, sort_keys=True))
        return 2 if status == "BLOCKED_ENV" else 1
    desired = load().get("ruleset")
    named = [item for item in response if isinstance(item, dict) and item.get("name") == RULESET_NAME] if isinstance(response, list) else []
    if len(named) != 1 or not isinstance(desired, dict):
        print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_MISMATCH", "matchingRulesets": len(named), "hostedResponse": response}, sort_keys=True))
        return 1
    ruleset_id = named[0].get("id")
    if not isinstance(ruleset_id, int) or not ruleset_matches(named[0], desired):
        try:
            observed = gh_api(f"repos/{repo}/rulesets/{ruleset_id}")
        except ValueError as error:
            print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_DETAIL_UNAVAILABLE", "message": str(error)}, sort_keys=True))
            return 1
    else:
        observed = named[0]
    if not ruleset_matches(observed, desired):
        print(json.dumps({**local, "status": "FAIL", "code": "HOSTED_RULESET_MISMATCH", "hostedRuleset": observed}, sort_keys=True))
        return 1
    print(json.dumps({**local, "status": "VERIFIED", "hostedRuleset": {"id": observed.get("id"), "name": observed.get("name"), "enforcement": observed.get("enforcement")}}, sort_keys=True))
    return 0


def apply(repo: str) -> int:
    policy = load()
    local = verify()
    desired = policy.get("ruleset")
    if not isinstance(desired, dict):
        raise ValueError("ruleset payload is missing")
    response = gh_api(f"repos/{repo}/rulesets?per_page=100")
    if not isinstance(response, list):
        raise ValueError("GitHub ruleset list response must be an array")
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
    print(json.dumps({**local, "status": "APPLIED", "operation": operation, "rulesetId": applied["id"], "rulesetName": applied.get("name")}, sort_keys=True))
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
