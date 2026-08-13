#!/usr/bin/env python3
"""Verify the checked-in desired branch/ruleset policy.

The local verifier deliberately does not imply that GitHub has applied the
policy. `probe` reports the hosted API result separately and preserves a 403
private-plan limitation as BLOCKED_ENV.
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


def load(path: Path = POLICY) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("branch policy must be a JSON object")
    return value


def verify(path: Path = POLICY) -> dict[str, object]:
    policy = load(path)
    if policy.get("schemaVersion") != "hartevo-github-branch-ruleset-policy/v1":
        raise ValueError("branch policy schema drift")
    if policy.get("repository") != "tangpingqingwa/hartevo-desktop":
        raise ValueError("branch policy repository drift")
    if policy.get("hostedEnforcement") != "not_claimed_unavailable_current_plan":
        raise ValueError("hosted enforcement must remain explicitly unclaimed")
    observed = policy.get("observedHostedStatus")
    if not isinstance(observed, dict) or observed.get("branchProtectionApi") != "HTTP_403_PRIVATE_REPOSITORY_PLAN" or observed.get("rulesetApi") != "HTTP_403_PRIVATE_REPOSITORY_PLAN":
        raise ValueError("hosted limitation must be recorded as the observed 403 plan boundary")
    branches = policy.get("branches")
    if not isinstance(branches, list) or {item.get("name") for item in branches if isinstance(item, dict)} != REQUIRED_BRANCHES:
        raise ValueError("policy must cover exactly main and bootstrap/macos-r0")
    for branch in branches:
        if not isinstance(branch, dict):
            raise ValueError("branch entry must be an object")
        checks = branch.get("requiredStatusChecks")
        if not isinstance(checks, list) or not checks or len(checks) != len(set(checks)):
            raise ValueError(f"required checks for {branch.get('name')} must be non-empty and unique")
        if branch.get("allowForcePushes") is not False or branch.get("allowDeletions") is not False:
            raise ValueError(f"destructive branch operations must be disabled for {branch.get('name')}")
        if branch.get("requirePullRequest") is not True or branch.get("requireCodeOwnerReview") is not True:
            raise ValueError(f"review and code-owner requirements missing for {branch.get('name')}")
    release = policy.get("releaseEnvironment")
    if not isinstance(release, dict) or release.get("name") != "release-promotion" or release.get("oidcOnly") is not True or release.get("longLivedCredentialsAllowed") is not False or release.get("releaseEnabledInThisPr") is not False:
        raise ValueError("release environment must be OIDC-only and disabled in this PR")
    return {
        "schema": "hartevo-ci-branch-policy/v1",
        "status": "VERIFIED",
        "hostedEnforcement": "NOT_CLAIMED",
        "branches": sorted(REQUIRED_BRANCHES),
        "releaseEnabled": False,
    }


def probe(repo: str) -> int:
    local = verify()
    process = subprocess.run(
        ["gh", "api", f"repos/{repo}/rulesets"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        message = (process.stderr or process.stdout).strip()
        status = "BLOCKED_ENV" if "403" in message or "forbidden" in message.lower() else "FAIL"
        print(json.dumps({**local, "status": status, "code": "HOSTED_RULESET_API_UNAVAILABLE", "message": message}, sort_keys=True))
        return 2 if status == "BLOCKED_ENV" else 1
    print(json.dumps({**local, "status": "OBSERVED", "hostedResponse": json.loads(process.stdout)}, sort_keys=True))
    return 0


def self_test() -> None:
    policy = load()
    mutated = json.loads(json.dumps(policy))
    mutated["hostedEnforcement"] = "enforced"
    try:
        verify_policy_value(mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted an unclaimed hosted-enforcement mutation")
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
    parser.add_argument("command", choices=["verify", "probe", "self-test"])
    parser.add_argument("--repo", default="tangpingqingwa/hartevo-desktop")
    args = parser.parse_args(list(argv))
    try:
        if args.command == "verify":
            print(json.dumps(verify(), sort_keys=True))
            return 0
        if args.command == "probe":
            return probe(args.repo)
        self_test()
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "hartevo-ci-branch-policy/v1", "status": "FAIL", "message": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
