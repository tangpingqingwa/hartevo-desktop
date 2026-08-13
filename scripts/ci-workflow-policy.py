#!/usr/bin/env python3
"""Enforce the checked-in GitHub Actions security and execution policy."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


WORKFLOW_DIR = Path(".github/workflows")
PINS = Path(".github/policies/action-pins.json")
BRANCH_POLICY = Path(".github/policies/branch-ruleset-policy.json")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_.-]+):\s*$")
NAME_RE = re.compile(r"^\s*name:\s*(?:['\"]([^'\"]+)['\"]|([^#]+?))\s*$")


class PolicyError(ValueError):
    pass


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PolicyError(f"{path} must contain a JSON object")
    return value


def workflow_files(root: Path) -> list[Path]:
    directory = root / WORKFLOW_DIR
    return sorted(path for path in directory.iterdir() if path.suffix in {".yml", ".yaml"} and path.is_file())


def action_pin_map(root: Path) -> dict[str, str]:
    policy = load_json(root / PINS)
    if policy.get("schemaVersion") != "hartevo-ci-action-pins/v1":
        raise PolicyError("action pin policy schema drift")
    pins = policy.get("pins")
    if not isinstance(pins, list) or not pins:
        raise PolicyError("action pin policy must contain pins")
    result: dict[str, str] = {}
    for pin in pins:
        if not isinstance(pin, dict):
            raise PolicyError("action pin entry must be an object")
        repository = pin.get("uses")
        ref = pin.get("ref")
        sha = pin.get("sha")
        if not isinstance(repository, str) or not isinstance(ref, str) or not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            raise PolicyError(f"invalid action pin entry: {pin}")
        if repository in result:
            raise PolicyError(f"duplicate action pin: {repository}")
        result[f"{repository}@{sha}"] = ref
    return result


def verify_pins(root: Path) -> dict[str, object]:
    policy = load_json(root / PINS)
    pins = policy.get("pins")
    if not isinstance(pins, list):
        raise PolicyError("action pin policy must contain a pins array")
    verified: list[str] = []
    for pin in pins:
        if not isinstance(pin, dict):
            raise PolicyError("action pin entry must be an object")
        repository = pin.get("uses")
        ref = pin.get("ref")
        expected = pin.get("sha")
        if not isinstance(repository, str) or not isinstance(ref, str) or not isinstance(expected, str) or not SHA_RE.fullmatch(expected):
            raise PolicyError(f"invalid action pin entry: {pin}")
        process = subprocess.run(
            ["git", "ls-remote", f"https://github.com/{repository}.git", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        if process.returncode != 0:
            raise PolicyError(f"unable to resolve upstream action tag {repository}@{ref}: {process.stderr.strip()}")
        resolved = {
            line.split()[0]
            for line in process.stdout.splitlines()
            if len(line.split()) == 2 and line.split()[1] in {f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"}
        }
        if expected not in resolved:
            raise PolicyError(f"action pin drift for {repository}@{ref}: expected {expected}, got {sorted(resolved)}")
        verified.append(f"{repository}@{ref}={expected}")
    return {"schema": "hartevo-ci-action-pin-resolution/v1", "status": "PASS", "verified": sorted(verified)}


def indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def block_for_job(lines: list[str], start: int) -> list[str]:
    result = []
    for line in lines[start:]:
        if result and line.strip() and indent(line) <= 2:
            break
        result.append(line)
    return result


def static_job_names(lines: list[str]) -> list[str]:
    names: list[str] = []
    for line in lines:
        match = NAME_RE.match(line)
        if match and indent(line) in {0, 2, 4}:
            value = (match.group(1) or match.group(2) or "").strip()
            if "${{" not in value:
                names.append(value)
    return names


def validate_job_blocks(path: Path, lines: list[str]) -> None:
    jobs_index = next((index for index, line in enumerate(lines) if line.strip() == "jobs:" and indent(line) == 0), None)
    if jobs_index is None:
        raise PolicyError(f"{path} is missing a top-level jobs block")
    jobs: list[tuple[str, int]] = []
    for index in range(jobs_index + 1, len(lines)):
        match = JOB_RE.match(lines[index])
        if match:
            jobs.append((match.group(1), index))
    if not jobs:
        raise PolicyError(f"{path} has no jobs")
    for job_name, start in jobs:
        block = block_for_job(lines, start)
        joined = "\n".join(block)
        if "permissions:" not in joined:
            raise PolicyError(f"{path} job {job_name} lacks explicit permissions")
        if "uses: ./.github/workflows/" not in joined and not re.search(r"^    timeout-minutes:\s*[1-9][0-9]*\s*$", joined, re.MULTILINE):
            raise PolicyError(f"{path} job {job_name} lacks a timeout-minutes fence")


def validate_permissions(path: Path, text: str) -> None:
    top = re.search(r"^permissions:\s*$", text, re.MULTILINE)
    if not top:
        raise PolicyError(f"{path} lacks top-level permissions")
    forbidden = ("write-all", "actions: write", "contents: write", "packages: write", "pull-requests: write", "id-token: write")
    if any(token in text for token in forbidden[:-1]):
        raise PolicyError(f"{path} contains broad or privileged write permissions")
    if "id-token: write" in text and path.name != "release-promotion.yml":
        raise PolicyError(f"{path} may not request OIDC token permissions")


def validate_concurrency(path: Path, text: str) -> None:
    if not re.search(r"^concurrency:\s*$", text, re.MULTILINE):
        raise PolicyError(f"{path} lacks workflow concurrency")
    if not re.search(r"^\s+group:\s*\S+", text, re.MULTILINE):
        raise PolicyError(f"{path} concurrency has no stable group")
    if not re.search(r"^\s+cancel-in-progress:\s*(true|false)\s*$", text, re.MULTILINE):
        raise PolicyError(f"{path} concurrency must declare cancel-in-progress")
    if path.name == "ci.yml" and not re.search(r"cancel-in-progress:\s*true", text):
        raise PolicyError("PR workflow must cancel superseded runs")
    if path.name in {"integration.yml", "release-promotion.yml"} and not re.search(r"cancel-in-progress:\s*false", text):
        raise PolicyError(f"{path} must serialize rather than cancel integration/release runs")


def validate_actions(path: Path, text: str, pins: dict[str, str]) -> list[str]:
    actions: list[str] = []
    for line in text.splitlines():
        match = USES_RE.match(line)
        if not match:
            continue
        value = match.group(1)
        if value.startswith("./") or value.startswith("docker://"):
            continue
        if "@" not in value:
            raise PolicyError(f"{path} contains an action without a ref: {value}")
        repository, sha = value.rsplit("@", 1)
        if not SHA_RE.fullmatch(sha):
            raise PolicyError(f"{path} action is not pinned to a full SHA: {value}")
        if f"{repository}@{sha}" not in pins:
            raise PolicyError(f"{path} action pin is not present in the verified catalog: {value}")
        actions.append(value)
    return actions


def validate_checkout_safety(path: Path, text: str) -> None:
    checkout_count = len(re.findall(r"actions/checkout@", text))
    safe_count = len(re.findall(r"persist-credentials:\s*false", text))
    if checkout_count != safe_count:
        raise PolicyError(f"{path} every checkout must disable persisted credentials")


def validate_pr_secrets(path: Path, text: str) -> None:
    if "pull_request_target" in text or "workflow_run:" in text:
        raise PolicyError(f"{path} uses a privileged event path")
    if "pull_request:" in text or "pull_request_review:" in text:
        if re.search(r"\bsecrets\b|secrets\.", text):
            raise PolicyError(f"{path} exposes secrets to an untrusted PR event")


def validate_required_workflow_contract(path: Path, text: str) -> None:
    if path.name == "ci.yml":
        required = ("pull_request:", "scripts/ci-scope.py", "rust-reusable.yml", "scripts/ci-workflow-policy.py", "scripts/ci-result.py", "PR / Result taxonomy")
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing a required fast-PR contract")
        if "branches: [main]" in text or "branches: [bootstrap/macos-r0]" in text:
            raise PolicyError(f"{path} must not run the integration push tier")
    elif path.name == "integration.yml":
        required = ("bootstrap/macos-r0", "pull_request_review:", "HARTEVO_TEST_POSTGRES_URL", "postgres:18.4", "check-evidence-doc-truth.sh", "check-openinterpreter-schema.sh", "check-dioxus-toolchain.sh", "catalog export", "evidence baseline", "Integration / Result taxonomy")
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing a required integration contract")
    elif path.name == "release-promotion.yml":
        required = ("workflow_dispatch:", "environment: release-promotion", "id-token: write", "source_commit", "refs/heads/main", "release-baseline", "releaseCommit", "passed", "sha256", "rollback", "release: false", "ci-distribution-hook.sh", "ci-oidc-interface")
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing a release fence")
        forbidden_deploy = ("kubectl apply", "helm upgrade", "aws deploy", "vercel --prod", "gh release create")
        if any(item in text for item in forbidden_deploy):
            raise PolicyError(f"{path} contains a deployment or tag-mutation command")
    elif path.name == "rust-reusable.yml":
        required = ("workflow_call:", "inputs:", "check_prefix", "ci-rust-gate.sh", "all-targets", "all-features", "--locked")
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing the reusable Rust gate contract")


def verify(root: Path) -> dict[str, object]:
    pins = action_pin_map(root)
    files = workflow_files(root)
    if {path.name for path in files} != {"ci.yml", "integration.yml", "release-promotion.yml", "rust-reusable.yml"}:
        raise PolicyError("workflow set must be exactly the PR, integration, release, and reusable workflows")
    all_actions: list[str] = []
    names: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        validate_permissions(path, text)
        validate_concurrency(path, text)
        validate_job_blocks(path, lines)
        validate_pr_secrets(path, text)
        validate_checkout_safety(path, text)
        validate_required_workflow_contract(path, text)
        all_actions.extend(validate_actions(path, text, pins))
        names.extend(static_job_names(lines))
    if len(names) != len(set(names)):
        raise PolicyError("static workflow job/check names must be unique")
    branch_policy = load_json(root / BRANCH_POLICY)
    if branch_policy.get("hostedEnforcement") != "not_claimed_unavailable_current_plan":
        raise PolicyError("branch policy may not claim hosted enforcement")
    return {
        "schema": "hartevo-ci-workflow-policy/v1",
        "status": "PASS",
        "workflowCount": len(files),
        "externalActionCount": len(all_actions),
        "actionPinsVerified": sorted(set(all_actions)),
        "hostedBranchEnforcement": "NOT_CLAIMED",
        "releaseEnabled": False,
    }


def self_test() -> None:
    pins = {"actions/checkout@" + "a" * 40: "v4"}
    try:
        validate_actions(Path("fixture.yml"), "- uses: actions/checkout@v4", pins)
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a movable action tag")
    try:
        validate_actions(Path("fixture.yml"), "- uses: actions/checkout@" + "b" * 40, pins)
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted an unverified action SHA")

    try:
        validate_permissions(Path("fixture.yml"), "permissions:\n  contents: write\n")
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a broad write permission")

    try:
        validate_pr_secrets(Path("fixture.yml"), "on:\n  pull_request_target:\n    secrets: inherit\n")
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a privileged PR secret path")

    try:
        validate_concurrency(Path("ci.yml"), "concurrency:\n  group: fixture\n  cancel-in-progress: false\n")
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a PR workflow without cancellation")

    try:
        validate_job_blocks(Path("fixture.yml"), ["jobs:", "  check:", "    runs-on: ubuntu-24.04"])
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a job without timeout or permissions")

    try:
        validate_required_workflow_contract(Path("release-promotion.yml"), "workflow_dispatch:\npermissions:\n  contents: read\n")
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted an unfenced release workflow")
    print(json.dumps({"schema": "hartevo-ci-workflow-policy-self-test/v1", "status": "PASS"}, sort_keys=True))


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["verify", "verify-pins", "self-test"])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args(list(argv))
    try:
        if args.command == "self-test":
            self_test()
            return 0
        if args.command == "verify-pins":
            print(json.dumps(verify_pins(args.repo), sort_keys=True))
            return 0
        print(json.dumps(verify(args.repo), sort_keys=True))
        return 0
    except (OSError, PolicyError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "hartevo-ci-workflow-policy/v1", "status": "FAIL", "message": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
