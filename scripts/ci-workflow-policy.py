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
CACHE_ACTION_REF = "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
CACHE_EPOCH = "hartevo-rust-cache-v2"
CACHE_RUNNER_OS = "${{ runner.os }}"
CACHE_RUNNER_ARCH = "${{ runner.arch }}"
CACHE_LOCK_DIGEST = "${{ hashFiles('rust-toolchain.toml', 'Cargo.toml', 'Cargo.lock') }}"
CACHE_FULL_WORKSPACE = "${{ inputs.full_workspace }}"
CACHE_GITHUB_SHA = "${{ github.sha }}"
CACHE_GITHUB_RUN_ID = "${{ github.run_id }}"
CACHE_GITHUB_RUN_ATTEMPT = "${{ github.run_attempt }}"
CACHE_MODE = "all-targets-all-features"
CACHE_SHARD_LAYOUT_DIGEST = "${{ steps.shard-plan.outputs.layout_digest }}"
CACHE_SHARD_INDEX = "${{ matrix.shard }}"
CACHE_COMMON_PATHS = (
    "~/.cargo/registry",
    "~/.cargo/git",
    "~/.rustup/toolchains/1.95.0-*",
    "~/.rustup/update",
)
CACHE_TARGET_PATH = "target/ci-cargo"
CACHE_GATE_NAMES = ("fmt-deps", "clippy-target", "test-target", "test-shard")


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
    if path.name == "governance-admission.yml":
        if re.search(r"^concurrency:\s*$", text, re.MULTILINE):
            raise PolicyError(f"{path} must let every required admission CheckRun finish")
        return
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


def reusable_concurrency_key(
    check_prefix: str,
    workflow: str,
    *,
    pull_request_number: int | None = None,
    run_id: int | None = None,
) -> str:
    """Model the GitHub expression used by rust-reusable.yml for self-tests."""
    identity = pull_request_number if pull_request_number is not None else run_id
    if identity is None:
        raise ValueError("a pull request number or run id is required")
    return f"hartevo-rust-reusable-{check_prefix}-{workflow}-{identity}"


def validate_reusable_concurrency_contract(path: Path, text: str) -> None:
    if path.name != "rust-reusable.yml":
        return
    required = (
        "group: hartevo-rust-reusable-${{ inputs.check_prefix }}-${{ github.workflow }}-"
        "${{ github.event.pull_request.number || github.run_id }}",
        "cancel-in-progress: false",
    )
    if any(item not in text for item in required):
        raise PolicyError(f"{path} must isolate reusable concurrency by caller PR or run")


RUST_REUSABLE_CHECK_SUFFIXES = (
    "fmt",
    "clippy (ubuntu-24.04)",
    "clippy (macos-15)",
    "test shard 0 of 2 (ubuntu-24.04)",
    "test shard 1 of 2 (ubuntu-24.04)",
    "test (ubuntu-24.04)",
    "test (macos-15)",
)


def reusable_rust_scope_plan(
    check_prefix: str, run_rust: bool, run_macos: bool = True
) -> list[dict[str, object]]:
    """Model the stable child checks and their planned scope behavior for policy tests."""
    result: list[dict[str, object]] = []
    for suffix in RUST_REUSABLE_CHECK_SUFFIXES:
        macos_check = suffix.endswith("(macos-15)")
        executes_rust = run_rust and (not macos_check or run_macos)
        result.append(
            {
                "name": f"{check_prefix} / {suffix}",
                "plannedSkip": not executes_rust,
                "executesRust": executes_rust,
                "runner": "macos-15" if macos_check and run_macos else "ubuntu-24.04",
            }
        )
    return result


def validate_reusable_scope_contract_v2(path: Path, text: str) -> None:
    """Validate split common-Rust/desktop lanes while retaining old fixtures."""
    required = (
        "run_rust:\n",
        "run_common_rust:\n",
        "run_desktop:\n",
        "common_rust_packages:\n",
        "desktop_packages:\n",
        "name: ${{ inputs.check_prefix }} / fmt",
        "name: ${{ inputs.check_prefix }} / clippy (${{ matrix.os }})",
        "os: [ubuntu-24.04, macos-15]",
        "matrix.os == 'ubuntu-24.04' && inputs.run_common_rust",
        "matrix.os == 'macos-15' && inputs.run_desktop",
        "test-ubuntu-shards:",
        "shard: [0, 1]",
        "test-ubuntu-result:",
        "if: ${{ always() }}",
        "test-macos:",
        "runs-on: ${{ !inputs.run_desktop && 'ubuntu-24.04' || 'macos-15' }}",
        "Desktop scope is empty",
        "Common Rust scope is empty",
    )
    if any(item not in text for item in required):
        raise PolicyError(f"{path} is missing the split-lane Rust scope contract")
    if re.search(r"\$\{\{[^}\n]*\+[^}\n]*\}\}", text):
        raise PolicyError(f"{path} contains unsupported arithmetic in a GitHub Actions expression")
    if re.search(r"(?m)^  (?:fmt|clippy|test-ubuntu-shards|test-ubuntu-result|test-macos):\n    if:", text):
        raise PolicyError(f"{path} reusable Rust jobs must expose planned skips as steps, not job conditions")
    shard_match = re.search(r"(?ms)^  test-ubuntu-shards:.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)", text)
    if not shard_match:
        raise PolicyError(f"{path} is missing the common-Rust Ubuntu shard lane")
    if "hartevo-desktop" in shard_match.group(0):
        raise PolicyError(f"{path} Ubuntu test lane must not select hartevo-desktop")
    shard_text = shard_match.group(0)
    if "--full-workspace false" not in shard_text or "--packages \"$COMMON_PACKAGES\"" not in shard_text:
        raise PolicyError(f"{path} Ubuntu shards must use the common-Rust package selector")
    if "if: ${{ !inputs.run_common_rust }}" not in shard_text:
        raise PolicyError(f"{path} Ubuntu shards must expose a common-Rust planned skip")
    if "strategy:\n      fail-fast: false\n      max-parallel: 2\n      matrix:\n        shard: [0, 1]" not in shard_text:
        raise PolicyError(f"{path} Ubuntu shards must use the fixed two-way fail-closed layout")
    if any(token in shard_text for token in ("fromJSON", "include:", "exclude:", "continue-on-error", "nextest", "--ignored", "fail-fast: true")):
        raise PolicyError(f"{path} Ubuntu shards contain a dynamic or non-fail-closed execution path")
    result_match = re.search(r"(?ms)^  test-ubuntu-result:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)", text)
    if not result_match:
        raise PolicyError(f"{path} is missing the Ubuntu aggregate")
    result_text = result_match.group(0)
    if "needs: test-ubuntu-shards" not in result_text or "if: ${{ always() }}" not in result_text:
        raise PolicyError(f"{path} Ubuntu aggregate must always inspect shard results")
    if "needs.test-ubuntu-shards.result" not in result_text or "!= success" not in result_text or "exit 1" not in result_text:
        raise PolicyError(f"{path} Ubuntu aggregate must fail closed on shard failure")
    if "if: inputs.run_common_rust" not in result_text:
        raise PolicyError(f"{path} Ubuntu aggregate gate must be scoped to common Rust")
    if "name: Planned scope skip marker" not in result_text or "if: ${{ !inputs.run_common_rust }}" not in result_text:
        raise PolicyError(f"{path} Ubuntu aggregate must expose a planned common-Rust marker")
    macos_block = re.search(r"(?ms)^  test-macos:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)", text)
    if not macos_block:
        raise PolicyError(f"{path} is missing the macOS desktop lane")
    macos_text = macos_block.group(0)
    if "if: inputs.run_desktop" not in macos_text or "--packages \"$DESKTOP_PACKAGES\"" not in macos_text:
        raise PolicyError(f"{path} macOS lane must execute only the desktop package selector")
    if "if: ${{ !inputs.run_desktop }}" not in macos_text:
        raise PolicyError(f"{path} macOS lane must expose a desktop planned skip")


def validate_reusable_scope_contract(path: Path, text: str) -> None:
    if path.name != "rust-reusable.yml":
        return
    if "run_common_rust:\n" in text:
        validate_reusable_scope_contract_v2(path, text)
        return
    if re.search(r"\$\{\{[^}\n]*\+[^}\n]*\}\}", text):
        raise PolicyError(f"{path} contains unsupported arithmetic in a GitHub Actions expression")
    required = (
        "run_rust:\n",
        "run_macos:\n",
        "type: boolean",
        "name: ${{ inputs.check_prefix }} / fmt",
        "name: ${{ inputs.check_prefix }} / clippy (${{ matrix.os }})",
        "os: [ubuntu-24.04, macos-15]",
        "test-ubuntu-shards:",
        "name: ${{ inputs.check_prefix }} / test shard ${{ matrix.shard }} of 2 (ubuntu-24.04)",
        "shard: [0, 1]",
        "fail-fast: false",
        "max-parallel: 2",
        "test-ubuntu-result:",
        "name: ${{ inputs.check_prefix }} / test (ubuntu-24.04)",
        "needs: test-ubuntu-shards",
        "if: ${{ always() }}",
        "test-macos:",
        "name: ${{ inputs.check_prefix }} / test (macos-15)",
        "name: Planned scope skip marker",
        "runs-on: ${{ matrix.os == 'macos-15' && !inputs.run_macos && 'ubuntu-24.04' || matrix.os }}",
        "runs-on: ${{ !inputs.run_macos && 'ubuntu-24.04' || 'macos-15' }}",
    )
    required = tuple(item.replace("${{", "$" + "{{") for item in required)
    github_expression = "$" + "{{"
    if any(item not in text for item in required):
        raise PolicyError(f"{path} is missing the scope-aware stable Rust check contract")
    gate_path = next(
        (
            candidate
            for candidate in (
                path.parent / "scripts/ci-rust-gate.sh",
                path.parent.parent / "scripts/ci-rust-gate.sh",
                path.parent.parent.parent / "scripts/ci-rust-gate.sh",
            )
            if candidate.is_file()
        ),
        path.parent / "scripts/ci-rust-gate.sh",
    )
    try:
        gate_text = gate_path.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyError(f"{path} cannot read the canonical Rust gate: {error}") from error
    for gate_contract in (
        "cargo test --workspace --all-targets --all-features --locked",
        'cargo_args+=("-p" "$package")',
        'cargo_args+=("--all-targets" "--all-features" "--locked")',
        "python3 \"$planner\" verify",
    ):
        if gate_contract not in gate_text:
            raise PolicyError(f"{path} Rust gate is missing {gate_contract}")
    heavy_steps = (
        "Checkout reviewed source",
        "Install Ubuntu desktop development libraries",
        "Cache Cargo and Rust toolchain",
        "Install the locked Rust components",
        "Format gate",
        "Strict Clippy gate",
    )
    for job_name in ("fmt", "clippy"):
        match = re.search(
            rf"(?ms)^  {re.escape(job_name)}:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
            text,
        )
        if not match:
            raise PolicyError(f"{path} is missing reusable Rust job {job_name}")
        block = match.group(0)
        header = block.split("    steps:", 1)[0]
        if re.search(r"^    if:.*inputs\.run_rust", header, re.MULTILINE):
            raise PolicyError(f"{path} {job_name} must not use a job-level run_rust condition")
        if "name: Planned scope skip marker" not in block:
            raise PolicyError(f"{path} {job_name} is missing the planned scope marker")
        marker = re.search(
            r"(?ms)^      - name: Planned scope skip marker\s*\n.*?(?=^      - name:|\Z)",
            block,
        )
        marker_condition = (
            r"!inputs\.run_rust"
            if job_name == "fmt"
            else r"!inputs\.run_rust\s*\|\|\s*\(matrix\.os\s*==\s*'macos-15'\s*&&\s*!inputs\.run_macos\)"
        )
        if not marker or not re.search(
            rf"^        if:\s*\$\{{\{{\s*{marker_condition}\s*\}}\}}\s*$",
            marker.group(0),
            re.MULTILINE,
        ):
            raise PolicyError(f"{path} {job_name} marker must cover its planned runner path")
        for step_name in heavy_steps:
            step = re.search(
                rf"(?ms)^      - name: {re.escape(step_name)}\s*\n.*?(?=^      - name:|\Z)",
                block,
            )
            if not step or not re.search(r"^        if:\s*(?:\$\{\{\s*)?inputs\.run_rust\b", step.group(0), re.MULTILINE):
                # A job only owns one gate step; the other gate names are checked
                # in their owning job below.
                if step_name in {
                    "Format gate" if job_name == "fmt" else "Strict Clippy gate" if job_name == "clippy" else "Locked Rust test gate"
                } or step_name in {"Checkout reviewed source", "Cache Cargo and Rust toolchain", "Install the locked Rust components"}:
                    raise PolicyError(f"{path} {job_name} heavy step is not guarded by inputs.run_rust: {step_name}")
        if job_name == "clippy" and any(item not in block for item in ("strategy:", "matrix:", "os: [ubuntu-24.04, macos-15]")):
            raise PolicyError(f"{path} {job_name} must retain the two-platform matrix")
        if job_name == "clippy" and "!inputs.run_macos && 'ubuntu-24.04' || matrix.os" not in block:
            raise PolicyError(f"{path} {job_name} must map planned macOS contexts onto Ubuntu")

    shard_match = re.search(
        r"(?ms)^  test-ubuntu-shards:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
        text,
    )
    if not shard_match:
        raise PolicyError(f"{path} is missing the deterministic Ubuntu shard job")
    shard_block = shard_match.group(0)
    shard_header = shard_block.split("    steps:", 1)[0]
    if re.search(r"^    if:", shard_header, re.MULTILINE):
        raise PolicyError(f"{path} Ubuntu shards must not use a job-level condition")
    if any(token in shard_block for token in ("fromJSON", "include:", "exclude:", "continue-on-error", "nextest", "fail-fast: true", "--ignored")):
        raise PolicyError(f"{path} Ubuntu shards must use fixed, fail-closed execution")
    if "strategy:\n      fail-fast: false\n      max-parallel: 2\n      matrix:\n        shard: [0, 1]" not in shard_header:
        raise PolicyError(f"{path} Ubuntu shards must use literal [0, 1], fail-fast false and max-parallel 2")
    if "runs-on: ubuntu-24.04" not in shard_header:
        raise PolicyError(f"{path} Ubuntu shards must use the fixed Ubuntu runner")
    marker = re.search(
        r"(?ms)^      - name: Planned scope skip marker\s*\n.*?(?=^      - name:|\Z)",
        shard_block,
    )
    if not marker or ("if: " + github_expression + " !inputs.run_rust }}") not in marker.group(0):
        raise PolicyError(f"{path} Ubuntu shards are missing the planned scope marker")
    for required_step in (
        "python3 scripts/ci-rust-test-shards.py plan",
        "python3 scripts/ci-rust-test-shards.py verify",
        "--shard-count 2",
        "ci-rust-gate.sh test --plan",
        "all-targets-all-features",
    ):
        if required_step not in shard_block:
            raise PolicyError(f"{path} Ubuntu shards are missing {required_step}")

    result_match = re.search(
        r"(?ms)^  test-ubuntu-result:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
        text,
    )
    if not result_match:
        raise PolicyError(f"{path} is missing the stable Ubuntu aggregate job")
    result_block = result_match.group(0)
    if "needs: test-ubuntu-shards" not in result_block or ("if: " + github_expression + " always() }}") not in result_block:
        raise PolicyError(f"{path} Ubuntu aggregate must always evaluate its shard dependency")
    if "needs.test-ubuntu-shards.result" not in result_block or "!= success" not in result_block or "exit 1" not in result_block:
        raise PolicyError(f"{path} Ubuntu aggregate must accept only a successful shard dependency")
    result_marker = re.search(
        r"(?ms)^      - name: Planned scope skip marker\s*\n.*?(?=^      - name:|\Z)",
        result_block,
    )
    if not result_marker or ("if: " + github_expression + " !inputs.run_rust }}") not in result_marker.group(0):
        raise PolicyError(f"{path} Ubuntu aggregate must expose a planned Rust-scope marker")
    result_gate = re.search(
        r"(?ms)^      - name: Require successful Ubuntu shards\s*\n.*?(?=^      - name:|\Z)",
        result_block,
    )
    if not result_gate or not re.search(r"^        if:\s*inputs\.run_rust\s*$", result_gate.group(0), re.MULTILINE):
        raise PolicyError(f"{path} Ubuntu aggregate shard gate must run only for Rust scope")
    if re.search(r"actions/checkout@|actions/cache@|\b(?:curl|wget)\b|https?://", result_block, re.IGNORECASE):
        raise PolicyError(f"{path} Ubuntu aggregate must be local and side-effect free")

    macos_match = re.search(
        r"(?ms)^  test-macos:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
        text,
    )
    if not macos_match:
        raise PolicyError(f"{path} is missing the real macOS test lane")
    macos_block = macos_match.group(0)
    if ("if: " + github_expression + " !inputs.run_rust || !inputs.run_macos }}") not in macos_block:
        raise PolicyError(f"{path} macOS lane is missing its planned-skip contract")
    if "if: inputs.run_rust && inputs.run_macos" not in macos_block:
        raise PolicyError(f"{path} macOS execution must remain gated to full callers")
    if "bash scripts/ci-rust-gate.sh test --full" not in macos_block:
        raise PolicyError(f"{path} macOS lane must retain the full-workspace test command")


def reusable_cache_job_block(text: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
        text,
    )
    if not match:
        raise PolicyError(f"rust-reusable.yml is missing cache job {job_name}")
    return match.group(0)


def reusable_cache_steps(job_block: str) -> list[str]:
    return re.findall(r"(?ms)^      - name:.*?(?=^      - name:|\Z)", job_block)


def reusable_cache_multiline_field(step: str, field: str) -> list[str]:
    field_lines = [
        index
        for index, line in enumerate(step.splitlines())
        if re.fullmatch(rf" {{10}}{re.escape(field)}:\s*\|\s*", line)
    ]
    if len(field_lines) != 1:
        raise PolicyError(f"cache step must contain exactly one multiline {field} field")
    lines = step.splitlines()
    start = field_lines[0]
    values: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() and indent(line) <= 10:
            break
        if line.strip():
            values.append(line.strip())
    return values


def reusable_cache_scalar_field(step: str, field: str) -> str:
    matches = re.findall(rf"^ {{10}}{re.escape(field)}:\s*(\S.*)$", step, re.MULTILINE)
    if len(matches) != 1:
        raise PolicyError(f"cache step must contain exactly one scalar {field} field")
    return matches[0].strip()


def reusable_cache_key_prefix(gate: str, *, include_full_workspace: bool) -> str:
    parts = [
        CACHE_EPOCH,
        CACHE_RUNNER_OS,
        CACHE_RUNNER_ARCH,
        "rust-1.95.0",
        gate,
        CACHE_MODE,
        CACHE_LOCK_DIGEST,
    ]
    if include_full_workspace:
        parts.append(CACHE_FULL_WORKSPACE)
    return "-".join(parts)


def reusable_cache_primary_key(gate: str) -> str:
    return "-".join(
        (
            reusable_cache_key_prefix(gate, include_full_workspace=True),
            CACHE_GITHUB_SHA,
            CACHE_GITHUB_RUN_ID,
            CACHE_GITHUB_RUN_ATTEMPT,
        )
    )


def reusable_cache_restore_prefixes(gate: str) -> list[str]:
    return [
        reusable_cache_key_prefix(gate, include_full_workspace=True) + "-",
        reusable_cache_key_prefix(gate, include_full_workspace=False) + "-",
        "-".join(
            (
                CACHE_EPOCH,
                CACHE_RUNNER_OS,
                CACHE_RUNNER_ARCH,
                "rust-1.95.0",
                gate,
                CACHE_MODE,
            )
        )
        + "-",
    ]


def reusable_cache_restore_block(gate: str) -> str:
    return "\n".join(
        [
            "          restore-keys: |",
            *[f"            {prefix}" for prefix in reusable_cache_restore_prefixes(gate)],
        ]
    )


def reusable_shard_cache_key_prefix(*, include_lock: bool, include_full_workspace: bool) -> str:
    parts = [
        "hartevo-rust-cache-v3",
        CACHE_RUNNER_OS,
        CACHE_RUNNER_ARCH,
        "rust-1.95.0",
        "test-shard",
        CACHE_SHARD_INDEX,
        "layout",
        CACHE_SHARD_LAYOUT_DIGEST,
        CACHE_MODE,
    ]
    if include_lock:
        parts.append(CACHE_LOCK_DIGEST)
    if include_full_workspace:
        parts.append(CACHE_FULL_WORKSPACE)
    return "-".join(parts)


def reusable_shard_cache_primary_key() -> str:
    return "-".join(
        (
            reusable_shard_cache_key_prefix(include_lock=True, include_full_workspace=True),
            CACHE_GITHUB_SHA,
            CACHE_GITHUB_RUN_ID,
            CACHE_GITHUB_RUN_ATTEMPT,
        )
    )


def reusable_shard_cache_restore_prefixes() -> list[str]:
    return [
        reusable_shard_cache_key_prefix(include_lock=True, include_full_workspace=True) + "-",
        reusable_shard_cache_key_prefix(include_lock=True, include_full_workspace=False) + "-",
        reusable_shard_cache_key_prefix(include_lock=False, include_full_workspace=False) + "-",
    ]


def reusable_shard_cache_restore_block() -> str:
    return "\n".join(
        [
            "          restore-keys: |",
            *[f"            {prefix}" for prefix in reusable_shard_cache_restore_prefixes()],
        ]
    )


def validate_reusable_cache_contract_v2(path: Path, text: str) -> None:
    """Ensure split lanes retain isolated, run-unique Cargo caches."""
    if len(re.findall(r"^\s+uses:\s*actions/cache@", text, re.MULTILINE)) != 4:
        raise PolicyError(f"{path} must contain exactly one cache step per Rust execution lane")
    if re.search(r"cache-hit", text, re.IGNORECASE):
        raise PolicyError(f"{path} must not use cache-hit to control required gates")
    if text.count("actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9") != 4:
        raise PolicyError(f"{path} cache actions must use the verified SHA")
    for cache in re.finditer(r"(?ms)^      - name: Cache Cargo and Rust toolchain\s*\n.*?(?=^      - name:|\Z)", text):
        block = cache.group(0)
        if "enableCrossOsArchive: false" not in block:
            raise PolicyError(f"{path} cache must disable cross-OS archives")
        if "${{ runner.os }}" not in block or "${{ runner.arch }}" not in block:
            raise PolicyError(f"{path} cache must be runner-scoped")
        if "${{ github.sha }}" not in block or "${{ github.run_id }}" not in block or "${{ github.run_attempt }}" not in block:
            raise PolicyError(f"{path} primary cache key must include run identity")
        if "restore-keys: |" not in block:
            raise PolicyError(f"{path} cache must provide restore prefixes")
        if "fmt-deps" in block:
            if "target/ci-cargo" in block:
                raise PolicyError(f"{path} format cache must not contain build targets")
        elif "target/ci-cargo" not in block:
            raise PolicyError(f"{path} executable build cache must contain target/ci-cargo")
    cache_keys = re.findall(r"^          key: (.+)$", text, re.MULTILINE)
    if len(cache_keys) != 4 or len(cache_keys) != len(set(cache_keys)):
        raise PolicyError(f"{path} cache primary keys must be unique")
    if sum("fmt-deps" in key for key in cache_keys) != 1:
        raise PolicyError(f"{path} must keep one format cache namespace")
    if sum("clippy-target" in key for key in cache_keys) != 1:
        raise PolicyError(f"{path} must keep one common/desktop clippy cache namespace")
    if sum("test-shard" in key for key in cache_keys) != 1:
        raise PolicyError(f"{path} must keep one Ubuntu shard cache namespace")
    if sum("test-target" in key for key in cache_keys) != 1:
        raise PolicyError(f"{path} must keep one desktop test cache namespace")
    for restore in re.findall(r"(?ms)^          restore-keys: \|\n.*?(?=^      - name:|\Z)", text):
        if "${{ runner.os }}" not in restore or "${{ runner.arch }}" not in restore:
            raise PolicyError(f"{path} cache restore prefixes must be runner-scoped")
        if any(identity in restore for identity in ("${{ github.sha }}", "${{ github.run_id }}", "${{ github.run_attempt }}")):
            raise PolicyError(f"{path} cache restore prefixes must not contain run identity")
    for gate in ("fmt-deps", "clippy-target", "test-target"):
        cache = next((block for block in re.finditer(r"(?ms)^      - name: Cache Cargo and Rust toolchain\s*\n.*?(?=^      - name:|\Z)", text) if gate in block.group(0)), None)
        if cache is None:
            raise PolicyError(f"{path} is missing the {gate} cache")
        restore_lines = re.search(r"(?ms)^          restore-keys: \|\n(.*?)(?=^      - name:|\Z)", cache.group(0))
        if restore_lines is None:
            raise PolicyError(f"{path} {gate} cache has no restore prefixes")
        actual = [line.strip() for line in restore_lines.group(1).splitlines() if line.strip()]
        if actual != reusable_cache_restore_prefixes(gate):
            raise PolicyError(f"{path} {gate} cache restore prefixes are missing, unsafe, or out of order")
    shard_cache = next((block for block in re.finditer(r"(?ms)^      - name: Cache Cargo and Rust toolchain\s*\n.*?(?=^      - name:|\Z)", text) if "test-shard" in block.group(0)), None)
    if shard_cache is None:
        raise PolicyError(f"{path} is missing the Ubuntu shard cache")
    shard_text = shard_cache.group(0)
    shard_key = re.search(r"^          key: (.+)$", shard_text, re.MULTILINE)
    if shard_key is None or reusable_shard_cache_primary_key() != shard_key.group(1).strip():
        raise PolicyError(f"{path} Ubuntu shard cache key is missing shard/layout/lock/run identity")
    shard_restore = re.search(r"(?ms)^          restore-keys: \|\n(.*?)(?=^      - name:|\Z)", shard_text)
    if shard_restore is None or [line.strip() for line in shard_restore.group(1).splitlines() if line.strip()] != reusable_shard_cache_restore_prefixes():
        raise PolicyError(f"{path} Ubuntu shard restore prefixes are missing, unsafe, or out of order")
    if "if: inputs.run_common_rust && steps.shard-plan.outputs.has_packages == 'true'" not in shard_text:
        raise PolicyError(f"{path} empty Ubuntu shards must not restore or save a cache")
    shard_match = re.search(r"(?ms)^  test-ubuntu-shards:\s*\n.*?(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)", text)
    if not shard_match or "${{ matrix.shard }}" not in shard_match.group(0):
        raise PolicyError(f"{path} Ubuntu cache must be shard-scoped")


def validate_reusable_cache_contract(path: Path, text: str) -> None:
    if path.name != "rust-reusable.yml":
        return
    if "run_common_rust:\n" in text:
        validate_reusable_cache_contract_v2(path, text)
        return

    if len(re.findall(r"^\s+uses:\s*actions/cache@", text, re.MULTILINE)) != 4:
        raise PolicyError(f"{path} must contain exactly one cache step per Rust execution lane")
    if re.search(r"cache-hit", text, re.IGNORECASE):
        raise PolicyError(f"{path} must not use cache-hit to control required gates")

    expected = {
        "fmt": {
            "gate": "fmt-deps",
            "paths": CACHE_COMMON_PATHS,
            "condition": "inputs.run_rust",
        },
        "clippy": {
            "gate": "clippy-target",
            "paths": CACHE_COMMON_PATHS + (CACHE_TARGET_PATH,),
            "condition": "inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)",
        },
        "test-macos": {
            "gate": "test-target",
            "paths": CACHE_COMMON_PATHS + (CACHE_TARGET_PATH,),
            "condition": "inputs.run_rust && inputs.run_macos",
        },
    }
    primary_keys: list[str] = []
    for job_name, contract in expected.items():
        job_block = reusable_cache_job_block(text, job_name)
        cache_steps = [
            step
            for step in reusable_cache_steps(job_block)
            if re.search(r"^\s+uses:\s*actions/cache@", step, re.MULTILINE)
        ]
        if len(cache_steps) != 1:
            raise PolicyError(f"{path} {job_name} must have exactly one executable cache step")
        cache_step = cache_steps[0]
        action = re.search(r"^\s+uses:\s*([^\s#]+)", cache_step, re.MULTILINE)
        if not action or action.group(1) != CACHE_ACTION_REF:
            raise PolicyError(f"{path} {job_name} must retain the verified actions/cache SHA")
        if f"        if: {contract['condition']}" not in cache_step:
            raise PolicyError(f"{path} {job_name} cache step must follow its executable gate condition")
        if reusable_cache_scalar_field(cache_step, "enableCrossOsArchive") != "false":
            raise PolicyError(f"{path} {job_name} must explicitly disable cross-OS archives")

        paths = tuple(reusable_cache_multiline_field(cache_step, "path"))
        if any(re.search(r"secret|receipt|evidence|runtime|user(?:[-_ ]data)?", item, re.IGNORECASE) for item in paths):
            raise PolicyError(f"{path} {job_name} cache paths contain sensitive or runtime data")
        if paths != contract["paths"]:
            raise PolicyError(f"{path} {job_name} cache paths do not match the gate contract")

        key = reusable_cache_scalar_field(cache_step, "key")
        expected_key = reusable_cache_primary_key(contract["gate"])
        if key != expected_key:
            raise PolicyError(f"{path} {job_name} primary cache key is not gate-scoped and run-unique")
        primary_keys.append(key)

        restore_keys = reusable_cache_multiline_field(cache_step, "restore-keys")
        expected_restore_keys = reusable_cache_restore_prefixes(contract["gate"])
        if restore_keys != expected_restore_keys:
            raise PolicyError(f"{path} {job_name} restore prefixes are missing, unsafe, or out of order")
        if any(identity in item for identity in (CACHE_GITHUB_SHA, CACHE_GITHUB_RUN_ID, CACHE_GITHUB_RUN_ATTEMPT) for item in restore_keys):
            raise PolicyError(f"{path} {job_name} restore prefixes must not include run identity")
        for other_gate in CACHE_GATE_NAMES:
            if other_gate != contract["gate"] and (other_gate in key or any(other_gate in item for item in restore_keys)):
                raise PolicyError(f"{path} {job_name} cache namespace crosses gates")

    shard_block = reusable_cache_job_block(text, "test-ubuntu-shards")
    shard_cache_steps = [
        step
        for step in reusable_cache_steps(shard_block)
        if re.search(r"^\s+uses:\s*actions/cache@", step, re.MULTILINE)
    ]
    if len(shard_cache_steps) != 1:
        raise PolicyError(f"{path} Ubuntu shards must have exactly one executable cache step")
    shard_cache_step = shard_cache_steps[0]
    shard_action = re.search(r"^\s+uses:\s*([^\s#]+)", shard_cache_step, re.MULTILINE)
    if not shard_action or shard_action.group(1) != CACHE_ACTION_REF:
        raise PolicyError(f"{path} Ubuntu shard cache must retain the verified actions/cache SHA")
    if "        if: inputs.run_rust && steps.shard-plan.outputs.has_packages == 'true'" not in shard_cache_step:
        raise PolicyError(f"{path} empty Ubuntu shards must not restore or save a cache")
    if reusable_cache_scalar_field(shard_cache_step, "enableCrossOsArchive") != "false":
        raise PolicyError(f"{path} Ubuntu shard cache must explicitly disable cross-OS archives")
    shard_paths = tuple(reusable_cache_multiline_field(shard_cache_step, "path"))
    if shard_paths != CACHE_COMMON_PATHS + (CACHE_TARGET_PATH,):
        raise PolicyError(f"{path} Ubuntu shard cache paths do not match the gate contract")
    if any(re.search(r"secret|receipt|evidence|runtime|user(?:[-_ ]data)?", item, re.IGNORECASE) for item in shard_paths):
        raise PolicyError(f"{path} Ubuntu shard cache paths contain sensitive or runtime data")
    shard_key = reusable_cache_scalar_field(shard_cache_step, "key")
    if shard_key != reusable_shard_cache_primary_key():
        raise PolicyError(f"{path} Ubuntu shard cache key must include shard, layout, lock and run identity")
    shard_restore_keys = reusable_cache_multiline_field(shard_cache_step, "restore-keys")
    if shard_restore_keys != reusable_shard_cache_restore_prefixes():
        raise PolicyError(f"{path} Ubuntu shard restore prefixes are missing, unsafe, or out of order")
    if any(identity in item for identity in (CACHE_GITHUB_SHA, CACHE_GITHUB_RUN_ID, CACHE_GITHUB_RUN_ATTEMPT) for item in shard_restore_keys):
        raise PolicyError(f"{path} Ubuntu shard restore prefixes must not include run identity")
    for required_identity in (CACHE_SHARD_INDEX, CACHE_SHARD_LAYOUT_DIGEST, CACHE_RUNNER_OS, CACHE_RUNNER_ARCH, CACHE_MODE):
        if required_identity not in shard_key or any(required_identity not in item for item in shard_restore_keys):
            raise PolicyError(f"{path} Ubuntu shard cache namespace is missing {required_identity}")
    for forbidden in ("test-target", "fmt-deps", "clippy-target"):
        if forbidden in shard_key or any(forbidden in item for item in shard_restore_keys):
            raise PolicyError(f"{path} Ubuntu shard cache namespace crosses another gate")
    primary_keys.append(shard_key)

    if len(primary_keys) != len(set(primary_keys)):
        raise PolicyError(f"{path} Rust gates must not share primary cache keys")


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
    if "workflow_run:" in text:
        raise PolicyError(f"{path} uses a privileged workflow_run event path")
    if "pull_request_target" in text:
        if path.name != "governance-admission.yml":
            raise PolicyError(f"{path} uses an unauthorized pull_request_target event path")
        required = (
            "ref: ${{ github.event.pull_request.base.sha }}",
            "persist-credentials: false",
            "git fetch --no-tags --no-write-fetch-head origin \"$HEAD_SHA\"",
            "--trusted-base",
            "pull_request_review:",
            "statuses: write",
            "Mark exact head admission pending",
            "name: Governance / PR admission",
            "STATUS_CONTEXT: Governance / PR admission",
            "statuses/$HEAD_SHA",
            "Fence stale exact-head controller run",
            "Recheck exact-head controller freshness",
            "admission-run-fence",
            "classify-pr-event",
            "Capture read-only exact-head GitHub review evidence",
            "pulls/$PR_NUMBER/reviews",
            "--github-reviews",
        )
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing the non-executing trusted-base admission contract")
        if text.index("Mark exact head admission pending") > text.index("Checkout trusted protected governance policy"):
            raise PolicyError(f"{path} must publish pending before checkout or verification")
        if "cancel-in-progress" in text:
            raise PolicyError(f"{path} must not cancel same-head required controller CheckRuns")
        if 'test "$CLASSIFICATION" != INVALID' in text:
            raise PolicyError(f"{path} invalid facts must use the replaceable status, not a sticky failed CheckRun")
        write_permissions = set(re.findall(r"^\s+([a-z-]+):\s*write\s*$", text, re.MULTILINE))
        if write_permissions != {"statuses"}:
            raise PolicyError(f"{path} may write only exact-head commit statuses")
        if re.search(r"\bsecrets\b|secrets\.", text):
            raise PolicyError(f"{path} exposes secrets to a privileged PR event")
    if "pull_request:" in text or "pull_request_review:" in text:
        if re.search(r"\bsecrets\b|secrets\.", text):
            raise PolicyError(f"{path} exposes secrets to an untrusted PR event")


def validate_dependency_audit_contract(path: Path, text: str) -> None:
    """Keep Cargo lock validation separate from cargo-audit's own CLI flags."""
    if path.name != "integration.yml":
        return
    if re.search(r"^\s*(?:run:\s*)?cargo\s+audit\b[^\n]*--locked\b", text, re.MULTILINE):
        raise PolicyError(f"{path} passes unsupported --locked to cargo audit")
    required = (
        "test -s Cargo.lock",
        "cargo metadata --format-version 1 --locked",
        "cargo audit --json",
    )
    if any(item not in text for item in required):
        raise PolicyError(f"{path} is missing the locked dependency audit contract")


def validate_dioxus_artifact_contract(path: Path, text: str) -> None:
    if path.name != "integration.yml":
        return
    required = (
        "CARGO_TARGET_DIR: target/ci-cargo",
        "bash scripts/check-dioxus-toolchain.sh self-test",
        "bash scripts/check-dioxus-toolchain.sh build",
        "bash scripts/check-dioxus-toolchain.sh verify-receipt",
    )
    if any(item not in text for item in required):
        raise PolicyError(f"{path} is missing the explicit Dioxus target/artifact contract")


def validate_required_workflow_contract(path: Path, text: str) -> None:
    if path.name == "ci.yml":
        required = (
            "pull_request:",
            "merge_group:",
            "startsWith(github.head_ref, 'merge-train/')",
            "ref: ${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}",
            "scripts/ci-scope.py",
            "rust-reusable.yml",
            "run_rust: ${{ needs.scope.outputs.rust == 'true' }}",
            "run_common_rust: ${{ needs.scope.outputs.common_rust == 'true' }}",
            "run_desktop: ${{ needs.scope.outputs.desktop == 'true' }}",
            "common_rust_packages",
            "desktop_packages",
            "dependency_only",
            "dependency-cordis-smoke",
            "dependency-desktop-smoke",
            "needs.scope.outputs.dependency_only != 'true' && 'ubuntu-24.04' || 'macos-15'",
            "cargo test -p hartevo-cordis --locked --lib",
            "cargo test -p hartevo-desktop --locked --lib",
            "--planned-scope common-rust",
            "--planned-scope desktop",
            "--planned-scope dependency",
            "--planned-job-name",
            "scripts/ci-workflow-policy.py",
            "scripts/repository_governance.py verify-repository",
            "scripts/repository_governance.py verify-pr-event",
            "scripts/ci-result.py",
            "PR / Result taxonomy",
        )
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing a required fast-PR contract")
        if re.search(r"^\s+if:\s+needs\.scope\.outputs\.rust\s*==\s*['\"]true['\"]\s*$", text, re.MULTILINE):
            raise PolicyError(f"{path} must always call the reusable Rust workflow")
        if "ready_for_review" in text:
            raise PolicyError(f"{path} must reuse same-SHA checks when a Draft becomes ready")
        if "branches: [main]" in text or "branches: [bootstrap/macos-r0]" in text:
            raise PolicyError(f"{path} must not run the integration push tier")
    elif path.name == "integration.yml":
        required = ("bootstrap/macos-r0", "workflow_dispatch:", "schedule:", "Verify recoverable direct PR or exact train merge", "ci-merge-train.py verify-bootstrap-push", "run_rust: true", "run_common_rust: true", "run_desktop: true", "HARTEVO_TEST_POSTGRES_URL", "postgres:18.4", "check-evidence-doc-truth.sh", "check-openinterpreter-schema.sh", "check-dioxus-toolchain.sh", "catalog export", "evidence baseline", "Integration / Result taxonomy")
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing a required integration contract")
        if "pull_request_review:" in text:
            raise PolicyError(f"{path} must not run the full Integration matrix on review events")
        validate_dependency_audit_contract(path, text)
        validate_dioxus_artifact_contract(path, text)
    elif path.name == "governance.yml":
        required = (
            "workflow_dispatch:",
            "schedule:",
            "*/5 * * * *",
            "hartevo-repository-governance-inventory",
            "repository_governance.py verify-repository",
            "repository_governance.py snapshot",
            "repository_governance.py plan",
            "ci-branch-policy.py probe",
            "READY_TO_TRAIN_SLA_BREACH",
            "manualCountsAccepted",
            "DISABLED_WITHOUT_EXACT_APPROVAL",
            "governance-inventory-${{ github.run_id }}",
        )
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing the read-only governance inventory contract")
        if re.search(r"\b(contents|issues|pull-requests):\s*write\b", text):
            raise PolicyError(f"{path} governance inventory workflow must remain read-only")
    elif path.name == "governance-admission.yml":
        required = (
            "pull_request_target:",
            "pull_request_review:",
            "name: Governance / PR admission",
            "Mark exact head admission pending",
            "Fence stale exact-head controller run",
            "Recheck exact-head controller freshness",
            "commits/$HEAD_SHA/statuses?per_page=100",
            "steps.final-fence.outputs.current == 'true'",
            "repository_governance.py admission-run-fence",
            "WAITING_REVIEW",
            "statuses: write",
            "statuses/$HEAD_SHA",
            "github.event.pull_request.base.sha",
            "github.event.pull_request.head.sha",
            "github.token",
            "pulls/$PR_NUMBER/reviews",
            "github-reviews.json",
            "repository_governance.py classify-pr-event",
            "--trusted-base",
            "--github-reviews",
        )
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing the trusted governance admission contract")
        if re.search(r"\b(contents|issues|pull-requests):\s*write\b", text):
            raise PolicyError(f"{path} trusted admission may not mutate repository or pull-request content")
    elif path.name == "release-promotion.yml":
        required = ("workflow_dispatch:", "environment: release-promotion", "id-token: write", "source_commit", "refs/heads/main", "release-baseline", "releaseCommit", "passed", "sha256", "rollback", "release: false", "ci-distribution-hook.sh", "ci-oidc-interface")
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing a release fence")
        forbidden_deploy = ("kubectl apply", "helm upgrade", "aws deploy", "vercel --prod", "gh release create")
        if any(item in text for item in forbidden_deploy):
            raise PolicyError(f"{path} contains a deployment or tag-mutation command")
    elif path.name == "rust-reusable.yml":
        required = (
            "workflow_call:",
            "inputs:",
            "check_prefix",
            "run_common_rust",
            "run_desktop",
            "common_rust_packages",
            "desktop_packages",
            "ci-rust-gate.sh",
            "ci-rust-test-shards.py",
            "test-ubuntu-shards",
            "test-ubuntu-result",
            "test-macos",
            "always()",
            "all-targets",
            "all-features",
            "--locked",
            "Desktop scope is empty",
            "Common Rust scope is empty",
            "matrix.os == 'ubuntu-24.04' && inputs.run_common_rust",
            "matrix.os == 'macos-15' && inputs.run_desktop",
        )
        if any(item not in text for item in required):
            raise PolicyError(f"{path} is missing the reusable Rust gate contract")
        validate_reusable_concurrency_contract(path, text)
        validate_reusable_scope_contract(path, text)
        validate_reusable_cache_contract(path, text)


def verify(root: Path) -> dict[str, object]:
    pins = action_pin_map(root)
    files = workflow_files(root)
    if {path.name for path in files} != {"ci.yml", "governance-admission.yml", "governance.yml", "integration.yml", "release-promotion.yml", "rust-reusable.yml"}:
        raise PolicyError("workflow set must be exactly the PR, trusted admission, governance, integration, release, and reusable workflows")
    if not (root / "scripts/ci-merge-train.py").is_file():
        raise PolicyError("repository merge-train verifier is missing")
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
    if branch_policy.get("hostedEnforcement") not in {"desired_active_not_yet_applied", "active"}:
        raise PolicyError("branch policy must remain desired-active or actively enforced")
    hosted_enforcement = branch_policy["hostedEnforcement"]
    return {
        "schema": "hartevo-ci-workflow-policy/v1",
        "status": "PASS",
        "workflowCount": len(files),
        "externalActionCount": len(all_actions),
        "actionPinsVerified": sorted(set(all_actions)),
        "hostedBranchEnforcement": "ACTIVE" if hosted_enforcement == "active" else "DESIRED_ACTIVE",
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

    validate_concurrency(Path("governance-admission.yml"), "name: trusted admission\n")
    try:
        validate_concurrency(
            Path("governance-admission.yml"),
            "concurrency:\n  group: admission\n  cancel-in-progress: false\n",
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted cancellation-prone admission concurrency")

    ci_fixture = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
    validate_required_workflow_contract(Path("ci.yml"), ci_fixture)
    try:
        validate_required_workflow_contract(
            Path("ci.yml"), ci_fixture.replace("types: [opened, synchronize, reopened]", "types: [opened, synchronize, reopened, ready_for_review]")
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a duplicate same-SHA ready-for-review run")

    reusable_fixture = """\
concurrency:
  group: hartevo-rust-reusable-${{ inputs.check_prefix }}-${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
  cancel-in-progress: false
"""
    validate_reusable_concurrency_contract(Path("rust-reusable.yml"), reusable_fixture)
    pr_one_key = reusable_concurrency_key("PR / Fast Rust", "Reusable / Rust gates", pull_request_number=203)
    pr_one_again_key = reusable_concurrency_key("PR / Fast Rust", "Reusable / Rust gates", pull_request_number=203)
    pr_two_key = reusable_concurrency_key("PR / Fast Rust", "Reusable / Rust gates", pull_request_number=204)
    assert pr_one_key == pr_one_again_key, "same PR must use one reusable concurrency key"
    assert pr_one_key != pr_two_key, "different PRs must use different reusable concurrency keys"
    assert reusable_concurrency_key("Integration / Full Rust", "Reusable / Rust gates", run_id=301) != reusable_concurrency_key(
        "Integration / Full Rust", "Reusable / Rust gates", run_id=302
    ), "non-PR runs must use distinct run-id fallback keys"
    try:
        validate_reusable_concurrency_contract(
            Path("rust-reusable.yml"), reusable_fixture.replace("github.event.pull_request.number || github.run_id", "github.workflow")
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a shared reusable concurrency key")

    scope_fixture = """\
on:
  workflow_call:
    inputs:
      run_rust:
        description: Scope gate
        required: true
        type: boolean
      run_macos:
        description: macOS gate
        required: true
        type: boolean
jobs:
  fmt:
    name: ${{ inputs.check_prefix }} / fmt
    steps:
      - name: Planned scope skip marker
        if: ${{ !inputs.run_rust }}
        run: echo planned
      - name: Checkout reviewed source
        if: inputs.run_rust
        uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Cache Cargo and Rust toolchain
        if: inputs.run_rust
        uses: actions/cache@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Install the locked Rust components
        if: inputs.run_rust
        run: rustup component add clippy
      - name: Format gate
        if: inputs.run_rust
        run: cargo fmt --all -- --check
  clippy:
    name: ${{ inputs.check_prefix }} / clippy (${{ matrix.os }})
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-15]
    runs-on: ${{ matrix.os == 'macos-15' && !inputs.run_macos && 'ubuntu-24.04' || matrix.os }}
    steps:
      - name: Planned scope skip marker
        if: ${{ !inputs.run_rust || (matrix.os == 'macos-15' && !inputs.run_macos) }}
        run: echo planned
      - name: Checkout reviewed source
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Install Ubuntu desktop development libraries
        if: inputs.run_rust && matrix.os == 'ubuntu-24.04'
        run: sudo apt-get update
      - name: Cache Cargo and Rust toolchain
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        uses: actions/cache@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Install the locked Rust components
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        run: rustup component add clippy
      - name: Strict Clippy gate
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        run: cargo clippy --locked
  test:
    name: ${{ inputs.check_prefix }} / test (${{ matrix.os }})
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-15]
    runs-on: ${{ matrix.os == 'macos-15' && !inputs.run_macos && 'ubuntu-24.04' || matrix.os }}
    steps:
      - name: Planned scope skip marker
        if: ${{ !inputs.run_rust || (matrix.os == 'macos-15' && !inputs.run_macos) }}
        run: echo planned
      - name: Checkout reviewed source
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Install Ubuntu desktop development libraries
        if: inputs.run_rust && matrix.os == 'ubuntu-24.04'
        run: sudo apt-get update
      - name: Cache Cargo and Rust toolchain
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        uses: actions/cache@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Install the locked Rust components
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        run: rustup component add clippy
      - name: Locked Rust test gate
        if: inputs.run_rust && (matrix.os == 'ubuntu-24.04' || inputs.run_macos)
        run: cargo test --locked
"""
    scope_fixture = (WORKFLOW_DIR / "rust-reusable.yml").read_text(encoding="utf-8")
    validate_reusable_scope_contract(Path("rust-reusable.yml"), scope_fixture)

    def expect_scope_rejection(label: str, mutated_fixture: str) -> None:
        try:
            validate_reusable_scope_contract(Path("rust-reusable.yml"), mutated_fixture)
        except PolicyError:
            return
        raise AssertionError(f"self-test accepted {label}")

    expect_scope_rejection("a three-way shard matrix", scope_fixture.replace("shard: [0, 1]", "shard: [0, 1, 2]"))
    expect_scope_rejection(
        "fail-fast true",
        scope_fixture.replace("      max-parallel: 2\n      matrix:", "      fail-fast: true\n      max-parallel: 2\n      matrix:", 1),
    )
    expect_scope_rejection("max-parallel above two", scope_fixture.replace("max-parallel: 2", "max-parallel: 3", 1))
    expect_scope_rejection(
        "a dynamic shard cardinality",
        scope_fixture.replace("shard: [0, 1]", "shard: " + "$" + "{{ fromJSON('[0,1]') }}"),
    )
    expect_scope_rejection(
        "arithmetic in a GitHub Actions expression",
        scope_fixture.replace(
            "name: ${{ inputs.check_prefix }} / test shard ${{ matrix.shard }} of 2 (ubuntu-24.04)",
            "name: ${{ inputs.check_prefix }} / test shard ${{ matrix.shard + 1 }} of 2 (ubuntu-24.04)",
            1,
        ),
    )
    expect_scope_rejection("an aggregate without always", scope_fixture.replace("always()", "success()", 1))
    expect_scope_rejection("an aggregate accepting failure", scope_fixture.replace("!= success", "== failure", 1))
    expect_scope_rejection(
        "an aggregate without its planned Rust-scope marker",
        scope_fixture.replace("      - name: Planned scope skip marker\n        if: ${{ !inputs.run_common_rust }}\n        run: echo \"Common Rust scope is empty; the Ubuntu aggregate confirms planned markers only.\"\n", "", 1),
    )
    expect_scope_rejection(
        "an aggregate shard gate that runs for empty Rust scope",
        scope_fixture.replace("      - name: Require successful Ubuntu common-Rust shards\n        if: inputs.run_common_rust\n", "      - name: Require successful Ubuntu common-Rust shards\n", 1),
    )

    scope_skip_plan = reusable_rust_scope_plan("PR / Fast Rust", False)
    assert [item["name"] for item in scope_skip_plan] == [
        "PR / Fast Rust / fmt",
        "PR / Fast Rust / clippy (ubuntu-24.04)",
        "PR / Fast Rust / clippy (macos-15)",
        "PR / Fast Rust / test shard 0 of 2 (ubuntu-24.04)",
        "PR / Fast Rust / test shard 1 of 2 (ubuntu-24.04)",
        "PR / Fast Rust / test (ubuntu-24.04)",
        "PR / Fast Rust / test (macos-15)",
    ]
    assert all(item["plannedSkip"] is True and item["executesRust"] is False for item in scope_skip_plan)
    assert all(item["plannedSkip"] is False and item["executesRust"] is True for item in reusable_rust_scope_plan("PR / Fast Rust", True))
    pr_plan = reusable_rust_scope_plan("PR / Fast Rust", True, run_macos=False)
    assert [item["name"] for item in pr_plan if item["plannedSkip"]] == [
        "PR / Fast Rust / clippy (macos-15)",
        "PR / Fast Rust / test (macos-15)",
    ]
    assert all(item["runner"] == "ubuntu-24.04" for item in pr_plan)
    try:
        validate_reusable_scope_contract(
            Path("rust-reusable.yml"), scope_fixture.replace("  fmt:\n    name:", "  fmt:\n    if: inputs.run_rust\n    name:")
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a reusable Rust workflow with a job-level scope condition")

    cache_fixture = (WORKFLOW_DIR / "rust-reusable.yml").read_text(encoding="utf-8")
    validate_reusable_cache_contract(Path("rust-reusable.yml"), cache_fixture)

    def expect_cache_rejection(label: str, mutated_fixture: str) -> None:
        try:
            validate_reusable_cache_contract(Path("rust-reusable.yml"), mutated_fixture)
        except PolicyError:
            return
        raise AssertionError(f"self-test accepted {label}")

    fmt_restore_block = reusable_cache_restore_block("fmt-deps")
    fmt_restore_prefixes = reusable_cache_restore_prefixes("fmt-deps")
    expect_cache_rejection(
        "shared gate cache keys",
        cache_fixture.replace("clippy-target", "fmt-deps", 1),
    )
    expect_cache_rejection(
        "a cache key without run identity",
        cache_fixture.replace(CACHE_GITHUB_RUN_ATTEMPT, "", 1),
    )
    expect_cache_rejection(
        "a wrong target cache path",
        cache_fixture.replace(f"            {CACHE_TARGET_PATH}", "            target/wrong", 1),
    )
    expect_cache_rejection(
        "a bad restore prefix",
        cache_fixture.replace(
            fmt_restore_prefixes[0],
            "hartevo-rust-cache-v2-${{ runner.os }}-${{ runner.arch }}-bad-prefix-",
            1,
        ),
    )
    expect_cache_rejection(
        "missing restore prefixes",
        cache_fixture.replace(fmt_restore_block + "\n", "", 1),
    )
    expect_cache_rejection(
        "reversed restore prefixes",
        cache_fixture.replace(
            fmt_restore_block,
            "\n".join(
                [
                    "          restore-keys: |",
                    *[f"            {prefix}" for prefix in reversed(fmt_restore_prefixes)],
                ]
            ),
            1,
        ),
    )
    expect_cache_rejection(
        "a cross-gate restore prefix",
        cache_fixture.replace(fmt_restore_block, fmt_restore_block.replace("fmt-deps", "test-target"), 1),
    )
    expect_cache_rejection(
        "a cross-OS restore prefix",
        cache_fixture.replace(fmt_restore_block, fmt_restore_block.replace(CACHE_RUNNER_OS, "ubuntu-24.04", 1), 1),
    )
    expect_cache_rejection(
        "cache-hit skipping of a required gate",
        cache_fixture.replace(
            "      - name: Format gate\n",
            "      - name: Format gate\n        if: steps.cache.outputs.cache-hit != 'true'\n",
            1,
        ),
    )
    expect_cache_rejection(
        "actions/cache pin drift",
        cache_fixture.replace(CACHE_ACTION_REF, "actions/cache@" + "a" * 40, 1),
    )
    expect_cache_rejection(
        "an Ubuntu shard cache without a literal shard namespace",
        cache_fixture.replace(
            reusable_shard_cache_primary_key(),
            reusable_shard_cache_primary_key().replace(CACHE_SHARD_INDEX, "0", 1),
            1,
        ),
    )
    expect_cache_rejection(
        "an Ubuntu shard cache without the layout digest",
        cache_fixture.replace(CACHE_SHARD_LAYOUT_DIGEST, "stale-layout", 1),
    )
    expect_cache_rejection(
        "a cross-shard Ubuntu restore prefix",
        cache_fixture.replace(
            reusable_shard_cache_restore_block(),
            reusable_shard_cache_restore_block().replace(CACHE_SHARD_INDEX, "1", 1),
            1,
        ),
    )
    expect_cache_rejection(
        "a cache on a planned-empty shard",
        cache_fixture.replace(
            "      - name: Cache Cargo and Rust toolchain\n"
            "        if: inputs.run_common_rust && steps.shard-plan.outputs.has_packages == 'true'",
            "      - name: Cache Cargo and Rust toolchain\n"
            "        if: inputs.run_common_rust",
            1,
        ),
    )

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

    dependency_fixture = """\
      - name: Verify the checked-in locked dependency graph
        run: |
          test -s Cargo.lock
          cargo metadata --format-version 1 --locked > metadata.json
      - name: Generate license and vulnerability evidence
        run: cargo audit --json > cargo-audit.json
    """
    validate_dependency_audit_contract(Path("integration.yml"), dependency_fixture)
    try:
        validate_dependency_audit_contract(
            Path("integration.yml"), dependency_fixture.replace("cargo audit --json", "cargo audit --locked --json")
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted unsupported cargo audit --locked")
    try:
        validate_dependency_audit_contract(
            Path("integration.yml"), dependency_fixture.replace("test -s Cargo.lock", "true")
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted an audit without an explicit lockfile check")

    dioxus_fixture = """\
    env:
      CARGO_TARGET_DIR: target/ci-cargo
    run: |
      bash scripts/check-dioxus-toolchain.sh self-test
      bash scripts/check-dioxus-toolchain.sh build
      bash scripts/check-dioxus-toolchain.sh verify-receipt receipt.json
    """
    validate_dioxus_artifact_contract(Path("integration.yml"), dioxus_fixture)
    try:
        validate_dioxus_artifact_contract(
            Path("integration.yml"), dioxus_fixture.replace("CARGO_TARGET_DIR: target/ci-cargo", "CARGO_TARGET_DIR: target")
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("self-test accepted a Dioxus workflow without the integration target root")
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
