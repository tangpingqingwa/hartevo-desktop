#!/usr/bin/env python3
"""Plan the smallest honest Rust/dependency CI lanes for a changed diff.

The desktop crate is intentionally a macOS-only lane.  Common Rust crates
(including Cordis) run on Ubuntu, while a desktop-only change never silently
falls into an Ubuntu desktop test.  Every dependency input change gets the
locked metadata/audit/SBOM lane; dependency-only changes additionally get two
narrow smoke lanes.  Unknown or missing scope remains fail-closed through
explicit planned skips rather than a false claim of full workspace coverage.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence


PACKAGES = {
    "application": "hartevo-application",
    "browser-adapter": "hartevo-browser-adapter",
    "capability-gateway": "hartevo-capability-gateway",
    "catalog": "hartevo-catalog",
    "channel-adapters": "hartevo-channel-adapters",
    "cloud-storage": "hartevo-cloud-storage",
    "commerce-connector": "hartevo-commerce-connector",
    "connector-sdk": "hartevo-connector-sdk",
    "context-fabric": "hartevo-context-fabric",
    "cordis": "hartevo-cordis",
    "desktop": "hartevo-desktop",
    "domain-kernel": "hartevo-domain-kernel",
    "effect-broker": "hartevo-effect-broker",
    "eval": "hartevo-eval",
    "mission-scheduler": "hartevo-mission-scheduler",
    "plugin-runtime": "hartevo-plugin-runtime",
    "runtime-adapter": "hartevo-runtime-adapter",
    "storage": "hartevo-storage",
}

DESKTOP_PACKAGES = (PACKAGES["desktop"],)
COMMON_RUST_PACKAGES = tuple(sorted(value for key, value in PACKAGES.items() if key != "desktop"))

DEPENDENCY_PATHS = {
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    ".cargo/config",
}
DEPENDENCY_SUFFIXES = ("/Cargo.toml", "/Cargo.lock")
REVIEW_DIRECTORY = Path(".github/governance/reviews")
REQUIRED_PARENT_CHECKS = (
    "PR / Workflow policy",
    "PR / Scope plan",
    "PR / Result taxonomy",
)


def changed_files(base: str, head: str, repo: Path) -> list[str]:
    process = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--"],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        message = process.stderr.strip() or "git diff failed"
        raise RuntimeError(message)
    return sorted(path for path in process.stdout.splitlines() if path)


def git_lines(repo: Path, *args: str) -> list[str]:
    process = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        message = process.stderr.strip() or f"git {' '.join(args)} failed"
        raise RuntimeError(message)
    return [line for line in process.stdout.splitlines() if line]


def receipt_candidate_parent(
    pr_number: int,
    parents: Sequence[str],
    parent_delta: Sequence[str],
) -> str | None:
    """Return the reviewed parent for an exact receipt-only child.

    Mentioning the current PR's receipt path opts into the high-risk receipt
    contract.  A mixed or merge commit is therefore an error, not an
    opportunity to hide product changes behind a narrow CI comparison.
    """
    expected = (REVIEW_DIRECTORY / f"pr-{pr_number}.json").as_posix()
    if expected not in parent_delta:
        return None
    if len(parents) != 2:
        raise RuntimeError("review receipt candidate must be a single-parent commit")
    if list(parent_delta) != [expected]:
        raise RuntimeError("review receipt candidate must change only its exact receipt path")
    return parents[1]


def verify_parent_check_runs(value: object, parent: str) -> None:
    """Require the latest GitHub Actions result for each parent code-head gate."""
    if not isinstance(value, dict):
        raise RuntimeError("parent check evidence must be a GitHub check-runs object")
    records = value.get("check_runs")
    total = value.get("total_count")
    if (
        not isinstance(records, list)
        or not isinstance(total, int)
        or total != len(records)
    ):
        raise RuntimeError("parent check evidence is incomplete or malformed")
    latest: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("name") not in REQUIRED_PARENT_CHECKS:
            continue
        if record.get("head_sha") != parent:
            continue
        identifier = record.get("id")
        app = record.get("app")
        if (
            not isinstance(identifier, int)
            or identifier <= 0
            or not isinstance(app, dict)
            or app.get("slug") != "github-actions"
        ):
            continue
        name = str(record["name"])
        previous = latest.get(name)
        if previous is None or identifier > int(previous["id"]):
            latest[name] = record
    missing = sorted(set(REQUIRED_PARENT_CHECKS) - set(latest))
    if missing:
        raise RuntimeError(f"reviewed parent is missing trusted check runs: {missing}")
    failed = sorted(
        name
        for name, record in latest.items()
        if record.get("status") != "completed" or record.get("conclusion") != "success"
    )
    if failed:
        raise RuntimeError(f"reviewed parent checks are not successful: {failed}")


def resolve_scope_base(
    base: str,
    head: str,
    repo: Path,
    pr_number: int | None,
    parent_check_runs: Path | None,
) -> tuple[str, bool]:
    """Narrow only a repository-verified high-risk receipt child to its parent."""
    if pr_number is None:
        return base, False
    parents = git_lines(repo, "rev-list", "--parents", "-n", "1", head)
    if len(parents) != 1:
        raise RuntimeError("unable to resolve exact head parents")
    parent_tokens = parents[0].split()
    if len(parent_tokens) < 2:
        return base, False
    parent = parent_tokens[1]
    parent_delta = sorted(git_lines(repo, "diff", "--name-only", parent, head, "--"))
    reviewed_parent = receipt_candidate_parent(pr_number, parent_tokens, parent_delta)
    if reviewed_parent is None:
        return base, False
    verifier = repo / "scripts/repository_governance.py"
    process = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "verify-review-receipt",
            "--root",
            str(repo),
            "--pr",
            str(pr_number),
            "--base",
            base,
            "--head",
            head,
        ],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        message = process.stderr.strip() or "review receipt verification failed"
        raise RuntimeError(message)
    try:
        verification = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("review receipt verifier returned invalid JSON") from error
    if (
        not isinstance(verification, dict)
        or verification.get("status") != "PASS"
        or verification.get("reviewedHeadSha") != reviewed_parent
    ):
        raise RuntimeError("review receipt verifier did not bind the exact reviewed parent")
    if parent_check_runs is None:
        raise RuntimeError("review receipt narrowing requires hosted parent check evidence")
    try:
        check_evidence = json.loads(parent_check_runs.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("unable to read hosted parent check evidence") from error
    verify_parent_check_runs(check_evidence, reviewed_parent)
    return reviewed_parent, True


def is_schema_path(path: str) -> bool:
    lower = path.lower()
    name = Path(path).name.lower()
    return (
        "/schema/" in f"/{lower}/"
        or "/schemas/" in f"/{lower}/"
        or "schema" in name
    )


def package_for_path(path: str) -> str | None:
    parts = Path(path).parts
    if len(parts) >= 2 and parts[0] == "hartevo-rs":
        return PACKAGES.get(parts[1])
    return None


def is_dependency_path(path: str) -> bool:
    """Return whether a path is safe to handle in the dependency-only lane."""
    return path in DEPENDENCY_PATHS or path.endswith(DEPENDENCY_SUFFIXES)


def empty_plan(files: Sequence[str], *, reason: str) -> dict[str, object]:
    return {
        "schema": "hartevo-ci-scope/v2",
        "mode": "non_rust",
        "full": False,
        "rust": False,
        "commonRust": False,
        "desktop": False,
        "commonRustPackages": [],
        "desktopPackages": [],
        "packages": [],
        "dependencyChanged": any(is_dependency_path(path) for path in files),
        "dependencyOnly": False,
        "catalog": False,
        "evidence": False,
        "docs": False,
        "reason": reason,
        "changedFiles": list(files),
    }


def plan_for_files(files: Sequence[str]) -> dict[str, object]:
    if not files:
        return {
            "schema": "hartevo-ci-scope/v2",
            "mode": "full",
            "full": True,
            "rust": True,
            "commonRust": True,
            "desktop": True,
            "commonRustPackages": list(COMMON_RUST_PACKAGES),
            "desktopPackages": list(DESKTOP_PACKAGES),
            "packages": sorted(PACKAGES.values()),
            "dependencyChanged": False,
            "dependencyOnly": False,
            "catalog": True,
            "evidence": True,
            "docs": True,
            "reason": "no changed-file list was available; fail closed to full workspace",
            "changedFiles": [],
        }

    full_reasons: list[str] = []
    packages: set[str] = set()
    desktop_packages: set[str] = set()
    catalog = False
    evidence = False
    docs = False
    dependency_paths = True
    dependency_changed = False

    for path in files:
        parts = Path(path).parts
        lower = path.lower()
        dependency_changed = dependency_changed or is_dependency_path(path)
        dependency_paths = dependency_paths and is_dependency_path(path)
        if path.startswith("hartevo-rs/"):
            package = package_for_path(path)
            if package is None:
                full_reasons.append(f"workspace-layout:{path}")
            else:
                packages.add(package)
                if package in DESKTOP_PACKAGES:
                    desktop_packages.add(package)
            catalog = catalog or "catalog" in parts[1:2] or "/catalog/" in f"/{lower}/"
            evidence = evidence or "/eval/" in f"/{lower}/" or "/catalog/" in f"/{lower}/"
            dependency_paths = False
        elif path.startswith("contracts/") or is_schema_path(path):
            # Contract and schema checks are deliberately handled by the
            # policy/evidence jobs; they are not evidence that desktop Cargo
            # should run on Ubuntu.
            dependency_paths = False
        if is_schema_path(path):
            full_reasons.append(f"schema:{path}")
        if path.startswith("scripts/"):
            evidence = evidence or path.startswith("scripts/check-")
            dependency_paths = False
        if path.startswith("docs/") or path == "README.md":
            docs = True
            dependency_paths = False
        if path.startswith(".github/"):
            dependency_paths = False

        # Keep broad Rust workspace/layout changes fail-closed.  Governance,
        # workflow, policy, and ledger paths stay out of the Rust matrix and
        # are instead covered by their trusted policy checks.
        if len(parts) == 1 and path not in DEPENDENCY_PATHS:
            full_reasons.append(f"repository-root:{path}")
        if path.startswith("hartevo-rs/") and package_for_path(path) is None:
            full_reasons.append(f"workspace-layout:{path}")

    if full_reasons:
        packages = set(PACKAGES.values())
        desktop_packages = set(DESKTOP_PACKAGES)
        return {
            "schema": "hartevo-ci-scope/v2",
            "mode": "full",
            "full": True,
            "rust": True,
            "commonRust": True,
            "desktop": True,
            "commonRustPackages": sorted(packages - desktop_packages),
            "desktopPackages": sorted(desktop_packages),
            "packages": sorted(packages),
            "dependencyChanged": dependency_changed,
            "dependencyOnly": False,
            "catalog": True,
            "evidence": True,
            "docs": True,
            "reason": "; ".join(sorted(set(full_reasons))),
            "changedFiles": list(files),
        }

    dependency_only = dependency_paths and not packages
    common_packages = sorted(packages - desktop_packages)
    desktop_changed = sorted(desktop_packages)
    rust = bool(common_packages or desktop_changed)
    if dependency_only:
        mode = "dependency_only"
        reason = "dependency and lockfile changes only"
    elif rust:
        mode = "scoped_mixed" if common_packages and desktop_changed else "scoped_common" if common_packages else "scoped_desktop"
        reason = "Cordis/common Rust and macOS desktop lanes planned independently" if common_packages and desktop_changed else "common Rust package changes only" if common_packages else "macOS desktop package changes only"
    else:
        mode = "non_rust"
        reason = "no Rust package changes"
    return {
        "schema": "hartevo-ci-scope/v2",
        "mode": mode,
        "full": False,
        "rust": rust,
        "commonRust": bool(common_packages),
        "desktop": bool(desktop_changed),
        "commonRustPackages": common_packages,
        "desktopPackages": desktop_changed,
        "packages": sorted(packages),
        "dependencyChanged": dependency_changed,
        "dependencyOnly": dependency_only,
        "catalog": catalog,
        "evidence": evidence,
        "docs": docs,
        "reason": reason,
        "changedFiles": list(files),
    }


def write_outputs(plan: dict[str, object], output: Path | None) -> None:
    rendered = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    print(rendered)
    if output is None:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    values = {
        "full": str(plan["full"]).lower(),
        "rust": str(plan["rust"]).lower(),
        "packages": json.dumps(plan["packages"], separators=(",", ":")),
        "common_rust": str(plan["commonRust"]).lower(),
        "common_rust_packages": json.dumps(plan["commonRustPackages"], separators=(",", ":")),
        "run_common_rust": str(plan["commonRust"]).lower(),
        "desktop": str(plan["desktop"]).lower(),
        "desktop_packages": json.dumps(plan["desktopPackages"], separators=(",", ":")),
        "run_desktop": str(plan["desktop"]).lower(),
        "dependency_changed": str(plan["dependencyChanged"]).lower(),
        "dependency_only": str(plan["dependencyOnly"]).lower(),
        "receipt_only": str(plan.get("receiptOnly", False)).lower(),
        "catalog": str(plan["catalog"]).lower(),
        "evidence": str(plan["evidence"]).lower(),
        "docs": str(plan["docs"]).lower(),
        "reason": str(plan["reason"]),
        "plan": rendered,
    }
    output.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")


def self_test() -> None:
    full = plan_for_files(["Cargo.lock"])
    assert full["full"] is False and full["rust"] is False
    assert full["dependencyOnly"] is True
    assert full["dependencyChanged"] is True
    assert full["commonRustPackages"] == [] and full["desktopPackages"] == []

    scoped = plan_for_files(["hartevo-rs/catalog/src/lib.rs"])
    assert scoped["full"] is False
    assert scoped["packages"] == ["hartevo-catalog"]
    assert scoped["rust"] is True
    assert scoped["commonRust"] is True and scoped["desktop"] is False
    assert scoped["dependencyChanged"] is False

    mixed_dependency = plan_for_files(
        [
            "Cargo.lock",
            "Cargo.toml",
            "hartevo-rs/commerce-connector/Cargo.toml",
            "hartevo-rs/commerce-connector/src/lib.rs",
        ]
    )
    assert mixed_dependency["dependencyOnly"] is False
    assert mixed_dependency["dependencyChanged"] is True
    assert mixed_dependency["packages"] == ["hartevo-commerce-connector"]

    mission_scheduler = plan_for_files(["hartevo-rs/mission-scheduler/src/lib.rs"])
    assert mission_scheduler["full"] is False
    assert mission_scheduler["packages"] == ["hartevo-mission-scheduler"]

    desktop = plan_for_files(["hartevo-rs/desktop/src/lib.rs"])
    assert desktop["desktop"] is True and desktop["commonRust"] is False
    assert desktop["desktopPackages"] == ["hartevo-desktop"]

    mixed = plan_for_files(["hartevo-rs/cordis/src/lib.rs", "hartevo-rs/desktop/src/lib.rs"])
    assert mixed["commonRust"] is True and mixed["desktop"] is True
    assert mixed["commonRustPackages"] == ["hartevo-cordis"]
    assert mixed["desktopPackages"] == ["hartevo-desktop"]

    capability = plan_for_files(["hartevo-rs/capability-gateway/src/lib.rs"])
    assert capability["full"] is False
    assert capability["packages"] == ["hartevo-capability-gateway"]

    commerce = plan_for_files(["hartevo-rs/commerce-connector/src/lib.rs"])
    assert commerce["full"] is False
    assert commerce["packages"] == ["hartevo-commerce-connector"]

    plugin_runtime = plan_for_files(["hartevo-rs/plugin-runtime/src/lib.rs"])
    assert plugin_runtime["full"] is False
    assert plugin_runtime["packages"] == ["hartevo-plugin-runtime"]

    cordis = plan_for_files(["hartevo-rs/cordis/src/lib.rs"])
    assert cordis["full"] is False
    assert cordis["packages"] == ["hartevo-cordis"]

    docs = plan_for_files(["docs/quality/example.md"])
    assert docs["full"] is False and docs["rust"] is False and docs["docs"] is True

    schema = plan_for_files(["hartevo-rs/application/schema/foo.json"])
    assert schema["full"] is True and schema["rust"] is True

    receipt = ".github/governance/reviews/pr-1020.json"
    parent = "a" * 40
    head = "b" * 40
    assert receipt_candidate_parent(1020, [head, parent], [receipt]) == parent
    assert receipt_candidate_parent(1020, [head, parent], ["scripts/ci-scope.py"]) is None
    for invalid_parents, invalid_delta in (
        ([head, parent], [receipt, "scripts/ci-scope.py"]),
        ([head, parent, "c" * 40], [receipt]),
    ):
        try:
            receipt_candidate_parent(1020, invalid_parents, invalid_delta)
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid receipt-looking commit did not fail closed")

    parent_checks = {
        "total_count": 4,
        "check_runs": [
            {
                "id": 1,
                "name": "PR / Result taxonomy",
                "head_sha": parent,
                "status": "completed",
                "conclusion": "failure",
                "app": {"slug": "github-actions"},
            },
            *[
                {
                    "id": index + 10,
                    "name": name,
                    "head_sha": parent,
                    "status": "completed",
                    "conclusion": "success",
                    "app": {"slug": "github-actions"},
                }
                for index, name in enumerate(REQUIRED_PARENT_CHECKS)
            ],
        ],
    }
    verify_parent_check_runs(parent_checks, parent)
    for invalid_checks in (
        {
            **parent_checks,
            "total_count": 3,
        },
        {
            "total_count": 2,
            "check_runs": parent_checks["check_runs"][1:3],
        },
        {
            **parent_checks,
            "check_runs": [
                {
                    **record,
                    "conclusion": (
                        "failure"
                        if record["name"] == "PR / Result taxonomy"
                        and record["id"] > 1
                        else record["conclusion"]
                    ),
                }
                for record in parent_checks["check_runs"]
            ],
        },
    ):
        try:
            verify_parent_check_runs(invalid_checks, parent)
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid hosted parent check evidence did not fail closed")

    print(json.dumps({"schema": "hartevo-ci-scope-self-test/v1", "status": "PASS"}, sort_keys=True))


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--parent-check-runs", type=Path)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.base or not args.head:
        print("--base and --head are required", file=sys.stderr)
        return 2
    try:
        effective_base, receipt_only = resolve_scope_base(
            args.base,
            args.head,
            args.repo,
            args.pr_number,
            args.parent_check_runs,
        )
        files = changed_files(effective_base, args.head, args.repo)
        plan = plan_for_files(files)
        plan["receiptOnly"] = receipt_only
        plan["comparisonBaseSha"] = effective_base
        write_outputs(plan, args.github_output)
    except (OSError, RuntimeError) as error:
        print(f"ci scope planning failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
