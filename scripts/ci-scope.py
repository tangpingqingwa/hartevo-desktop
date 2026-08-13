#!/usr/bin/env python3
"""Plan a conservative changed-scope CI matrix.

The planner is deliberately fail-closed: repository roots, contracts, schemas,
workflow policy, and lock/toolchain changes request the full workspace matrix.
It emits both a machine-readable plan and GitHub Actions outputs.
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
    "catalog": "hartevo-catalog",
    "cloud-storage": "hartevo-cloud-storage",
    "connector-sdk": "hartevo-connector-sdk",
    "context-fabric": "hartevo-context-fabric",
    "desktop": "hartevo-desktop",
    "domain-kernel": "hartevo-domain-kernel",
    "effect-broker": "hartevo-effect-broker",
    "eval": "hartevo-eval",
    "mission-scheduler": "hartevo-mission-scheduler",
    "runtime-adapter": "hartevo-runtime-adapter",
    "storage": "hartevo-storage",
}


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


def plan_for_files(files: Sequence[str]) -> dict[str, object]:
    if not files:
        return {
            "schema": "hartevo-ci-scope/v1",
            "mode": "full",
            "full": True,
            "rust": True,
            "packages": sorted(PACKAGES.values()),
            "catalog": True,
            "evidence": True,
            "docs": True,
            "reason": "no changed-file list was available; fail closed to full workspace",
            "changedFiles": [],
        }

    full_reasons: list[str] = []
    packages: set[str] = set()
    catalog = False
    evidence = False
    docs = False

    for path in files:
        parts = Path(path).parts
        lower = path.lower()
        if len(parts) == 1:
            full_reasons.append(f"repository-root:{path}")
        if path == "Cargo.lock" or path == "Cargo.toml" or path == "rust-toolchain.toml":
            full_reasons.append(f"workspace-contract:{path}")
        if path.startswith("contracts/"):
            full_reasons.append(f"contract:{path}")
        if path.startswith(".github/workflows/") or path.startswith(".github/policies/"):
            full_reasons.append(f"workflow-policy:{path}")
        if is_schema_path(path):
            full_reasons.append(f"schema:{path}")
        if path.startswith("hartevo-rs/"):
            package = package_for_path(path)
            if package is None:
                full_reasons.append(f"workspace-layout:{path}")
            else:
                packages.add(package)
            catalog = catalog or "catalog" in parts[1:2] or "/catalog/" in f"/{lower}/"
            evidence = evidence or "/eval/" in f"/{lower}/" or "/catalog/" in f"/{lower}/"
        if path.startswith("scripts/"):
            evidence = evidence or path.startswith("scripts/check-")
        if path.startswith("docs/") or path == "README.md":
            docs = True

    if full_reasons:
        packages = set(PACKAGES.values())
        return {
            "schema": "hartevo-ci-scope/v1",
            "mode": "full",
            "full": True,
            "rust": True,
            "packages": sorted(packages),
            "catalog": True,
            "evidence": True,
            "docs": True,
            "reason": "; ".join(sorted(set(full_reasons))),
            "changedFiles": list(files),
        }

    rust = bool(packages)
    return {
        "schema": "hartevo-ci-scope/v1",
        "mode": "scoped" if rust else "non_rust",
        "full": False,
        "rust": rust,
        "packages": sorted(packages),
        "catalog": catalog,
        "evidence": evidence,
        "docs": docs,
        "reason": "package-local changes only" if rust else "no Rust package changes",
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
        "catalog": str(plan["catalog"]).lower(),
        "evidence": str(plan["evidence"]).lower(),
        "docs": str(plan["docs"]).lower(),
        "reason": str(plan["reason"]),
        "plan": rendered,
    }
    output.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")


def self_test() -> None:
    full = plan_for_files(["Cargo.lock"])
    assert full["full"] is True and full["rust"] is True
    assert len(full["packages"]) == len(PACKAGES)

    scoped = plan_for_files(["hartevo-rs/catalog/src/lib.rs"])
    assert scoped["full"] is False
    assert scoped["packages"] == ["hartevo-catalog"]
    assert scoped["rust"] is True

    mission_scheduler = plan_for_files(["hartevo-rs/mission-scheduler/src/lib.rs"])
    assert mission_scheduler["full"] is False
    assert mission_scheduler["packages"] == ["hartevo-mission-scheduler"]

    docs = plan_for_files(["docs/quality/example.md"])
    assert docs["full"] is False and docs["rust"] is False and docs["docs"] is True

    schema = plan_for_files(["hartevo-rs/application/schema/foo.json"])
    assert schema["full"] is True

    print(json.dumps({"schema": "hartevo-ci-scope-self-test/v1", "status": "PASS"}, sort_keys=True))


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--head")
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
        files = changed_files(args.base, args.head, args.repo)
        plan = plan_for_files(files)
        write_outputs(plan, args.github_output)
    except (OSError, RuntimeError) as error:
        print(f"ci scope planning failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
