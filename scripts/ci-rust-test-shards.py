#!/usr/bin/env python3
"""Plan and verify the fixed Ubuntu Rust test shard layout.

The planner is deliberately small and fail-closed. It reads Cargo workspace
membership and package names from the checked-out source, validates the
checked-in two-way layout, and emits only canonical package arrays as data.
No value read from the repository can change the number of jobs, their runner,
or a shell command.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterable, Sequence


LAYOUT_VERSION = "layout-v1"
SHARD_COUNT = 2
PLAN_SCHEMA = "hartevo-ci-rust-test-shards/plan-v1"
VERIFY_SCHEMA = "hartevo-ci-rust-test-shards/verify-v1"
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
GLOB_MARKERS = frozenset("*?[{")

# This is the exact member list in the root Cargo.toml. The source digest
# covers paths, not just package names, so a rename cannot silently reuse the
# old partition.
CHECKED_IN_WORKSPACE_MEMBERS = (
    "hartevo-rs/application",
    "hartevo-rs/browser-adapter",
    "hartevo-rs/capability-gateway",
    "hartevo-rs/catalog",
    "hartevo-rs/cloud-storage",
    "hartevo-rs/connector-sdk",
    "hartevo-rs/commerce-connector",
    "hartevo-rs/context-fabric",
    "hartevo-rs/desktop",
    "hartevo-rs/domain-kernel",
    "hartevo-rs/effect-broker",
    "hartevo-rs/eval",
    "hartevo-rs/runtime-adapter",
    "hartevo-rs/mission-scheduler",
    "hartevo-rs/plugin-runtime",
    "hartevo-rs/storage",
)

# Keep these arrays as data. They are intentionally deterministic, explicit,
# and not claimed to be balanced because no per-package timing series exists.
CHECKED_IN_SHARDS = (
    (
        "hartevo-application",
        "hartevo-capability-gateway",
        "hartevo-cloud-storage",
        "hartevo-connector-sdk",
        "hartevo-desktop",
        "hartevo-effect-broker",
        "hartevo-mission-scheduler",
        "hartevo-runtime-adapter",
    ),
    (
        "hartevo-browser-adapter",
        "hartevo-catalog",
        "hartevo-commerce-connector",
        "hartevo-context-fabric",
        "hartevo-domain-kernel",
        "hartevo-eval",
        "hartevo-plugin-runtime",
        "hartevo-storage",
    ),
)
CHECKED_IN_WORKSPACE_PACKAGES = tuple(sorted(package for shard in CHECKED_IN_SHARDS for package in shard))


class ShardError(ValueError):
    """A fail-closed planner or verification error."""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def layout_descriptor(shards: Sequence[Sequence[str]] = CHECKED_IN_SHARDS) -> dict[str, object]:
    return {
        "layoutVersion": LAYOUT_VERSION,
        "shards": {str(index): list(packages) for index, packages in enumerate(shards)},
    }


CHECKED_IN_LAYOUT_DIGEST = "aa41a33cd0b0b50d9e68e4c5893646cc4497ec5c98bf61d8f0b2a9d5fe6072dd"
CHECKED_IN_SOURCE_WORKSPACE_MEMBER_DIGEST = "f449e4db87a42c207cb1b5da3478f3494c83c28a3d3f8a4a08e74013fb91b95c"


def fail(message: str) -> None:
    raise ShardError(message)


def package_name(value: object, *, source: str) -> str:
    if not isinstance(value, str) or not PACKAGE_NAME_RE.fullmatch(value):
        fail(f"{source} contains an invalid Cargo package name: {value!r}")
    return value


def cargo_lines(path: Path) -> list[tuple[str, str]]:
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"unable to read Cargo manifest {path}: {error}")

    section = ""
    result: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section:
                fail(f"{path}:{line_number} has an empty TOML section")
            result.append((section, ""))
            continue
        result.append((section, line))
    return result


def read_workspace_members(path: Path) -> list[str]:
    lines = cargo_lines(path)
    for index, (section, line) in enumerate(lines):
        if section != "workspace" or not line.startswith("members"):
            continue
        match = re.fullmatch(r"members\s*=\s*(.*)", line)
        if not match:
            fail(f"{path} has a malformed workspace.members assignment")
        expression = match.group(1)
        while expression.count("[") > expression.count("]"):
            index += 1
            if index >= len(lines) or lines[index][0] != "workspace" or not lines[index][1]:
                fail(f"{path} has an unterminated workspace.members array")
            expression += lines[index][1]
        try:
            value = ast.literal_eval(expression)
        except (SyntaxError, ValueError) as error:
            fail(f"{path} has a malformed workspace.members array: {error}")
        if not isinstance(value, list):
            fail(f"{path} workspace.members must be an array")
        return value
    fail(f"{path} is missing a workspace.members array")


def read_package_name(path: Path) -> object:
    for section, line in cargo_lines(path):
        if section != "package" or not line.startswith("name"):
            continue
        match = re.fullmatch(r'name\s*=\s*"([^"]+)"', line)
        if not match:
            fail(f"{path} has a malformed [package].name assignment")
        return match.group(1)
    fail(f"{path} is missing [package].name")


def repo_path(repo: Path) -> Path:
    try:
        return repo.resolve(strict=True)
    except OSError as error:
        fail(f"repository root is unavailable: {error}")


def read_workspace(repo: Path) -> dict[str, object]:
    root = repo_path(repo)
    members = read_workspace_members(root / "Cargo.toml")
    if not members:
        fail("Cargo.toml workspace.members must be a non-empty array")

    raw_members: list[str] = []
    package_names: list[str] = []
    seen_members: set[str] = set()
    seen_manifests: set[Path] = set()
    for index, member in enumerate(members):
        if not isinstance(member, str) or not member:
            fail(f"workspace member {index} must be a non-empty string")
        if any(marker in member for marker in GLOB_MARKERS):
            fail(f"workspace member {member!r} must not contain a glob")
        member_path = (root / member).resolve()
        try:
            member_path.relative_to(root)
        except ValueError:
            fail(f"workspace member escapes the repository: {member!r}")
        if member in seen_members:
            fail(f"duplicate workspace member: {member}")
        seen_members.add(member)
        manifest = member_path / "Cargo.toml" if member_path.is_dir() else member_path
        if manifest in seen_manifests:
            fail(f"duplicate workspace manifest: {manifest}")
        seen_manifests.add(manifest)
        package_names.append(package_name(read_package_name(manifest), source=f"{manifest} [package].name"))
        raw_members.append(member)

    if len(package_names) != len(set(package_names)):
        fail("workspace package names must be unique")

    source_digest = digest(raw_members)
    if tuple(raw_members) != CHECKED_IN_WORKSPACE_MEMBERS:
        fail("workspace member source drift: the checked-in layout is not valid for this workspace")
    if tuple(sorted(package_names)) != CHECKED_IN_WORKSPACE_PACKAGES:
        fail("workspace package set drift: the checked-in layout is not valid for this workspace")
    if source_digest != CHECKED_IN_SOURCE_WORKSPACE_MEMBER_DIGEST:
        fail("workspace member source digest drift")

    return {
        "root": root,
        "members": tuple(raw_members),
        "packages": tuple(sorted(package_names)),
        "sourceDigest": source_digest,
    }


def validate_layout(
    *,
    workspace_packages: Sequence[str],
    shards: Sequence[Sequence[str]] = CHECKED_IN_SHARDS,
    expected_digest: str = CHECKED_IN_LAYOUT_DIGEST,
) -> str:
    if len(shards) != SHARD_COUNT:
        fail(f"layout must contain exactly {SHARD_COUNT} shards")
    normalized: list[list[str]] = []
    flattened: list[str] = []
    for index, shard in enumerate(shards):
        if not isinstance(shard, (list, tuple)):
            fail(f"shard {index} package array is malformed")
        names = [package_name(value, source=f"shard {index}") for value in shard]
        if names != sorted(names):
            fail(f"shard {index} package array is not canonical")
        if len(names) != len(set(names)):
            fail(f"shard {index} contains duplicate packages")
        normalized.append(names)
        flattened.extend(names)
    if len(flattened) != len(set(flattened)):
        fail("shard package arrays overlap")
    if tuple(sorted(flattened)) != tuple(sorted(workspace_packages)):
        fail("shard package union does not equal the workspace package set")
    actual_digest = digest(layout_descriptor(normalized))
    if actual_digest != expected_digest:
        fail(f"layout digest drift: expected {expected_digest}, got {actual_digest}")
    return actual_digest


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    fail(f"expected a boolean, got {value!r}")


def parse_packages(raw: object, *, workspace_packages: Sequence[str], allow_empty: bool = True) -> list[str]:
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            fail(f"malformed package scope JSON: {error}")
    else:
        value = raw
    if not isinstance(value, list):
        fail("package scope must be a JSON array")
    if not allow_empty and not value:
        fail("scoped Rust execution requires at least one package")
    names = [package_name(item, source="package scope") for item in value]
    if len(names) != len(set(names)):
        fail("package scope contains duplicate packages")
    unknown = sorted(set(names) - set(workspace_packages))
    if unknown:
        fail(f"package scope contains unknown packages: {unknown}")
    return sorted(names)


def build_plan(
    workspace: dict[str, object],
    *,
    shard: int,
    shard_count: int,
    full_workspace: bool,
    packages: object,
) -> dict[str, object]:
    if shard_count != SHARD_COUNT:
        fail(f"shard count must be exactly {SHARD_COUNT}")
    if shard not in range(SHARD_COUNT):
        fail(f"unknown shard index: {shard}")
    workspace_packages = tuple(workspace["packages"])
    layout_digest = validate_layout(workspace_packages=workspace_packages)
    scope = parse_packages(packages, workspace_packages=workspace_packages)
    if full_workspace and scope and tuple(scope) != tuple(workspace_packages):
        fail("full-workspace scope must be empty or contain every workspace package exactly once")
    selected = list(CHECKED_IN_SHARDS[shard]) if full_workspace else sorted(set(CHECKED_IN_SHARDS[shard]) & set(scope))
    return {
        "schema": PLAN_SCHEMA,
        "layoutVersion": LAYOUT_VERSION,
        "layoutDigest": layout_digest,
        "sourceWorkspaceMemberDigest": workspace["sourceDigest"],
        "shard": shard,
        "shardCount": shard_count,
        "packages": selected,
        "fullWorkspace": full_workspace,
        "hasPackages": bool(selected),
        "plannedEmpty": not selected,
    }


def write_plan(record: dict[str, object], output: Path | None) -> None:
    rendered = canonical_json(record)
    print(rendered)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")


def write_github_outputs(record: dict[str, object], output: Path | None) -> None:
    if output is None:
        return
    values = {
        "layout_digest": record["layoutDigest"],
        "source_workspace_member_digest": record["sourceWorkspaceMemberDigest"],
        "has_packages": str(record["hasPackages"]).lower(),
        "planned_empty": str(record["plannedEmpty"]).lower(),
        "packages": canonical_json(record["packages"]),
    }
    output.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")


def read_plan(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"unable to read a valid shard plan from {path}: {error}")
    if not isinstance(value, dict):
        fail("shard plan must be a JSON object")
    return value


def verify_plan(workspace: dict[str, object], value: dict[str, object]) -> dict[str, object]:
    required = {
        "schema",
        "layoutVersion",
        "layoutDigest",
        "sourceWorkspaceMemberDigest",
        "shard",
        "shardCount",
        "packages",
        "fullWorkspace",
        "hasPackages",
        "plannedEmpty",
    }
    if set(value) != required:
        fail("shard plan schema has missing or unexpected fields")
    if value.get("schema") != PLAN_SCHEMA or value.get("layoutVersion") != LAYOUT_VERSION:
        fail("shard plan schema or layout version drift")
    if not isinstance(value.get("shard"), int) or isinstance(value["shard"], bool):
        fail("shard plan index is malformed")
    if not isinstance(value.get("shardCount"), int) or isinstance(value["shardCount"], bool):
        fail("shard plan count is malformed")
    if not isinstance(value.get("fullWorkspace"), bool):
        fail("shard plan fullWorkspace is malformed")
    expected = build_plan(
        workspace,
        shard=value["shard"],
        shard_count=value["shardCount"],
        full_workspace=value["fullWorkspace"],
        packages=[] if value["fullWorkspace"] else value["packages"],
    )
    if value != expected:
        fail("shard plan does not match the current workspace, layout, or canonical selection")
    return expected


def verify_command(args: argparse.Namespace) -> int:
    workspace = read_workspace(args.repo)
    layout_digest = validate_layout(workspace_packages=workspace["packages"])
    if args.plan is not None:
        if args.packages is not None or args.full_workspace is not None:
            fail("--plan cannot be combined with an inline package scope")
        record = verify_plan(workspace, read_plan(args.plan))
        if args.emit_packages:
            for package in record["packages"]:
                print(package)
        else:
            print(canonical_json({"schema": VERIFY_SCHEMA, "status": "PASS", "plan": record}))
        return 0

    if args.packages is not None:
        scope = parse_packages(args.packages, workspace_packages=workspace["packages"])
        if args.full_workspace:
            if scope and tuple(scope) != tuple(workspace["packages"]):
                fail("full-workspace scope must be empty or contain every workspace package exactly once")
            selected = list(workspace["packages"])
        else:
            selected = scope
        if args.emit_packages:
            for package in selected:
                print(package)
        else:
            print(
                canonical_json(
                    {
                        "schema": VERIFY_SCHEMA,
                        "status": "PASS",
                        "layoutDigest": layout_digest,
                        "sourceWorkspaceMemberDigest": workspace["sourceDigest"],
                        "packages": selected,
                        "fullWorkspace": args.full_workspace,
                    }
                )
            )
        return 0

    if args.emit_packages:
        fail("--emit-packages requires --plan")
    plans = [
        build_plan(
            workspace,
            shard=index,
            shard_count=SHARD_COUNT,
            full_workspace=True,
            packages=[],
        )
        for index in range(SHARD_COUNT)
    ]
    print(
        canonical_json(
            {
                "schema": VERIFY_SCHEMA,
                "status": "PASS",
                "layoutVersion": LAYOUT_VERSION,
                "layoutDigest": layout_digest,
                "sourceWorkspaceMemberDigest": workspace["sourceDigest"],
                "workspacePackages": list(workspace["packages"]),
                "plans": plans,
            }
        )
    )
    return 0


def plan_command(args: argparse.Namespace) -> int:
    workspace = read_workspace(args.repo)
    record = build_plan(
        workspace,
        shard=args.shard,
        shard_count=args.shard_count,
        full_workspace=args.full_workspace,
        packages=args.packages,
    )
    write_plan(record, args.output)
    write_github_outputs(record, args.github_output)
    return 0


def self_test() -> None:
    workspace = read_workspace(Path.cwd())
    layout_digest = validate_layout(workspace_packages=workspace["packages"])
    assert layout_digest == CHECKED_IN_LAYOUT_DIGEST

    plans = [
        build_plan(workspace, shard=index, shard_count=SHARD_COUNT, full_workspace=True, packages=[])
        for index in range(SHARD_COUNT)
    ]
    selected = [package for plan in plans for package in plan["packages"]]
    assert len(selected) == len(set(selected)) == len(CHECKED_IN_WORKSPACE_PACKAGES)
    assert sorted(selected) == list(CHECKED_IN_WORKSPACE_PACKAGES)

    scoped = build_plan(
        workspace,
        shard=1,
        shard_count=SHARD_COUNT,
        full_workspace=False,
        packages='["hartevo-browser-adapter"]',
    )
    assert scoped["packages"] == ["hartevo-browser-adapter"]
    assert scoped["hasPackages"] is True and scoped["plannedEmpty"] is False
    empty = build_plan(
        workspace,
        shard=0,
        shard_count=SHARD_COUNT,
        full_workspace=False,
        packages='["hartevo-browser-adapter"]',
    )
    assert empty["packages"] == [] and empty["plannedEmpty"] is True

    for invalid in (
        "not-json",
        '["hartevo-application", "hartevo-application"]',
        '["hartevo-does-not-exist"]',
        '["$(touch /tmp/ci-rust-test-shards-injection)"]',
        '{"package":"hartevo-application"}',
    ):
        try:
            parse_packages(invalid, workspace_packages=workspace["packages"])
        except ShardError:
            pass
        else:
            raise AssertionError(f"self-test accepted invalid package scope: {invalid}")

    try:
        validate_layout(
            workspace_packages=workspace["packages"],
            shards=(CHECKED_IN_SHARDS[0] + (CHECKED_IN_SHARDS[0][0],), CHECKED_IN_SHARDS[1]),
        )
    except ShardError:
        pass
    else:
        raise AssertionError("self-test accepted overlapping shard packages")
    try:
        validate_layout(workspace_packages=workspace["packages"], expected_digest="0" * 64)
    except ShardError:
        pass
    else:
        raise AssertionError("self-test accepted layout digest drift")

    with TemporaryDirectory(prefix="hartevo-ci-rust-shards-self-test-") as directory:
        fixture = Path(directory)
        (fixture / "Cargo.toml").write_text('[workspace]\nmembers = ["hartevo-rs/*"]\n', encoding="utf-8")
        try:
            read_workspace(fixture)
        except ShardError:
            pass
        else:
            raise AssertionError("self-test accepted a glob workspace member")

    print(canonical_json({"schema": f"{PLAN_SCHEMA}-self-test", "status": "PASS"}))


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--repo", type=Path, default=Path.cwd())
    plan.add_argument("--shard", type=int, required=True)
    plan.add_argument("--shard-count", type=int, default=SHARD_COUNT)
    plan.add_argument("--full-workspace", type=parse_bool, nargs="?", const=True, default=False)
    plan.add_argument("--packages", "--rust-packages", dest="packages", default="[]")
    plan.add_argument("--output", type=Path)
    plan.add_argument("--github-output", type=Path)
    plan.set_defaults(handler=plan_command)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo", type=Path, default=Path.cwd())
    verify.add_argument("--plan", type=Path)
    verify.add_argument("--packages", "--rust-packages", dest="packages")
    verify.add_argument("--full-workspace", type=parse_bool, nargs="?", const=True)
    verify.add_argument("--emit-packages", action="store_true")
    verify.set_defaults(handler=verify_command)

    self_test_parser = subparsers.add_parser("self-test")
    self_test_parser.set_defaults(handler=lambda _args: self_test() or 0)

    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ShardError, TypeError, ValueError) as error:
        print(
            canonical_json(
                {
                    "schema": VERIFY_SCHEMA,
                    "status": "FAIL",
                    "message": str(error),
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
