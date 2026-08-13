#!/usr/bin/env python3
"""Validate build-once/promotion fences without performing a deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def semver(tag: str) -> tuple[int, int, int, str]:
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-(.*))?", tag)
    if not match:
        raise ValueError(f"invalid promotion tag: {tag}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4) or "~stable"


def evidence_status(path: Path, expected_commit: str) -> tuple[str, bool]:
    if not path.exists():
        return "NOT_IMPLEMENTED", False
    if path.is_symlink() or not path.is_file():
        raise ValueError("release evidence must be a regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("passed"), bool):
        raise ValueError("release evidence must contain a boolean passed field")
    if value.get("releaseCommit") != expected_commit:
        raise ValueError("release evidence is not bound to the source commit")
    return "PASS" if value["passed"] else "FAIL", value["passed"]


def validate(args: argparse.Namespace) -> dict[str, object]:
    for value, label in ((args.source_commit, "source commit"), (args.current_main, "current main")):
        if not SHA1.fullmatch(value):
            raise ValueError(f"{label} must be a full SHA-1")
    if args.source_commit != args.current_main:
        raise ValueError("source commit is not the current reviewed main commit")
    if not TAG.fullmatch(args.tag):
        raise ValueError("tag must be an immutable semver tag")
    if args.release != "false":
        raise ValueError("Release is permanently false in this scaffolding PR")
    if args.promotion_kind not in {"forward", "rollback"}:
        raise ValueError("promotion kind must be forward or rollback")
    if args.promotion_kind == "rollback" and not args.rollback_of:
        raise ValueError("rollback promotions require rollback_of and a new tag")
    if args.rollback_of:
        if not TAG.fullmatch(args.rollback_of):
            raise ValueError("rollback_of must be an immutable semver tag")
        if args.rollback_of == args.tag:
            raise ValueError("rollback must be a new promotion tag, never the old tag")
    artifact = Path(args.artifact)
    if artifact.is_symlink() or not artifact.is_file():
        raise ValueError("promotion artifact must be a regular file")
    actual_digest = sha256(artifact)
    if not SHA256.fullmatch(args.expected_digest) or actual_digest != args.expected_digest:
        raise ValueError("promotion artifact digest does not match the build receipt")
    status, passed = evidence_status(Path(args.release_evidence), args.source_commit)
    if not passed:
        raise ValueError("release evidence is not passed; promotion is blocked")
    if not args.rollback_of:
        existing = subprocess.run(
            ["git", "tag", "--list", "v*"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if existing.returncode != 0:
            raise ValueError("unable to inspect existing tags")
        stable = [tag for tag in existing.stdout.splitlines() if TAG.fullmatch(tag) and "-" not in tag]
        if stable and semver(args.tag) <= max(semver(tag) for tag in stable):
            raise ValueError("forward promotion tag is not monotonic")
    payload = {
        "schema": "hartevo-ci-promotion-fence/v1",
        "decision": "DRY_RUN_ONLY",
        "release": False,
        "deployment": False,
        "sourceCommit": args.source_commit,
        "currentMain": args.current_main,
        "tag": args.tag,
        "promotionKind": args.promotion_kind,
        "rollbackOf": args.rollback_of,
        "artifactSha256": actual_digest,
        "releaseEvidenceStatus": status,
        "releaseEvidencePassed": passed,
        "oidcInterface": "github-actions-oidc",
        "longLivedCredentials": False,
    }
    return payload


def self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="hartevo-ci-promotion-") as directory:
        root = Path(directory)
        artifact = root / "artifact.bin"
        artifact.write_bytes(b"fixture artifact")
        evidence = root / "release.json"
        evidence.write_text(json.dumps({"passed": True, "releaseCommit": "a" * 40}), encoding="utf-8")
        args = argparse.Namespace(
            source_commit="a" * 40,
            current_main="a" * 40,
            tag="v999.0.0",
            release="false",
            promotion_kind="forward",
            rollback_of=None,
            artifact=str(artifact),
            expected_digest=sha256(artifact),
            release_evidence=str(evidence),
        )
        value = validate(args)
        assert value["decision"] == "DRY_RUN_ONLY" and value["release"] is False
        evidence.write_text(json.dumps({"passed": False}), encoding="utf-8")
        try:
            validate(args)
        except ValueError:
            pass
        else:
            raise AssertionError("self-test accepted a failed release evidence baseline")
        args.release = "true"
        try:
            validate(args)
        except ValueError:
            pass
        else:
            raise AssertionError("self-test accepted Release=true")
    print(json.dumps({"schema": "hartevo-ci-promotion-self-test/v1", "status": "PASS"}, sort_keys=True))


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["validate", "self-test"])
    parser.add_argument("--source-commit")
    parser.add_argument("--current-main")
    parser.add_argument("--tag")
    parser.add_argument("--release")
    parser.add_argument("--promotion-kind", default="forward")
    parser.add_argument("--rollback-of")
    parser.add_argument("--artifact")
    parser.add_argument("--expected-digest")
    parser.add_argument("--release-evidence")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv))
    try:
        if args.command == "self-test":
            self_test()
            return 0
        required = (args.source_commit, args.current_main, args.tag, args.release, args.artifact, args.expected_digest, args.release_evidence)
        if any(value is None for value in required):
            raise ValueError("validate requires source, main, tag, release, artifact, digest, and evidence")
        value = validate(args)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "hartevo-ci-promotion-fence/v1", "decision": "BLOCKED", "release": False, "deployment": False, "message": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
