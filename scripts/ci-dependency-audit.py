#!/usr/bin/env python3
"""Create a deterministic Cargo dependency/license/SBOM receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def audit(metadata_path: Path, tree_path: Path, lock_path: Path, audit_path: Path | None, output: Path) -> dict[str, object]:
    metadata = load(metadata_path)
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise ValueError("cargo metadata must contain a packages array")
    packages: list[dict[str, object]] = []
    for package in metadata["packages"]:
        if not isinstance(package, dict):
            raise ValueError("cargo metadata package must be an object")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        license_value = package.get("license")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("cargo metadata package identity is malformed")
        if source is not None and (not isinstance(license_value, str) or not license_value):
            raise ValueError(f"external package lacks license metadata: {name} {version}")
        packages.append(
            {
                "name": name,
                "version": version,
                "source": source or "workspace",
                "license": license_value or "Proprietary",
                "licenseFile": package.get("license_file"),
            }
        )
    packages.sort(key=lambda item: (str(item["name"]), str(item["version"]), str(item["source"])))
    lock_raw = lock_path.read_bytes()
    tree_raw = tree_path.read_bytes()
    audit_status: dict[str, object]
    if audit_path is None:
        audit_status = {"status": "BLOCKED_ENV", "reason": "cargo audit receipt was not supplied"}
    else:
        value = load(audit_path)
        if not isinstance(value, dict):
            raise ValueError("cargo audit output must be a JSON object")
        vulnerabilities = value.get("vulnerabilities", {})
        warnings = value.get("warnings", {})
        audit_status = {
            "status": "PASS" if not vulnerabilities and not warnings else "CODE_FAILURE",
            "vulnerabilityCount": len(vulnerabilities.get("list", [])) if isinstance(vulnerabilities, dict) else None,
            "warningCount": len(warnings.get("unmaintained", [])) if isinstance(warnings, dict) and isinstance(warnings.get("unmaintained"), list) else None,
            "receiptSha256": digest(audit_path.read_bytes()),
        }
    sbom = {
        "schema": "hartevo-ci-sbom/v1",
        "format": "cargo-metadata-normalized",
        "lockfileSha256": digest(lock_raw),
        "dependencyGraphSha256": digest(tree_raw),
        "packageCount": len(packages),
        "packages": packages,
        "licensePolicy": "every external package must expose Cargo license metadata",
        "vulnerabilityScan": audit_status,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sbom, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return sbom


def self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="hartevo-ci-deps-") as directory:
        root = Path(directory)
        (root / "metadata.json").write_text(json.dumps({"packages": [{"name": "fixture", "version": "1.0.0", "source": None, "license": "Proprietary"}]}), encoding="utf-8")
        (root / "tree.txt").write_text("fixture v1.0.0\n", encoding="utf-8")
        (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        value = audit(root / "metadata.json", root / "tree.txt", root / "Cargo.lock", None, root / "sbom.json")
        assert value["schema"] == "hartevo-ci-sbom/v1"
        assert value["vulnerabilityScan"]["status"] == "BLOCKED_ENV"
    print(json.dumps({"schema": "hartevo-ci-dependency-audit-self-test/v1", "status": "PASS"}, sort_keys=True))


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["audit", "self-test"])
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--cargo-audit-json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv))
    try:
        if args.command == "self-test":
            self_test()
            return 0
        if not all((args.metadata, args.tree, args.lock, args.output)):
            raise ValueError("audit requires --metadata, --tree, --lock, and --output")
        value = audit(args.metadata, args.tree, args.lock, args.cargo_audit_json, args.output)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0 if value["vulnerabilityScan"]["status"] == "PASS" else 2
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "hartevo-ci-sbom/v1", "status": "INFRA_FAILURE", "message": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
