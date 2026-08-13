#!/usr/bin/env python3
"""Create a deterministic Cargo dependency/license/SBOM receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_audit_receipt(value: object) -> dict[str, object]:
    """Normalize cargo-audit findings without treating informational warnings as vulnerabilities."""
    if not isinstance(value, dict):
        raise ValueError("cargo audit output must be a JSON object")

    vulnerabilities = value.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise ValueError("cargo audit output must contain a vulnerabilities object")
    vulnerability_list = vulnerabilities.get("list")
    if not isinstance(vulnerability_list, list):
        raise ValueError("cargo audit vulnerabilities must contain a list")

    warnings = value.get("warnings")
    if not isinstance(warnings, dict):
        raise ValueError("cargo audit output must contain a warnings object")

    warning_counts: dict[str, int] = {}
    warning_evidence: list[dict[str, str]] = []
    for category, entries in warnings.items():
        if not isinstance(category, str) or not category:
            raise ValueError("cargo audit warning category must be a non-empty string")
        if not isinstance(entries, list):
            raise ValueError(f"cargo audit warning category is not a list: {category}")
        warning_counts[category] = len(entries)
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"cargo audit warning entry must be an object: {category}")
            advisory = entry.get("advisory")
            package = entry.get("package")
            if not isinstance(advisory, dict) or not isinstance(package, dict):
                raise ValueError(f"cargo audit warning entry is missing advisory/package data: {category}")
            advisory_id = advisory.get("id")
            package_name = package.get("name")
            package_version = package.get("version")
            if not all(isinstance(item, str) and item for item in (advisory_id, package_name, package_version)):
                raise ValueError(f"cargo audit warning entry is missing id/package/version data: {category}")
            warning_evidence.append(
                {
                    "category": category,
                    "id": advisory_id,
                    "package": package_name,
                    "version": package_version,
                }
            )

    warning_counts = dict(sorted(warning_counts.items()))
    warning_evidence.sort(key=lambda item: (item["category"], item["id"], item["package"], item["version"]))
    warning_count = sum(warning_counts.values())
    return {
        "status": "CODE_FAILURE" if vulnerability_list else "PASS",
        "vulnerabilityCount": len(vulnerability_list),
        "warningCount": warning_count,
        "warningsPresent": warning_count > 0,
        "warningCounts": warning_counts,
        "warnings": warning_evidence,
    }


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
        audit_status = parse_audit_receipt(load(audit_path))
        audit_status["receiptSha256"] = digest(audit_path.read_bytes())
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

        def write_receipt(name: str, value: object) -> Path:
            path = root / name
            path.write_text(json.dumps(value), encoding="utf-8")
            return path

        def warning(category: str, advisory_id: str, package: str, version: str) -> dict[str, object]:
            return {
                "kind": category,
                "package": {"name": package, "version": version},
                "advisory": {"id": advisory_id},
            }

        zero_vulnerability_warnings = write_receipt(
            "zero-vulnerability-warnings.json",
            {
                "vulnerabilities": {"found": False, "count": 0, "list": []},
                "warnings": {
                    "unsound": [warning("unsound", "RUSTSEC-2026-0097", "rand", "0.7.3")],
                    "unmaintained": [warning("unmaintained", "RUSTSEC-2024-0436", "paste", "1.0.15")],
                },
            },
        )
        value = audit(
            root / "metadata.json",
            root / "tree.txt",
            root / "Cargo.lock",
            zero_vulnerability_warnings,
            root / "sbom-warnings.json",
        )
        assert value["schema"] == "hartevo-ci-sbom/v1"
        warning_scan = value["vulnerabilityScan"]
        assert warning_scan["status"] == "PASS"
        assert warning_scan["vulnerabilityCount"] == 0
        assert warning_scan["warningsPresent"] is True
        assert warning_scan["warningCount"] == 2
        assert warning_scan["warningCounts"] == {"unmaintained": 1, "unsound": 1}
        assert warning_scan["warnings"] == [
            {"category": "unmaintained", "id": "RUSTSEC-2024-0436", "package": "paste", "version": "1.0.15"},
            {"category": "unsound", "id": "RUSTSEC-2026-0097", "package": "rand", "version": "0.7.3"},
        ]

        vulnerability = write_receipt(
            "vulnerability.json",
            {
                "vulnerabilities": {
                    "found": True,
                    "count": 1,
                    "list": [{"id": "RUSTSEC-2026-0235"}],
                },
                "warnings": {},
            },
        )
        value = audit(root / "metadata.json", root / "tree.txt", root / "Cargo.lock", vulnerability, root / "sbom-vulnerability.json")
        vulnerability_scan = value["vulnerabilityScan"]
        assert vulnerability_scan["status"] == "CODE_FAILURE"
        assert vulnerability_scan["vulnerabilityCount"] == 1
        assert vulnerability_scan["warningsPresent"] is False
        assert vulnerability_scan["warningCount"] == 0

        missing = audit(root / "metadata.json", root / "tree.txt", root / "Cargo.lock", None, root / "sbom-missing.json")
        assert missing["vulnerabilityScan"]["status"] == "BLOCKED_ENV"

        empty_receipt = write_receipt("empty.json", {})
        try:
            audit(root / "metadata.json", root / "tree.txt", root / "Cargo.lock", empty_receipt, root / "sbom-empty.json")
        except ValueError as error:
            assert "vulnerabilities" in str(error)
        else:
            raise AssertionError("empty cargo audit receipt was accepted")

        malformed_receipt = write_receipt(
            "malformed.json",
            {
                "vulnerabilities": {"found": False, "count": 0, "list": []},
                "warnings": {"unmaintained": [{"kind": "unmaintained"}]},
            },
        )
        try:
            audit(
                root / "metadata.json",
                root / "tree.txt",
                root / "Cargo.lock",
                malformed_receipt,
                root / "sbom-malformed.json",
            )
        except ValueError as error:
            assert "advisory/package" in str(error) or "id/package/version" in str(error)
        else:
            raise AssertionError("malformed cargo audit receipt was accepted")
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
