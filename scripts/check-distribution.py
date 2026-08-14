#!/usr/bin/env python3
"""Executable DIST-01 distribution, telemetry, and restore contract gate.

The script intentionally reports the distinction between a mechanically valid
contract, deterministic simulator evidence, unavailable native infrastructure,
and a releasable product.  It never turns a fixture, a test signing key, or a
BLOCKED_ENV result into product completion.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "hartevo-distribution-gate/v1"
RELEASE_DECISION = "NOT_EVALUATED"
CONTRACT_DIR = Path("contracts/distribution")
CONTRACTS = {
    "manifest": CONTRACT_DIR / "build-manifest.v1.json",
    "local_manifest": CONTRACT_DIR / "local-build-manifest.v1.json",
    "sbom": CONTRACT_DIR / "sbom.v1.json",
    "spdx": CONTRACT_DIR / "spdx-sbom.v1.json",
    "checksums": CONTRACT_DIR / "checksums.v1.json",
    "provenance": CONTRACT_DIR / "provenance.v1.json",
    "update": CONTRACT_DIR / "update-metadata.v1.json",
    "telemetry": CONTRACT_DIR / "telemetry.v1.json",
    "telemetry_v2": CONTRACT_DIR / "telemetry.v2.json",
    "restore": CONTRACT_DIR / "restore-drill.v1.json",
    "gate": CONTRACT_DIR / "gate.v1.json",
    "verification": CONTRACT_DIR / "verification.v1.json",
}
UPDATE_ROLE_NAMES = ("root", "targets", "snapshot", "timestamp", "rollback")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
FORBIDDEN_TELEMETRY_TERMS = (
    "authorization",
    "cookie",
    "credential",
    "email",
    "header",
    "password",
    "pii",
    "prompt",
    "secret",
    "stdout",
    "token",
    "transcript",
    "url",
    "user_content",
)


class GateError(Exception):
    def __init__(self, code: str, message: str, *, status: str = "FAIL") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class BlockedEnvironment(GateError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status="BLOCKED_ENV")


def fail(code: str, message: str) -> None:
    raise GateError(code, message)


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        fail(code, message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("DUPLICATE_JSON_KEY", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=unique_object)
    except GateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail("INVALID_JSON", f"{label} is not strict UTF-8 JSON: {error}")
    require(isinstance(value, dict), "JSON_ROOT_NOT_OBJECT", f"{label} root must be an object")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pretty_json(value))


def run(
    command: Sequence[str],
    repo: Path,
    *,
    check: bool = True,
    timeout: int = 180,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    merged_env = os.environ.copy()
    merged_env.update(env or {})
    try:
        completed = subprocess.run(
            list(command),
            cwd=repo,
            env=merged_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        if check:
            raise BlockedEnvironment("COMMAND_UNAVAILABLE", f"command could not run: {' '.join(command)}: {error}") from error
        return subprocess.CompletedProcess(list(command), 127, b"", str(error).encode())
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        fail("COMMAND_FAILED", f"command failed ({' '.join(command)}): {stderr[-2000:]}")
    return completed


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = run(("git", *args), repo, check=check)
    return result.stdout.decode("utf-8", errors="strict").strip()


def repo_relative(repo: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(repo.resolve())
    except ValueError as error:
        fail("PATH_OUTSIDE_REPOSITORY", f"artifact path is outside the repository: {path}")
        raise error
    value = relative.as_posix()
    require(not value.startswith("../") and value != "..", "PATH_ESCAPE", f"artifact path escapes repository: {value}")
    return value


def source_context(repo: Path) -> dict[str, Any]:
    commit = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    require(HEX40.fullmatch(commit) is not None, "GIT_COMMIT_INVALID", "HEAD is not a SHA-1 commit")
    require(HEX40.fullmatch(tree) is not None, "GIT_TREE_INVALID", "HEAD tree is not a SHA-1 tree")
    tree_bytes = run(("git", "ls-tree", "-r", "-z", "--full-tree", "HEAD"), repo).stdout
    dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=all"))
    source_date_epoch = int(git(repo, "show", "-s", "--format=%ct", "HEAD"))
    remote = git(repo, "remote", "get-url", "origin", check=False)
    if not remote or remote.startswith("git@"):
        remote = "https://github.com/tangpingqingwa/hartevo-desktop"
    remote = re.sub(r"^[^:]+://[^/@]+@", "https://", remote)
    remote = re.sub(r"^git@([^:]+):", r"https://\1/", remote)
    remote = remote.removesuffix("/")
    if remote.endswith(".git"):
        remote = remote[:-4]
    require(re.fullmatch(r"https://[^/@]+/[^/@]+/[^/@]+", remote) is not None, "REPOSITORY_URI_INVALID", "repository URI is not canonical")
    return {
        "commit": commit,
        "tree": tree,
        "treeSha256": sha256_bytes(tree_bytes),
        "dirty": dirty,
        "repository": remote,
        "sourceDateEpoch": source_date_epoch,
    }


def iso_at(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime(ISO_FORMAT)


def tool_version(repo: Path, command: str, args: Sequence[str]) -> str:
    result = run((command, *args), repo, check=False)
    return result.stdout.decode("utf-8", errors="replace").splitlines()[0].strip() or "unavailable"


def ensure_contracts(repo: Path) -> None:
    expected_versions = {
        "manifest": "hartevo-build-manifest/v1",
        "local_manifest": "hartevo-local-build-manifest/v1",
        "sbom": "hartevo-sbom/v1",
        "spdx": None,
        "checksums": "hartevo-distribution-checksums/v1",
        "provenance": "hartevo-distribution-provenance/v1",
        "update": "hartevo-update-metadata/v1",
        "telemetry": "hartevo-operational-telemetry/v1",
        "telemetry_v2": "hartevo-operational-telemetry/v2",
        "restore": "hartevo-restore-drill/v1",
        "gate": "hartevo-distribution-gate/v1",
        "verification": "hartevo-distribution-verification/v1",
    }
    for name, relative in CONTRACTS.items():
        path = repo / relative
        require(path.is_file() and not path.is_symlink(), "CONTRACT_MISSING", f"missing distribution contract {relative}")
        contract = load_json(path, str(relative))
        require(contract.get("type") == "object", "CONTRACT_NOT_OBJECT", f"{relative} must define an object schema")
        require(contract.get("additionalProperties") is False, "CONTRACT_NOT_STRICT", f"{relative} must reject unknown fields")
        if name == "spdx":
            require(contract.get("properties", {}).get("spdxVersion", {}).get("const") == "SPDX-2.3", "CONTRACT_VERSION_MISMATCH", f"{relative} has unexpected SPDX version")
        else:
            version = contract.get("properties", {}).get("schemaVersion", {}).get("const")
            require(version == expected_versions[name], "CONTRACT_VERSION_MISMATCH", f"{relative} has unexpected schemaVersion")


def catalog_snapshot(repo: Path, temporary: Path) -> dict[str, Any]:
    output = temporary / "catalog.json"
    run(
        ("cargo", "run", "-p", "hartevo-eval", "--locked", "--", "catalog", "export", "--output", str(output)),
        repo,
        env={"CARGO_TERM_COLOR": "never"},
        timeout=240,
    )
    snapshot = load_json(output, "catalog snapshot")
    digest = snapshot.get("digest")
    require(isinstance(digest, str) and HEX64.fullmatch(digest) is not None, "CATALOG_DIGEST_INVALID", "catalog snapshot digest is invalid")
    return snapshot


def rust_target(repo: Path) -> str:
    version = tool_version(repo, "rustc", ("-vV",))
    for line in version.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    return f"{platform.machine()}-unknown-{platform.system().lower()}"


def artifact_record(repo: Path, path: Path, artifact_id: str, kind: str, evidence_class: str, source_commit: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "ARTIFACT_MISSING", f"artifact is not a regular file: {path}")
    relative = repo_relative(repo, path)
    require(not Path(relative).is_absolute(), "ARTIFACT_ABSOLUTE_PATH", "artifact path must be relative")
    return {
        "id": artifact_id,
        "kind": kind,
        "path": relative,
        "sha256": sha256_file(path),
        "byteCount": path.stat().st_size,
        "evidenceClass": evidence_class,
        "sourceCommit": source_commit,
    }


def signing_status(repo: Path, ci_status: str) -> tuple[str, str, str]:
    blocked = "CI_NOT_EXECUTED" if ci_status == "CI_NOT_EXECUTED" else "BLOCKED_ENV"
    macos_sign = blocked
    notarization = blocked
    windows_sign = blocked
    app = os.environ.get("HARTEVO_MACOS_APP")
    identity = os.environ.get("HARTEVO_MACOS_CODESIGN_IDENTITY")
    if app and identity and shutil.which("codesign"):
        app_path = Path(app)
        if app_path.exists():
            result = run(("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_path)), repo, check=False)
            details = run(("codesign", "--display", "--verbose=4", str(app_path)), repo, check=False)
            authority = f"Authority={identity}".encode("utf-8")
            macos_sign = "PASS" if result.returncode == 0 and authority in details.stderr + details.stdout else "FAIL"
    notarized = os.environ.get("HARTEVO_MACOS_NOTARIZED_ARTIFACT")
    if notarized and shutil.which("xcrun"):
        notarization_result = run(("xcrun", "stapler", "validate", notarized), repo, check=False)
        notarization = "PASS" if notarization_result.returncode == 0 else "FAIL"
    signed_artifact = os.environ.get("HARTEVO_WINDOWS_SIGNED_ARTIFACT")
    if signed_artifact and shutil.which("signtool") and Path(signed_artifact).is_file():
        signing_result = run(("signtool", "verify", "/pa", "/all", signed_artifact), repo, check=False)
        windows_sign = "PASS" if signing_result.returncode == 0 else "FAIL"
    return macos_sign, notarization, windows_sign


def build_sbom(repo: Path, output: Path, source: dict[str, Any], ci_status: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="hartevo-distribution-catalog-") as temporary_name:
        snapshot = catalog_snapshot(repo, Path(temporary_name))
        metadata = run(
            ("cargo", "metadata", "--locked", "--format-version", "1"),
            repo,
            env={"CARGO_TERM_COLOR": "never"},
            timeout=240,
        )
    document = json.loads(metadata.stdout.decode("utf-8"))
    packages = document.get("packages")
    require(isinstance(packages, list) and packages, "CARGO_METADATA_INVALID", "cargo metadata returned no packages")
    components: list[dict[str, Any]] = []
    refs_by_id: dict[str, str] = {}
    missing_licenses: list[str] = []
    denied_licenses: list[str] = []
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        package_id = package.get("id")
        license_value = package.get("license")
        require(isinstance(name, str) and name, "CARGO_PACKAGE_INVALID", "package name is missing")
        require(isinstance(version, str) and version, "CARGO_PACKAGE_INVALID", f"package {name} has no version")
        require(isinstance(package_id, str) and package_id, "CARGO_PACKAGE_INVALID", f"package {name} has no id")
        source_value = package.get("source") or "path"
        if source_value == "path":
            bom_ref = f"pkg:generic/hartevo/{name}@{version}"
            purl = bom_ref
        else:
            bom_ref = f"pkg:cargo/{name}@{version}"
            purl = bom_ref
        if package_id not in refs_by_id:
            refs_by_id[package_id] = bom_ref
        if not isinstance(license_value, str) or not license_value.strip():
            missing_licenses.append(f"{name}@{version}")
            license_value = "UNKNOWN"
        upper_license = license_value.upper()
        if any(token in upper_license for token in ("AGPL", "GPL-3.0", "SSPL")):
            denied_licenses.append(f"{name}@{version}:{license_value}")
        components.append(
            {
                "type": "library",
                "bom-ref": bom_ref,
                "group": "hartevo" if source_value == "path" else "crates.io",
                "name": name,
                "version": version,
                "scope": "required",
                "purl": purl,
                "licenses": [{"license": {"name": license_value}}],
                "properties": [
                    {"name": "hartevo:source", "value": "path" if source_value == "path" else source_value},
                    {"name": "hartevo:package-id", "value": package_id},
                ],
            }
        )
    components.sort(key=lambda item: (item["name"], item["version"], item["bom-ref"]))
    dependencies: list[dict[str, Any]] = []
    resolve = document.get("resolve")
    resolved_nodes = resolve.get("nodes", []) if isinstance(resolve, dict) else []
    resolved_dependencies: dict[str, set[str]] = {}
    if isinstance(resolved_nodes, list):
        for node in resolved_nodes:
            if not isinstance(node, dict) or not isinstance(node.get("id"), str):
                continue
            resolved_dependencies[node["id"]] = {
                dependency["pkg"]
                for dependency in node.get("dependencies", [])
                if isinstance(dependency, dict) and isinstance(dependency.get("pkg"), str)
            }
    for package in packages:
        package_id = package["id"]
        ref = refs_by_id[package_id]
        dependency_ids = resolved_dependencies.get(package_id, set())
        dependencies.append(
            {
                "ref": ref,
                "dependsOn": sorted(
                    refs_by_id[dependency_id]
                    for dependency_id in dependency_ids
                    if dependency_id in refs_by_id
                ),
            }
        )
    dependencies.sort(key=lambda item: item["ref"])
    license_status = "PASS" if not missing_licenses and not denied_licenses else "FAIL"
    findings: list[str] = []
    if ci_status == "CI_NOT_EXECUTED" and license_status == "PASS":
        vulnerability_status = "CI_NOT_EXECUTED"
    elif shutil.which("cargo-audit") is None:
        vulnerability_status = "CI_NOT_EXECUTED" if ci_status == "CI_NOT_EXECUTED" else "BLOCKED_ENV"
    else:
        audit = run(("cargo-audit", "audit", "--locked", "--json"), repo, check=False, timeout=240)
        if audit.returncode != 0:
            vulnerability_status = "FAIL"
            findings = [audit.stderr.decode("utf-8", errors="replace")[-1000:]]
        else:
            try:
                audit_json = json.loads(audit.stdout.decode("utf-8"))
                findings = [str(item) for item in audit_json.get("vulnerabilities", {}).get("list", [])]
            except (UnicodeDecodeError, json.JSONDecodeError):
                findings = ["cargo-audit returned non-JSON output"]
            vulnerability_status = "FAIL" if findings else "PASS"
    serial_material = f"{source['commit']}:{source['tree']}".encode("utf-8")
    serial_hex = hashlib.sha256(serial_material).hexdigest()
    sbom = {
        "schemaVersion": "hartevo-sbom/v1",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_hex[:8]}-{serial_hex[8:12]}-{serial_hex[12:16]}-{serial_hex[16:20]}-{serial_hex[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": iso_at(source["sourceDateEpoch"]),
            "tools": ["cargo metadata --locked", "hartevo DIST-01 SBOM gate"],
            "component": {"type": "application", "bom-ref": "hartevo-desktop", "name": "hartevo-desktop", "version": "0.1.0"},
        },
        "components": components,
        "dependencies": dependencies,
        "licenseAudit": {
            "status": license_status,
            "policy": "declared SPDX-compatible license; deny AGPL/GPL-3.0/SSPL; local Proprietary is explicit",
            "missing": sorted(missing_licenses),
            "denied": sorted(denied_licenses),
        },
        "vulnerabilityAudit": {
            "status": vulnerability_status,
            "tool": "cargo-audit",
            "findings": findings,
        },
        "provenance": {
            "commit": source["commit"],
            "cargoLockSha256": sha256_file(repo / "Cargo.lock"),
            "catalogDigest": snapshot["digest"],
        },
    }
    write_json(output, sbom)
    return sbom


def build_manifest(
    repo: Path,
    output: Path,
    sbom_path: Path,
    sbom: Mapping[str, Any],
    source: dict[str, Any],
    ci_status: str,
    profile: str,
    artifact_path: Path | None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="hartevo-distribution-catalog-") as temporary_name:
        snapshot = catalog_snapshot(repo, Path(temporary_name))
    schema_records = []
    for relative in sorted(CONTRACT_DIR.glob("*.json")):
        schema_records.append({"path": relative.as_posix(), "sha256": sha256_file(repo / relative)})
    rustc = tool_version(repo, "rustc", ("--version",))
    cargo = tool_version(repo, "cargo", ("--version",))
    target = rust_target(repo)
    macos_sign, notarization, windows_sign = signing_status(repo, ci_status)
    artifacts = [artifact_record(repo, sbom_path, "dependency-sbom", "SBOM", "DETERMINISTIC_SIMULATOR", source["commit"])]
    if artifact_path is not None:
        # An externally supplied binary has not been built and verified by this
        # gate. Keep it explicitly blocked until native signing/notarization
        # evidence is attached by the platform release workflow.
        artifacts.append(artifact_record(repo, artifact_path, "desktop-application", "APPLICATION", "BLOCKED_ENV", source["commit"]))
    manifest = {
        "schemaVersion": "hartevo-build-manifest/v1",
        "manifestId": f"commit-{source['commit']}",
        "releaseDecision": RELEASE_DECISION,
        "releaseEligible": False,
        "source": source,
        "toolchain": {"rustc": rustc, "cargo": cargo, "target": target},
        "build": {
            "profile": profile,
            "target": target,
            "reproducible": True,
            "cargoLockSha256": sha256_file(repo / "Cargo.lock"),
            "commands": [
                {"id": "cargo-metadata", "argv": ["cargo", "metadata", "--locked", "--format-version", "1"]},
                {"id": "catalog-validate", "argv": ["cargo", "run", "-p", "hartevo-eval", "--locked", "--", "catalog", "validate"]},
                {"id": "desktop-build", "argv": ["cargo", "build", "-p", "hartevo-desktop", "--locked", f"--{profile}"]},
            ],
            "environment": {
                "sourceDateEpoch": source["sourceDateEpoch"],
                "networkPolicy": "offline" if os.environ.get("HARTEVO_DISTRIBUTION_OFFLINE") == "1" else "locked-network",
            },
        },
        "catalog": {
            "digest": snapshot["digest"],
            "schemaVersion": snapshot["schemaVersion"],
            "applicationHandlerRegistryVersion": snapshot.get("applicationHandlerRegistryVersion", "unknown"),
            "releaseEvidenceSchemaVersion": "2.3.0",
        },
        "schemas": schema_records,
        "artifacts": artifacts,
        "sbom": {
            "path": repo_relative(repo, sbom_path),
            "sha256": sha256_file(sbom_path),
            "componentCount": len(sbom["components"]),
            "licenseStatus": sbom["licenseAudit"]["status"],
            "vulnerabilityStatus": sbom["vulnerabilityAudit"]["status"],
        },
        "platform": {
            "os": platform.system().lower(),
            "architecture": platform.machine(),
            "macosSigning": macos_sign,
            "macosNotarization": notarization,
            "windowsSigning": windows_sign,
        },
        "nativeEvidence": {"status": "NOT_PROVEN", "required": True, "releaseEligible": False},
    }
    write_json(output, manifest)
    return manifest


def build_spdx_sbom(repo: Path, output: Path, source: Mapping[str, Any]) -> dict[str, Any]:
    metadata = run(
        ("cargo", "metadata", "--locked", "--format-version", "1"),
        repo,
        env={"CARGO_TERM_COLOR": "never"},
        timeout=240,
    )
    document = json.loads(metadata.stdout.decode("utf-8"))
    packages = document.get("packages")
    require(isinstance(packages, list) and packages, "CARGO_METADATA_INVALID", "cargo metadata returned no packages")
    refs_by_id: dict[str, str] = {}
    spdx_packages: list[dict[str, Any]] = []
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        package_id = package.get("id")
        require(isinstance(name, str) and name, "CARGO_PACKAGE_INVALID", "package name is missing")
        require(isinstance(version, str) and version, "CARGO_PACKAGE_INVALID", f"package {name} has no version")
        require(isinstance(package_id, str) and package_id, "CARGO_PACKAGE_INVALID", f"package {name} has no id")
        package_digest = sha256_bytes(f"{package_id}:{name}:{version}".encode("utf-8"))
        spdx_id = f"SPDXRef-Package-{package_digest[:24]}"
        refs_by_id[package_id] = spdx_id
        license_value = package.get("license")
        if not isinstance(license_value, str) or not license_value.strip():
            license_value = "NOASSERTION"
        spdx_packages.append(
            {
                "SPDXID": spdx_id,
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license_value,
                "copyrightText": "NOASSERTION",
            }
        )
    spdx_packages.sort(key=lambda package: (package["name"], package["versionInfo"], package["SPDXID"]))
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
        for package in spdx_packages
    ]
    resolve = document.get("resolve")
    resolved_nodes = resolve.get("nodes", []) if isinstance(resolve, dict) else []
    if isinstance(resolved_nodes, list):
        for node in resolved_nodes:
            if not isinstance(node, dict) or not isinstance(node.get("id"), str):
                continue
            source_ref = refs_by_id.get(node["id"])
            if source_ref is None:
                continue
            dependency_ids = {
                dependency.get("pkg")
                for dependency in node.get("dependencies", [])
                if isinstance(dependency, dict) and isinstance(dependency.get("pkg"), str)
            }
            for dependency_id in sorted(dependency_ids):
                target_ref = refs_by_id.get(dependency_id)
                if target_ref is not None:
                    relationships.append(
                        {
                            "spdxElementId": source_ref,
                            "relationshipType": "DEPENDS_ON",
                            "relatedSpdxElement": target_ref,
                        }
                    )
    relationships.sort(key=lambda relationship: (relationship["spdxElementId"], relationship["relationshipType"], relationship["relatedSpdxElement"]))
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "hartevo-desktop dependencies",
        "documentNamespace": f"https://hartevo.example/spdx/{source['commit']}/{source['treeSha256']}",
        "creationInfo": {
            "created": iso_at(source["sourceDateEpoch"]),
            "creators": ["Tool: hartevo DIST-02 local distribution gate"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }
    write_json(output, spdx)
    return spdx


def hook_record(repo: Path, name: str, status: str, evidence_environment: str) -> dict[str, Any]:
    record: dict[str, Any] = {"status": status, "hook": name}
    if status == "PASS":
        evidence_value = os.environ.get(evidence_environment)
        require(evidence_value, "SIGNING_EVIDENCE_MISSING", f"{name} PASS requires {evidence_environment}")
        evidence_path = Path(evidence_value).expanduser().resolve()
        require(evidence_path.is_file() and not evidence_path.is_symlink(), "SIGNING_EVIDENCE_MISSING", f"{name} evidence must be a regular file")
        record["evidencePath"] = repo_relative(repo, evidence_path)
        record["evidenceSha256"] = sha256_file(evidence_path)
    return record


def signing_hook_records(repo: Path, statuses: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "macosSigning": hook_record(repo, "codesign", statuses[0], "HARTEVO_MACOS_SIGNING_EVIDENCE"),
        "macosNotarization": hook_record(repo, "notarytool-stapler", statuses[1], "HARTEVO_MACOS_NOTARIZATION_EVIDENCE"),
        "windowsSigning": hook_record(repo, "signtool", statuses[2], "HARTEVO_WINDOWS_SIGNING_EVIDENCE"),
    }


def build_local_manifest(
    repo: Path,
    output: Path,
    sbom_path: Path,
    sbom: Mapping[str, Any],
    spdx_path: Path,
    spdx: Mapping[str, Any],
    source: Mapping[str, Any],
    profile: str,
    artifact_path: Path | None,
    signing_hooks: Mapping[str, Any],
    checksums_path: Path,
    provenance_path: Path,
    telemetry_path: Path,
) -> dict[str, Any]:
    rustc = tool_version(repo, "rustc", ("--version",))
    cargo = tool_version(repo, "cargo", ("--version",))
    target = rust_target(repo)
    toolchain = {"rustc": rustc, "cargo": cargo, "target": target}
    artifacts = [
        artifact_record(repo, sbom_path, "cyclonedx-sbom", "SBOM", "LOCAL_CONTRACT", source["commit"]),
        artifact_record(repo, spdx_path, "spdx-sbom", "SBOM", "LOCAL_CONTRACT", source["commit"]),
    ]
    if artifact_path is not None:
        artifacts.append(artifact_record(repo, artifact_path, "desktop-application", "APPLICATION", "BLOCKED_ENV", source["commit"]))
    manifest = {
        "schemaVersion": "hartevo-local-build-manifest/v1",
        "manifestId": f"commit-{source['commit']}",
        "releaseDecision": RELEASE_DECISION,
        "releaseReady": False,
        "source": dict(source),
        "toolchain": toolchain,
        "build": {
            "profile": profile,
            "target": target,
            "reproducible": True,
            "cargoLockSha256": sha256_file(repo / "Cargo.lock"),
            "commands": [
                {"id": "cargo-metadata", "argv": ["cargo", "metadata", "--locked", "--format-version", "1"]},
                {"id": "catalog-validate", "argv": ["cargo", "run", "-p", "hartevo-eval", "--locked", "--", "catalog", "validate"]},
                {"id": "distribution-verify", "argv": ["cargo", "run", "-p", "hartevo-eval", "--locked", "--", "distribution", "verify"]},
            ],
            "environment": {
                "sourceDateEpoch": source["sourceDateEpoch"],
                "networkPolicy": "offline" if os.environ.get("HARTEVO_DISTRIBUTION_OFFLINE") == "1" else "locked-network",
            },
        },
        "artifacts": artifacts,
        "sbom": {
            "cycloneDx": {"path": repo_relative(repo, sbom_path), "sha256": sha256_file(sbom_path), "byteCount": sbom_path.stat().st_size},
            "spdx": {"path": repo_relative(repo, spdx_path), "sha256": sha256_file(spdx_path), "byteCount": spdx_path.stat().st_size},
        },
        "checksums": {"path": repo_relative(repo, checksums_path)},
        "provenance": {"path": repo_relative(repo, provenance_path)},
        "telemetry": {"path": repo_relative(repo, telemetry_path)},
        "signingHooks": dict(signing_hooks),
        "nativeEvidence": {"status": "NOT_PROVEN", "requiredForRelease": True, "releaseEligible": False},
    }
    require(len(spdx["packages"]) > 0, "SPDX_EMPTY", "SPDX SBOM has no packages")
    write_json(output, manifest)
    return manifest


def build_checksums(
    repo: Path,
    output: Path,
    source: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    records: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    checksums = {
        "schemaVersion": "hartevo-distribution-checksums/v1",
        "algorithm": "SHA-256",
        "sourceCommit": source["commit"],
        "toolchain": dict(toolchain),
        "artifacts": list(records),
    }
    write_json(output, checksums)
    return checksums


def build_provenance(
    repo: Path,
    output: Path,
    source: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    checksums_path: Path,
    records: Sequence[dict[str, Any]],
    signing_hooks: Mapping[str, Any],
) -> dict[str, Any]:
    provenance = {
        "schemaVersion": "hartevo-distribution-provenance/v1",
        "source": dict(source),
        "toolchain": dict(toolchain),
        "checksumManifest": {
            "path": repo_relative(repo, checksums_path),
            "sha256": sha256_file(checksums_path),
            "byteCount": checksums_path.stat().st_size,
        },
        "artifacts": list(records),
        "signingHooks": dict(signing_hooks),
        "nativeEvidence": {"status": "NOT_PROVEN", "requiredForRelease": True, "releaseEligible": False},
        "releaseDecision": RELEASE_DECISION,
        "releaseReady": False,
    }
    write_json(output, provenance)
    return provenance


def crypto(repo: Path, operation: str, **paths: Path) -> None:
    if operation == "keygen":
        command = ("cargo", "run", "-p", "hartevo-eval", "--locked", "--", "distribution", "crypto", "keygen", "--private-key", str(paths["private"]), "--public-key", str(paths["public"]))
    elif operation == "sign":
        command = ("cargo", "run", "-p", "hartevo-eval", "--locked", "--", "distribution", "crypto", "sign", "--private-key", str(paths["private"]), "--input", str(paths["input"]), "--output", str(paths["signature"]))
    elif operation == "verify":
        command = ("cargo", "run", "-p", "hartevo-eval", "--locked", "--", "distribution", "crypto", "verify", "--public-key", str(paths["public"]), "--input", str(paths["input"]), "--signature", str(paths["signature"]))
    else:
        fail("CRYPTO_OPERATION_UNKNOWN", operation)
    run(command, repo, env={"CARGO_TERM_COLOR": "never"}, timeout=240)


def prepare_signers(repo: Path, temporary: Path) -> tuple[dict[str, Path], dict[str, Path], bool, int]:
    configured = os.environ.get("HARTEVO_UPDATE_SIGNING_KEY")
    if configured:
        private = Path(configured).expanduser().resolve()
        public_value = os.environ.get("HARTEVO_UPDATE_PUBLIC_KEY")
        require(private.is_file(), "UPDATE_PRIVATE_KEY_MISSING", "HARTEVO_UPDATE_SIGNING_KEY is not a regular file")
        require(public_value, "UPDATE_PUBLIC_KEY_MISSING", "HARTEVO_UPDATE_PUBLIC_KEY must point to a raw 32-byte public key file")
        public = Path(public_value).expanduser().resolve()
        require(public.is_file(), "UPDATE_PUBLIC_KEY_MISSING", "HARTEVO_UPDATE_PUBLIC_KEY is not a regular file")
        key_id = os.environ.get("HARTEVO_UPDATE_KEY_ID", "release-key-1")
        require(SAFE_ID.fullmatch(key_id) is not None, "UPDATE_KEY_ID_INVALID", "HARTEVO_UPDATE_KEY_ID must be a safe lowercase identifier")
        return {key_id: private}, {key_id: public}, False, 1
    signers: dict[str, Path] = {}
    public_keys: dict[str, Path] = {}
    for index in range(1, 3):
        private = temporary / f"test-key-{index}.pk8"
        public = temporary / f"test-key-{index}.pub"
        crypto(repo, "keygen", private=private, public=public)
        signers[f"test-key-{index}"] = private
        public_keys[f"test-key-{index}"] = public
    return signers, public_keys, True, 2


def signature_for(repo: Path, signed: Mapping[str, Any], private: Path, temporary: Path) -> str:
    payload = temporary / f"payload-{uuid.uuid4().hex}.json"
    signature = temporary / f"signature-{uuid.uuid4().hex}.bin"
    payload.write_bytes(canonical_json(signed))
    crypto(repo, "sign", private=private, input=payload, signature=signature)
    return base64.b64encode(signature.read_bytes()).decode("ascii")


def envelope(repo: Path, signed: dict[str, Any], role: str, signers: Mapping[str, Path], threshold: int, temporary: Path) -> dict[str, Any]:
    signatures = [
        {"keyid": key_id, "sig": signature_for(repo, signed, private, temporary)}
        for key_id, private in sorted(signers.items())
    ]
    require(len(signatures) >= threshold, "SIGNER_THRESHOLD_UNAVAILABLE", f"{role} threshold cannot be satisfied")
    return {"signed": signed, "signatures": signatures}


def update_metadata(
    repo: Path,
    output_dir: Path,
    manifest_path: Path,
    sbom_path: Path,
    source: Mapping[str, Any],
    channel: str,
    architecture: str,
    sequence: int,
    artifact_path: Path | None,
    signer_bundle: tuple[dict[str, Path], dict[str, Path], bool, int] | None = None,
) -> dict[str, Any]:
    require(channel in {"alpha", "beta", "stable"}, "UPDATE_CHANNEL_INVALID", "channel must be alpha, beta, or stable")
    require(sequence > 0, "UPDATE_SEQUENCE_INVALID", "update sequence must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hartevo-update-signers-") as temporary_name:
        temporary = Path(temporary_name)
        if signer_bundle is None:
            signers, public_paths, test_only, threshold = prepare_signers(repo, temporary)
        else:
            signers, public_paths, test_only, threshold = signer_bundle
        keys: dict[str, dict[str, str]] = {}
        for key_id, private in signers.items():
            public_path = public_paths[key_id]
            if not public_path.is_file():
                crypto(repo, "public-key", private=private, public=public_path)
            raw_public = public_path.read_bytes()
            require(len(raw_public) == 32, "UPDATE_PUBLIC_KEY_INVALID", "update public key must contain 32 raw bytes")
            keys[key_id] = {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "publicKey": base64.b64encode(raw_public).decode("ascii"),
            }
        roles = {role: {"keyids": sorted(signers), "threshold": threshold} for role in UPDATE_ROLE_NAMES}
        root_signed = {
            "_type": "root",
            "specVersion": "1.0.0",
            "version": 1,
            "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).strftime(ISO_FORMAT),
            "keys": keys,
            "roles": roles,
            "releaseDecision": RELEASE_DECISION,
        }
        root = envelope(repo, root_signed, "root", signers, threshold, temporary)
        target_files = {
            "build-manifest.json": manifest_path,
            "sbom.json": sbom_path,
        }
        if artifact_path is not None:
            target_files["application-artifact"] = artifact_path
        targets: dict[str, Any] = {}
        for target_name, path in sorted(target_files.items()):
            target = {
                "length": path.stat().st_size,
                "hashes": {"sha256": sha256_file(path)},
                "custom": {
                    "commit": source["commit"],
                    "channel": channel,
                    "architecture": architecture,
                    "sequence": sequence,
                    "releaseVersion": str(sequence),
                    "manifestSha256": sha256_file(manifest_path),
                    "sbomSha256": sha256_file(sbom_path),
                    "releaseDecision": RELEASE_DECISION,
                    "releaseReady": False,
                    "nativeEvidence": "NOT_PROVEN",
                },
            }
            targets[target_name] = target
        targets_signed = {
            "_type": "targets",
            "specVersion": "1.0.0",
            "version": sequence,
            "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).strftime(ISO_FORMAT),
            "targets": targets,
            "rollbackProtection": {
                "mode": "monotonic-unless-authorized",
                "highestSequence": sequence,
                "requiresSignedAuthorization": True,
            },
            "releaseDecision": RELEASE_DECISION,
        }
        targets_envelope = envelope(repo, targets_signed, "targets", signers, threshold, temporary)
        targets_bytes = pretty_json(targets_envelope)
        targets_ref = {"version": sequence, "length": len(targets_bytes), "hashes": {"sha256": sha256_bytes(targets_bytes)}}
        snapshot_signed = {
            "_type": "snapshot",
            "specVersion": "1.0.0",
            "version": sequence,
            "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).strftime(ISO_FORMAT),
            "meta": {"targets.json": targets_ref},
            "releaseDecision": RELEASE_DECISION,
        }
        snapshot_envelope = envelope(repo, snapshot_signed, "snapshot", signers, threshold, temporary)
        snapshot_bytes = pretty_json(snapshot_envelope)
        snapshot_ref = {"version": sequence, "length": len(snapshot_bytes), "hashes": {"sha256": sha256_bytes(snapshot_bytes)}}
        timestamp_signed = {
            "_type": "timestamp",
            "specVersion": "1.0.0",
            "version": sequence,
            "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).strftime(ISO_FORMAT),
            "meta": {"snapshot.json": snapshot_ref},
            "releaseDecision": RELEASE_DECISION,
        }
        timestamp_envelope = envelope(repo, timestamp_signed, "timestamp", signers, threshold, temporary)
        write_json(output_dir / "root.json", root)
        write_json(output_dir / "targets.json", targets_envelope)
        write_json(output_dir / "snapshot.json", snapshot_envelope)
        write_json(output_dir / "timestamp.json", timestamp_envelope)
        feed = {
            "schemaVersion": "hartevo-update-metadata/v1",
            "channel": channel,
            "architecture": architecture,
            "root": "root.json",
            "targets": "targets.json",
            "snapshot": "snapshot.json",
            "timestamp": "timestamp.json",
            "rollbackPolicy": {
                "mode": "monotonic-unless-authorized",
                "requiresSignedAuthorization": True,
                "freezeProtection": True,
                "maxClockSkewSeconds": 300,
            },
            "releaseDecision": RELEASE_DECISION,
            "signingIdentity": "TEST_ONLY" if test_only else "CONFIGURED_RELEASE_KEY",
        }
        write_json(output_dir / "update-metadata.json", feed)
        return feed


def verify_envelope(repo: Path, value: Mapping[str, Any], role: str, root_signed: Mapping[str, Any], temporary: Path) -> None:
    signed = value.get("signed")
    signatures = value.get("signatures")
    require(isinstance(signed, dict), "UPDATE_SIGNED_MISSING", f"{role} signed body is missing")
    require(isinstance(signatures, list), "UPDATE_SIGNATURES_MISSING", f"{role} signatures are missing")
    root_roles = root_signed.get("roles", {})
    role_definition = root_roles.get(role)
    require(isinstance(role_definition, dict), "UPDATE_ROLE_MISSING", f"root does not define {role} role")
    keyids = role_definition.get("keyids")
    threshold = role_definition.get("threshold")
    require(isinstance(keyids, list) and isinstance(threshold, int), "UPDATE_ROLE_INVALID", f"{role} role is malformed")
    keys = root_signed.get("keys", {})
    verified: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="hartevo-update-verify-") as verify_dir_name:
        verify_dir = Path(verify_dir_name)
        payload = verify_dir / "payload.json"
        payload.write_bytes(canonical_json(signed))
        for signature in signatures:
            require(isinstance(signature, dict), "UPDATE_SIGNATURE_INVALID", f"{role} signature is not an object")
            key_id = signature.get("keyid")
            encoded = signature.get("sig")
            if key_id in verified:
                fail("UPDATE_SIGNATURE_DUPLICATE", f"{role} repeats key {key_id}")
            require(key_id in keyids, "UPDATE_SIGNATURE_UNAUTHORIZED", f"{role} signature key is not authorized")
            key = keys.get(key_id)
            require(isinstance(key, dict), "UPDATE_KEY_MISSING", f"update key {key_id} is missing")
            raw_public = base64.b64decode(key.get("publicKey", ""), validate=True)
            require(len(raw_public) == 32, "UPDATE_KEY_INVALID", f"update key {key_id} is not a raw Ed25519 key")
            public = verify_dir / f"{key_id}.pub"
            signature_file = verify_dir / f"{key_id}.sig"
            public.write_bytes(raw_public)
            signature_file.write_bytes(base64.b64decode(encoded, validate=True))
            crypto(repo, "verify", public=public, input=payload, signature=signature_file)
            verified.add(key_id)
    require(len(verified) >= threshold, "UPDATE_SIGNATURE_THRESHOLD", f"{role} has {len(verified)} valid signatures but requires {threshold}")


def parse_expiry(value: Any, label: str) -> dt.datetime:
    require(isinstance(value, str), "UPDATE_EXPIRY_INVALID", f"{label} expiry is not a string")
    try:
        return dt.datetime.strptime(value, ISO_FORMAT).replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        fail("UPDATE_EXPIRY_INVALID", f"{label} expiry is not canonical: {error}")
        raise error


def verify_update(
    repo: Path,
    output_dir: Path,
    expected_channel: str,
    expected_architecture: str,
    installed_sequence: int,
    rollback_token: Path | None = None,
    expected_commit: str | None = None,
) -> None:
    feed = load_json(output_dir / "update-metadata.json", "update feed")
    require(feed.get("schemaVersion") == "hartevo-update-metadata/v1", "UPDATE_FEED_SCHEMA", "update feed schema mismatch")
    require(feed.get("channel") == expected_channel, "UPDATE_CHANNEL_MISMATCH", "update channel mismatch")
    require(feed.get("architecture") == expected_architecture, "UPDATE_ARCHITECTURE_MISMATCH", "update architecture mismatch")
    require(feed.get("releaseDecision") == RELEASE_DECISION, "UPDATE_RELEASE_DECISION", "update feed may not evaluate release")
    require(feed.get("signingIdentity") in {"TEST_ONLY", "CONFIGURED_RELEASE_KEY"}, "UPDATE_SIGNING_IDENTITY", "update feed signing identity is invalid")
    root = load_json(output_dir / feed["root"], "root metadata")
    targets = load_json(output_dir / feed["targets"], "targets metadata")
    snapshot = load_json(output_dir / feed["snapshot"], "snapshot metadata")
    timestamp = load_json(output_dir / feed["timestamp"], "timestamp metadata")
    root_signed = root.get("signed")
    require(isinstance(root_signed, dict), "UPDATE_ROOT_INVALID", "root signed body missing")
    verify_envelope(repo, root, "root", root_signed, output_dir)
    for role, value in (("targets", targets), ("snapshot", snapshot), ("timestamp", timestamp)):
        verify_envelope(repo, value, role, root_signed, output_dir)
    now = dt.datetime.now(dt.timezone.utc)
    for role, value in (("root", root), ("targets", targets), ("snapshot", snapshot), ("timestamp", timestamp)):
        expiry = parse_expiry(value["signed"].get("expires"), role)
        require(expiry > now, "UPDATE_METADATA_EXPIRED", f"{role} metadata is expired")
    targets_signed = targets["signed"]
    snapshot_signed = snapshot["signed"]
    timestamp_signed = timestamp["signed"]
    require(snapshot_signed["meta"]["targets.json"]["version"] == targets_signed["version"], "UPDATE_SNAPSHOT_VERSION", "snapshot target version mismatch")
    require(snapshot_signed["meta"]["targets.json"]["hashes"]["sha256"] == sha256_file(output_dir / feed["targets"]), "UPDATE_SNAPSHOT_DIGEST", "snapshot target digest mismatch")
    require(timestamp_signed["meta"]["snapshot.json"]["version"] == snapshot_signed["version"], "UPDATE_TIMESTAMP_VERSION", "timestamp snapshot version mismatch")
    require(timestamp_signed["meta"]["snapshot.json"]["hashes"]["sha256"] == sha256_file(output_dir / feed["snapshot"]), "UPDATE_TIMESTAMP_DIGEST", "timestamp snapshot digest mismatch")
    sequence = targets_signed.get("version")
    require(isinstance(sequence, int) and sequence > 0, "UPDATE_SEQUENCE_INVALID", "targets version must be positive")
    if sequence < installed_sequence:
        require(rollback_token is not None, "UPDATE_ROLLBACK_UNAUTHORIZED", "rollback requires a separately signed authorization token")
        token = load_json(rollback_token, "rollback authorization")
        verify_envelope(repo, token, "rollback", root_signed, output_dir)
        token_signed = token["signed"]
        require(token_signed.get("schemaVersion") == "hartevo-update-rollback-authorization/v1", "UPDATE_ROLLBACK_TOKEN_SCHEMA", "rollback token schema mismatch")
        require(token_signed.get("fromSequence") == installed_sequence, "UPDATE_ROLLBACK_FROM_MISMATCH", "rollback token does not authorize the installed sequence")
        require(token_signed.get("toSequence") == sequence, "UPDATE_ROLLBACK_TO_MISMATCH", "rollback token does not authorize this target sequence")
        require(token_signed.get("targetSha256") == sha256_file(output_dir / feed["targets"]), "UPDATE_ROLLBACK_TARGET_MISMATCH", "rollback token target digest mismatch")
        require(token_signed.get("releaseDecision") == RELEASE_DECISION, "UPDATE_ROLLBACK_RELEASE_DECISION", "rollback token may not evaluate release")
    for target_name, target in targets_signed.get("targets", {}).items():
        require(isinstance(target, dict), "UPDATE_TARGET_INVALID", f"target {target_name} is malformed")
        custom = target.get("custom")
        require(isinstance(custom, dict), "UPDATE_TARGET_CUSTOM_MISSING", f"target {target_name} has no custom binding")
        require(custom.get("channel") == expected_channel, "UPDATE_TARGET_CHANNEL", f"target {target_name} channel mismatch")
        require(custom.get("architecture") == expected_architecture, "UPDATE_TARGET_ARCHITECTURE", f"target {target_name} architecture mismatch")
        require(custom.get("sequence") == sequence, "UPDATE_TARGET_SEQUENCE", f"target {target_name} sequence mismatch")
        if expected_commit is not None:
            require(custom.get("commit") == expected_commit, "UPDATE_TARGET_COMMIT", f"target {target_name} is not bound to the expected commit")
        require(custom.get("releaseReady") is False, "UPDATE_TARGET_RELEASE_READY", "update target may not claim release readiness")
        require(custom.get("nativeEvidence") == "NOT_PROVEN", "UPDATE_TARGET_NATIVE_EVIDENCE", "update target native evidence must remain NOT_PROVEN")
        target_path = output_dir.parent / target_name if target_name in {"build-manifest.json", "sbom.json"} else None
        if target_path is not None and target_path.is_file():
            require(target["length"] == target_path.stat().st_size, "UPDATE_TARGET_LENGTH", f"target {target_name} length mismatch")
            require(target["hashes"]["sha256"] == sha256_file(target_path), "UPDATE_TARGET_DIGEST", f"target {target_name} digest mismatch")
            require(custom.get("manifestSha256") == sha256_file(output_dir.parent / "build-manifest.json"), "UPDATE_MANIFEST_BINDING", "update target manifest binding drifted")
            require(custom.get("sbomSha256") == sha256_file(output_dir.parent / "sbom.json"), "UPDATE_SBOM_BINDING", "update target SBOM binding drifted")


def make_rollback_token(
    repo: Path,
    output: Path,
    from_sequence: int,
    to_sequence: int,
    target_digest: str,
    signer_bundle: tuple[dict[str, Path], dict[str, Path], bool, int],
) -> None:
    signers, _, _, threshold = signer_bundle
    with tempfile.TemporaryDirectory(prefix="hartevo-rollback-signers-") as temporary_name:
        temporary = Path(temporary_name)
        token_signed = {
            "schemaVersion": "hartevo-update-rollback-authorization/v1",
            "fromSequence": from_sequence,
            "toSequence": to_sequence,
            "targetSha256": target_digest,
            "reason": "authorized disaster-recovery rollback drill",
            "approvedAt": dt.datetime.now(dt.timezone.utc).strftime(ISO_FORMAT),
            "releaseDecision": RELEASE_DECISION,
        }
        token = envelope(repo, token_signed, "rollback", signers, threshold, temporary)
        write_json(output, token)


def pseudonym(value: str, salt: bytes, field: str) -> str:
    return hmac.new(salt, f"{field}\0{value}".encode("utf-8"), hashlib.sha256).hexdigest()


def telemetry_event(source: Mapping[str, Any], manifest_sha: str, opt_in: bool) -> dict[str, Any]:
    salt = os.environ.get("HARTEVO_TELEMETRY_HASH_SALT", "dist01-test-only-salt").encode("utf-8")
    status = "started" if opt_in else "disabled"
    event_name = "app.start"
    event_body = {
        "schemaVersion": "hartevo-operational-telemetry/v1",
        "eventName": event_name,
        "eventId": pseudonym(f"{source['commit']}:{event_name}:0", salt, "event"),
        "occurredAt": iso_at(source["sourceDateEpoch"]),
        "buildCommit": source["commit"],
        "buildManifestSha256": manifest_sha,
        "tenantPseudonym": pseudonym("dist01-tenant", salt, "tenant"),
        "projectPseudonym": pseudonym("dist01-project", salt, "project"),
        "missionPseudonym": pseudonym("dist01-mission", salt, "mission"),
        "runPseudonym": pseudonym("dist01-run", salt, "run"),
        "checkpointPseudonym": pseudonym("dist01-checkpoint", salt, "checkpoint"),
        "effectPseudonym": pseudonym("dist01-effect", salt, "effect"),
        "providerId": "local-runtime",
        "sequence": 0,
        "status": status,
        "durationMs": 0,
        "attributes": {},
    }
    return {
        "schemaVersion": "hartevo-operational-telemetry/v1",
        "policy": {
            "defaultEnabled": False,
            "optInRequired": True,
            "contentAllowed": False,
            "secretAllowed": False,
            "piiAllowed": False,
            "retentionDays": 7,
        },
        "event": event_body,
    }


def telemetry_event_v2(source: Mapping[str, Any], manifest_sha: str, opt_in: bool) -> dict[str, Any]:
    value = telemetry_event(source, manifest_sha, opt_in)
    value["schemaVersion"] = "hartevo-operational-telemetry/v2"
    value["policy"]["contentFree"] = True
    value["event"]["schemaVersion"] = "hartevo-operational-telemetry/v2"
    return value


def validate_telemetry(value: Mapping[str, Any]) -> None:
    require(value.get("schemaVersion") == "hartevo-operational-telemetry/v1", "TELEMETRY_SCHEMA", "telemetry schema mismatch")
    policy = value.get("policy")
    require(isinstance(policy, dict), "TELEMETRY_POLICY", "telemetry policy missing")
    require(policy.get("defaultEnabled") is False and policy.get("optInRequired") is True, "TELEMETRY_OPT_IN", "telemetry must be opt-in")
    require(policy.get("contentAllowed") is False and policy.get("secretAllowed") is False and policy.get("piiAllowed") is False and policy.get("retentionDays") == 7, "TELEMETRY_CONTENT_POLICY", "telemetry policy allows content or sensitive data")
    event = value.get("event")
    require(isinstance(event, dict), "TELEMETRY_EVENT", "telemetry event missing")
    require(event.get("schemaVersion") == "hartevo-operational-telemetry/v1", "TELEMETRY_EVENT_SCHEMA", "telemetry event schema mismatch")
    require(event.get("eventName") in {"app.start", "app.update_check", "app.update_apply", "app.rollback", "run.started", "run.terminal", "run.failure", "restore.drill", "crash.redacted"}, "TELEMETRY_EVENT_NAME", "telemetry event name is not allowlisted")
    for key in FORBIDDEN_TELEMETRY_TERMS:
        require(key not in {str(field).lower() for field in event}, "TELEMETRY_FORBIDDEN_FIELD", f"telemetry event contains forbidden field {key}")
    require(HEX40.fullmatch(str(event.get("buildCommit", ""))) is not None, "TELEMETRY_COMMIT", "telemetry build commit is invalid")
    require(isinstance(event.get("occurredAt"), str), "TELEMETRY_TIME", "telemetry timestamp is invalid")
    try:
        dt.datetime.strptime(event["occurredAt"], ISO_FORMAT)
    except ValueError as error:
        fail("TELEMETRY_TIME", f"telemetry timestamp is not canonical: {error}")
    for field in ("eventId", "buildManifestSha256", "tenantPseudonym", "projectPseudonym", "missionPseudonym", "runPseudonym", "checkpointPseudonym", "effectPseudonym"):
        require(HEX64.fullmatch(str(event.get(field, ""))) is not None, "TELEMETRY_DIGEST", f"telemetry {field} is not a digest")
    require(SAFE_ID.fullmatch(str(event.get("providerId", ""))) is not None, "TELEMETRY_PROVIDER", "telemetry provider id is invalid")
    require(isinstance(event.get("sequence"), int) and event["sequence"] >= 0, "TELEMETRY_SEQUENCE", "telemetry sequence is invalid")
    require(event.get("status") in {"started", "in_progress", "succeeded", "failed", "uncertain", "blocked", "disabled"}, "TELEMETRY_STATUS", "telemetry status is invalid")
    require(isinstance(event.get("durationMs"), int) and event["durationMs"] >= 0, "TELEMETRY_DURATION", "telemetry duration is invalid")
    attributes = event.get("attributes")
    require(isinstance(attributes, dict), "TELEMETRY_ATTRIBUTES", "telemetry attributes are invalid")
    require(set(attributes) <= {"failureClass", "items", "bytes", "retryCount", "costMinor"}, "TELEMETRY_ATTRIBUTES", "telemetry attributes contain an unknown field")
    if "failureClass" in attributes:
        require(re.fullmatch(r"[A-Z0-9_]{1,64}", str(attributes["failureClass"])) is not None, "TELEMETRY_ATTRIBUTES", "telemetry failure class is invalid")
    for numeric_field in ("items", "bytes", "retryCount", "costMinor"):
        if numeric_field in attributes:
            require(isinstance(attributes[numeric_field], int) and attributes[numeric_field] >= 0, "TELEMETRY_ATTRIBUTES", f"telemetry {numeric_field} is invalid")
    # The policy necessarily names the prohibited classes (for example,
    # ``piiAllowed``), so lexical redaction checks apply to the event payload,
    # not to the policy declaration itself.
    encoded = json.dumps(event, ensure_ascii=False, sort_keys=True).lower()
    for term in FORBIDDEN_TELEMETRY_TERMS:
        require(term not in encoded, "TELEMETRY_FORBIDDEN_CONTENT", f"telemetry payload contains forbidden lexical marker {term}")


def validate_telemetry_v2(value: Mapping[str, Any]) -> None:
    require(value.get("schemaVersion") == "hartevo-operational-telemetry/v2", "TELEMETRY_V2_SCHEMA", "telemetry v2 schema mismatch")
    policy = value.get("policy")
    require(isinstance(policy, dict) and policy.get("contentFree") is True, "TELEMETRY_V2_POLICY", "telemetry v2 must declare contentFree=true")
    event = value.get("event")
    require(isinstance(event, dict), "TELEMETRY_V2_EVENT", "telemetry v2 event is missing")
    shadow = copy.deepcopy(value)
    shadow["schemaVersion"] = "hartevo-operational-telemetry/v1"
    shadow["policy"].pop("contentFree", None)
    shadow["event"]["schemaVersion"] = "hartevo-operational-telemetry/v1"
    validate_telemetry(shadow)


def restore_drill(
    repo: Path,
    output: Path,
    source: Mapping[str, Any],
    manifest_sha: str,
    ci_status: str,
    update_rollback_verified: bool,
) -> dict[str, Any]:
    statuses: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="hartevo-restore-drill-") as temporary_name:
        temporary = Path(temporary_name)
        source_db = temporary / "source.db"
        backup_db = temporary / "backup.db"
        restored_db = temporary / "restored.db"
        ciphertext = hashlib.sha256(f"encrypted:{source['commit']}".encode("utf-8")).hexdigest()
        connection = sqlite3.connect(source_db)
        connection.execute("CREATE TABLE restore_projection (record_id TEXT PRIMARY KEY, ciphertext_sha256 TEXT NOT NULL, byte_count INTEGER NOT NULL)")
        connection.execute("INSERT INTO restore_projection VALUES (?, ?, ?)", ("record-1", ciphertext, 32))
        connection.commit()
        connection.close()
        source_connection = sqlite3.connect(source_db)
        backup_connection = sqlite3.connect(backup_db)
        source_connection.backup(backup_connection)
        backup_connection.close()
        source_connection.close()
        backup_connection = sqlite3.connect(backup_db)
        restored_connection = sqlite3.connect(restored_db)
        backup_connection.backup(restored_connection)
        backup_connection.close()
        row = restored_connection.execute("SELECT record_id, ciphertext_sha256, byte_count FROM restore_projection").fetchone()
        restored_connection.close()
    require(row == ("record-1", ciphertext, 32), "RESTORE_CONTENT_DIGEST", "simulated encrypted projection did not round-trip exactly")
    statuses.append({
        "id": "local_sqlcipher_backup_restore",
        "kind": "local",
        "status": "PASS",
        "evidenceClass": "DETERMINISTIC_SIMULATOR",
        "rpoMinutes": 0,
        "rtoMinutes": 60,
        "checks": ["backup preserves content-free encrypted projection", "restore preserves schema and ciphertext digest", "no plaintext record body is stored"],
        "failureClasses": ["BACKUP_UNAVAILABLE", "KEY_VERSION_MISMATCH", "CIPHERTEXT_DIGEST_MISMATCH"],
    })
    blocked = "CI_NOT_EXECUTED" if ci_status == "CI_NOT_EXECUTED" else "BLOCKED_ENV"
    signed_update_status = "PASS" if update_rollback_verified else blocked
    signed_update_evidence = "DETERMINISTIC_SIMULATOR" if update_rollback_verified else blocked
    statuses.extend([
        {"id": "cell_postgres_failover", "kind": "cell", "status": blocked, "evidenceClass": blocked, "rpoMinutes": 5, "rtoMinutes": 60, "checks": ["requires non-superuser PostgreSQL failover environment"], "failureClasses": ["POSTGRES_UNAVAILABLE", "RLS_SCOPE_MISMATCH"]},
        {"id": "object_store_unavailable", "kind": "object_store", "status": blocked, "evidenceClass": blocked, "rpoMinutes": 5, "rtoMinutes": 60, "checks": ["requires isolated object-store outage and replay environment"], "failureClasses": ["OBJECT_STORE_UNAVAILABLE", "OUTBOX_REPLAY_BLOCKED"]},
        {"id": "desktop_migration_rollback", "kind": "migration", "status": blocked, "evidenceClass": blocked, "rpoMinutes": 0, "rtoMinutes": 60, "checks": ["requires native SQLCipher database and migration fault injection"], "failureClasses": ["MIGRATION_FAILED", "BACKUP_RESTORE_FAILED"]},
        {"id": "signed_update_rollback", "kind": "update", "status": signed_update_status, "evidenceClass": signed_update_evidence, "rpoMinutes": 0, "rtoMinutes": 60, "checks": ["signed metadata rejects unauthorised rollback", "signed rollback authorization is a separate path"], "failureClasses": ["UPDATE_ROLLBACK_UNAUTHORIZED", "UPDATE_METADATA_EXPIRED"]},
    ])
    scenario_statuses = {scenario["status"] for scenario in statuses}
    overall_evidence_class = "DETERMINISTIC_SIMULATOR"
    if "CI_NOT_EXECUTED" in scenario_statuses:
        overall_evidence_class = "CI_NOT_EXECUTED"
    elif "BLOCKED_ENV" in scenario_statuses:
        overall_evidence_class = "BLOCKED_ENV"
    result = {
        "schemaVersion": "hartevo-restore-drill/v1",
        "drillId": f"restore-{source['commit']}",
        "releaseCommit": source["commit"],
        "manifestSha256": manifest_sha,
        "evidenceClass": overall_evidence_class,
        "releaseDecision": RELEASE_DECISION,
        "scenarios": statuses,
        "contentFree": True,
        "nativeEvidenceRequired": True,
    }
    write_json(output, result)
    return result


def validate_manifest(repo: Path, value: Mapping[str, Any], source: Mapping[str, Any]) -> None:
    require(value.get("schemaVersion") == "hartevo-build-manifest/v1", "MANIFEST_SCHEMA", "manifest schema mismatch")
    require(value.get("manifestId") == f"commit-{source['commit']}", "MANIFEST_COMMIT", "manifest is not bound to current commit")
    require(value.get("releaseDecision") == RELEASE_DECISION and value.get("releaseEligible") is False, "MANIFEST_RELEASE_AUTHORITY", "manifest may not assert release eligibility")
    require(value.get("source") == source, "MANIFEST_SOURCE_BINDING", "manifest source binding drifted")
    require(value.get("nativeEvidence", {}).get("status") == "NOT_PROVEN", "MANIFEST_NATIVE_EVIDENCE", "manifest native evidence must remain NOT_PROVEN")
    require(value.get("sbom", {}).get("sha256") and HEX64.fullmatch(value["sbom"]["sha256"]) is not None, "MANIFEST_SBOM_BINDING", "manifest SBOM digest is invalid")
    artifacts = value.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "MANIFEST_ARTIFACTS", "manifest has no artifact records")
    for artifact in artifacts:
        require(isinstance(artifact, dict), "MANIFEST_ARTIFACT", "manifest artifact record is malformed")
        require(artifact.get("sourceCommit") == source["commit"], "MANIFEST_ARTIFACT_COMMIT", "manifest artifact is not bound to current commit")
        artifact_path = repo / str(artifact.get("path", ""))
        require(repo_relative(repo, artifact_path) == artifact.get("path"), "MANIFEST_ARTIFACT_PATH", "manifest artifact path is not repository-relative")
        require(artifact_path.is_file() and not artifact_path.is_symlink(), "MANIFEST_ARTIFACT_MISSING", "manifest artifact path is not a regular file")
        require(artifact.get("byteCount") == artifact_path.stat().st_size, "MANIFEST_ARTIFACT_LENGTH", "manifest artifact length drifted")
        require(artifact.get("sha256") == sha256_file(artifact_path), "MANIFEST_ARTIFACT_DIGEST", "manifest artifact digest drifted")


def validate_sbom(value: Mapping[str, Any], source: Mapping[str, Any]) -> None:
    require(value.get("schemaVersion") == "hartevo-sbom/v1", "SBOM_SCHEMA", "SBOM schema mismatch")
    require(value.get("bomFormat") == "CycloneDX" and value.get("specVersion") == "1.5", "SBOM_FORMAT", "SBOM must be CycloneDX 1.5")
    require(value.get("provenance", {}).get("commit") == source["commit"], "SBOM_COMMIT", "SBOM commit binding drifted")
    require(isinstance(value.get("components"), list) and value["components"], "SBOM_COMPONENTS", "SBOM has no components")
    component_refs = [component.get("bom-ref") for component in value["components"] if isinstance(component, dict)]
    require(all(isinstance(reference, str) and reference for reference in component_refs), "SBOM_COMPONENT_REFS", "SBOM component references are invalid")
    require(len(component_refs) == len(set(component_refs)), "SBOM_DUPLICATE_COMPONENT", "SBOM contains duplicate component references")
    dependency_refs = {dependency.get("ref") for dependency in value.get("dependencies", []) if isinstance(dependency, dict)}
    require(dependency_refs == set(component_refs), "SBOM_DEPENDENCY_ROOTS", "SBOM dependency roots do not match components")
    for dependency in value.get("dependencies", []):
        require(isinstance(dependency, dict), "SBOM_DEPENDENCY", "SBOM dependency entry is malformed")
        require(set(dependency.get("dependsOn", [])) <= set(component_refs), "SBOM_DEPENDENCY_REF", "SBOM dependency points to an unknown component")
    require(value.get("licenseAudit", {}).get("status") in {"PASS", "FAIL", "BLOCKED_ENV", "CI_NOT_EXECUTED"}, "SBOM_LICENSE_STATUS", "SBOM license audit status invalid")
    require(value.get("vulnerabilityAudit", {}).get("status") in {"PASS", "FAIL", "BLOCKED_ENV", "CI_NOT_EXECUTED"}, "SBOM_VULNERABILITY_STATUS", "SBOM vulnerability audit status invalid")


def validate_restore(value: Mapping[str, Any], source: Mapping[str, Any], manifest_sha: str) -> None:
    require(value.get("schemaVersion") == "hartevo-restore-drill/v1", "RESTORE_SCHEMA", "restore drill schema mismatch")
    require(value.get("releaseCommit") == source["commit"], "RESTORE_COMMIT", "restore drill commit binding drifted")
    require(value.get("manifestSha256") == manifest_sha, "RESTORE_MANIFEST", "restore drill manifest binding drifted")
    require(value.get("contentFree") is True and value.get("nativeEvidenceRequired") is True, "RESTORE_POLICY", "restore drill policy is unsafe")
    require(value.get("evidenceClass") in {"DETERMINISTIC_SIMULATOR", "BLOCKED_ENV", "CI_NOT_EXECUTED"}, "RESTORE_EVIDENCE_CLASS", "restore drill cannot claim native evidence")
    scenarios = value.get("scenarios", [])
    ids = [scenario.get("id") for scenario in scenarios]
    require(set(ids) == {"local_sqlcipher_backup_restore", "cell_postgres_failover", "object_store_unavailable", "desktop_migration_rollback", "signed_update_rollback"}, "RESTORE_SCENARIOS", "restore drill scenario set is incomplete")
    statuses = {scenario.get("status") for scenario in scenarios}
    if "CI_NOT_EXECUTED" in statuses:
        require(value.get("evidenceClass") == "CI_NOT_EXECUTED", "RESTORE_EVIDENCE_STATUS", "restore drill evidence class does not reflect CI_NOT_EXECUTED")
    elif "BLOCKED_ENV" in statuses:
        require(value.get("evidenceClass") == "BLOCKED_ENV", "RESTORE_EVIDENCE_STATUS", "restore drill evidence class does not reflect BLOCKED_ENV")


def gate(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    output_dir = (repo / args.output).resolve() if not Path(args.output).is_absolute() else Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    source = source_context(repo)
    if args.strict_clean:
        require(not source["dirty"], "SOURCE_DIRTY", "strict distribution gate requires a clean worktree")
    ci_status = args.ci_status
    sbom_path = output_dir / "sbom.json"
    manifest_path = output_dir / "build-manifest.json"
    spdx_path = output_dir / "spdx-sbom.json"
    local_manifest_path = output_dir / "local-build-manifest.json"
    checksums_path = output_dir / "checksums.json"
    provenance_path = output_dir / "provenance.json"
    update_dir = output_dir / "update"
    update_path = update_dir / "update-metadata.json"
    telemetry_path = output_dir / "telemetry.json"
    telemetry_v2_path = output_dir / "telemetry-v2.json"
    restore_path = output_dir / "restore-drill.json"
    release_path = output_dir / "release-baseline.json"
    verification_path = output_dir / "verification.json"
    with tempfile.TemporaryDirectory(prefix="hartevo-distribution-gate-") as temporary_name:
        temporary = Path(temporary_name)
        sbom = build_sbom(repo, sbom_path, source, ci_status)
        artifact_path = Path(args.artifact).resolve() if args.artifact else None
        manifest = build_manifest(repo, manifest_path, sbom_path, sbom, source, ci_status, args.profile, artifact_path)
        spdx = build_spdx_sbom(repo, spdx_path, source)
        hook_statuses = (manifest["platform"]["macosSigning"], manifest["platform"]["macosNotarization"], manifest["platform"]["windowsSigning"])
        signing_hooks = signing_hook_records(repo, hook_statuses)
        local_manifest = build_local_manifest(
            repo,
            local_manifest_path,
            sbom_path,
            sbom,
            spdx_path,
            spdx,
            source,
            args.profile,
            artifact_path,
            signing_hooks,
            checksums_path,
            provenance_path,
            telemetry_v2_path,
        )
        signer_bundle = prepare_signers(repo, temporary / "signers")
        update_metadata(
            repo,
            update_dir,
            manifest_path,
            sbom_path,
            source,
            args.channel,
            platform.machine(),
            args.sequence,
            artifact_path,
            signer_bundle,
        )
        verify_update(repo, update_dir, args.channel, platform.machine(), 0, expected_commit=source["commit"])
        rollback_token = temporary / "rollback-authorization.json"
        make_rollback_token(
            repo,
            rollback_token,
            args.sequence + 1,
            args.sequence,
            sha256_file(update_dir / "targets.json"),
            signer_bundle,
        )
        verify_update(
            repo,
            update_dir,
            args.channel,
            platform.machine(),
            args.sequence + 1,
            rollback_token,
            source["commit"],
        )
        telemetry = telemetry_event(source, sha256_file(manifest_path), args.telemetry_opt_in)
        validate_telemetry(telemetry)
        write_json(telemetry_path, telemetry)
        telemetry_v2 = telemetry_event_v2(source, sha256_file(local_manifest_path), args.telemetry_opt_in)
        validate_telemetry_v2(telemetry_v2)
        write_json(telemetry_v2_path, telemetry_v2)
        restore = restore_drill(repo, restore_path, source, sha256_file(manifest_path), ci_status, True)
        validate_manifest(repo, manifest, source)
        validate_sbom(sbom, source)
        validate_restore(restore, source, sha256_file(manifest_path))
        checksum_records = [
            artifact_record(repo, local_manifest_path, "local-build-manifest", "MANIFEST", "LOCAL_CONTRACT", source["commit"]),
            artifact_record(repo, sbom_path, "cyclonedx-sbom", "SBOM", "LOCAL_CONTRACT", source["commit"]),
            artifact_record(repo, spdx_path, "spdx-sbom", "SBOM", "LOCAL_CONTRACT", source["commit"]),
            artifact_record(repo, telemetry_v2_path, "operational-telemetry", "TELEMETRY", "LOCAL_CONTRACT", source["commit"]),
        ]
        if artifact_path is not None:
            checksum_records.append(artifact_record(repo, artifact_path, "desktop-application", "APPLICATION", "BLOCKED_ENV", source["commit"]))
        build_checksums(repo, checksums_path, source, local_manifest["toolchain"], checksum_records)
        build_provenance(repo, provenance_path, source, local_manifest["toolchain"], checksums_path, checksum_records, signing_hooks)
        run(
            ("cargo", "run", "-p", "hartevo-eval", "--locked", "--", "evidence", "baseline", "--commit", source["commit"], "--output", str(release_path)),
            repo,
            env={"CARGO_TERM_COLOR": "never"},
            timeout=240,
        )
    release_evidence = load_json(release_path, "release baseline")
    require(release_evidence.get("releaseCommit") == source["commit"], "RELEASE_COMMIT", "release baseline is not bound to current commit")
    require(release_evidence.get("passed") is False, "RELEASE_FALSE_GUARD", "DIST-01 must keep existing Release Evidence passed=false")
    sbom_check = "PASS"
    if sbom["licenseAudit"]["status"] == "FAIL" or sbom["vulnerabilityAudit"]["status"] == "FAIL":
        sbom_check = "FAIL"
    elif sbom["licenseAudit"]["status"] != "PASS" or sbom["vulnerabilityAudit"]["status"] != "PASS":
        sbom_check = "CI_NOT_EXECUTED" if ci_status == "CI_NOT_EXECUTED" else "BLOCKED_ENV"
    restore_statuses = {scenario["status"] for scenario in restore["scenarios"]}
    if "FAIL" in restore_statuses:
        restore_check = "FAIL"
    elif "CI_NOT_EXECUTED" in restore_statuses:
        restore_check = "CI_NOT_EXECUTED"
    elif "BLOCKED_ENV" in restore_statuses:
        restore_check = "BLOCKED_ENV"
    else:
        restore_check = "PASS"
    blocked_env = []
    if sbom["vulnerabilityAudit"]["status"] != "PASS":
        blocked_env.append(f"sbom_vulnerability_audit:{sbom['vulnerabilityAudit']['status']}")
    for label, status in zip(("macos_signing", "macos_notarization", "windows_signing"), (manifest["platform"]["macosSigning"], manifest["platform"]["macosNotarization"], manifest["platform"]["windowsSigning"])):
        if status != "PASS":
            blocked_env.append(f"{label}:{status}")
    for scenario in restore["scenarios"]:
        if scenario["status"] in {"BLOCKED_ENV", "CI_NOT_EXECUTED"}:
            blocked_env.append(f"restore:{scenario['id']}:{scenario['status']}")
    if ci_status == "CI_NOT_EXECUTED":
        blocked_env.append("github_actions:CI_NOT_EXECUTED")
    blocked_env.append("release_evidence:NOT_PROVEN")
    result = {
        "schemaVersion": SCHEMA,
        "issue": "DIST-01",
        "releaseCommit": source["commit"],
        "sourceDirty": source["dirty"],
        "ciStatus": ci_status,
        "releaseDecision": RELEASE_DECISION,
        "releaseReady": False,
        "artifactReferences": {
            "manifest": repo_relative(repo, manifest_path),
            "sbom": repo_relative(repo, sbom_path),
            "updateMetadata": repo_relative(repo, update_path),
            "telemetry": repo_relative(repo, telemetry_path),
            "restoreDrill": repo_relative(repo, restore_path),
            "releaseEvidence": repo_relative(repo, release_path),
        },
        "checks": {
            "manifest": "PASS",
            "sbom": sbom_check,
            "updateMetadata": "PASS",
            "telemetry": "PASS",
            "restoreDrill": restore_check,
            "releaseEvidence": "BLOCKED_ENV",
        },
        "nativeEvidence": {"status": "NOT_PROVEN", "requiredForRelease": True, "productCompletionCounted": False},
        "blockedEnv": sorted(set(blocked_env)),
        "failures": [],
    }
    gate_path = output_dir / "gate.json"
    write_json(gate_path, result)
    run(
        ("cargo", "run", "-p", "hartevo-eval", "--locked", "--", "distribution", "validate", "--gate", str(gate_path), "--commit", source["commit"]),
        repo,
        env={"CARGO_TERM_COLOR": "never"},
        timeout=240,
    )
    run(
        (
            "cargo", "run", "-p", "hartevo-eval", "--locked", "--", "distribution", "verify",
            "--root", str(repo),
            "--manifest", str(local_manifest_path),
            "--cyclonedx", str(spdx_path.parent / "sbom.json"),
            "--spdx", str(spdx_path),
            "--checksums", str(checksums_path),
            "--provenance", str(provenance_path),
            "--telemetry", str(telemetry_v2_path),
            "--commit", source["commit"],
            "--output", str(verification_path),
        ),
        repo,
        env={"CARGO_TERM_COLOR": "never"},
        timeout=240,
    )
    print(json.dumps({"status": "PASS", "releaseReady": False, "releaseDecision": RELEASE_DECISION, "gate": repo_relative(repo, gate_path), "verification": repo_relative(repo, verification_path)}, sort_keys=True))
    return result


def self_test(repo: Path) -> None:
    source = source_context(repo)
    with tempfile.TemporaryDirectory(prefix="hartevo-distribution-self-test-") as temporary_name:
        temporary = Path(temporary_name)
        manifest = temporary / "build-manifest.json"
        sbom = temporary / "sbom.json"
        manifest.write_bytes(b"manifest fixture bound to test only\n")
        sbom.write_bytes(b"sbom fixture bound to test only\n")
        update_dir = temporary / "update"
        signer_bundle = prepare_signers(repo, temporary / "signers")
        update_metadata(repo, update_dir, manifest, sbom, source, "alpha", platform.machine(), 2, None, signer_bundle)
        verify_update(repo, update_dir, "alpha", platform.machine(), 1, expected_commit=source["commit"])
        original_targets = (update_dir / "targets.json").read_bytes()
        tampered_targets = load_json(update_dir / "targets.json", "self-test targets")
        tampered_targets["signed"]["version"] = 3
        write_json(update_dir / "targets.json", tampered_targets)
        try:
            verify_update(repo, update_dir, "alpha", platform.machine(), 1, expected_commit=source["commit"])
        except GateError as error:
            require(error.code == "COMMAND_FAILED", "SELF_TEST_SIGNATURE", "tampered update metadata was not rejected")
        else:
            fail("SELF_TEST_SIGNATURE", "tampered update metadata was accepted")
        (update_dir / "targets.json").write_bytes(original_targets)
        try:
            verify_update(repo, update_dir, "alpha", platform.machine(), 3, expected_commit=source["commit"])
        except GateError as error:
            require(error.code == "UPDATE_ROLLBACK_UNAUTHORIZED", "SELF_TEST_ROLLBACK", "unauthorized rollback was not rejected")
        else:
            fail("SELF_TEST_ROLLBACK", "unauthorized rollback was accepted")
        token = temporary / "rollback.json"
        make_rollback_token(repo, token, 3, 2, sha256_file(update_dir / "targets.json"), signer_bundle)
        verify_update(repo, update_dir, "alpha", platform.machine(), 3, token, source["commit"])
        telemetry = telemetry_event(source, sha256_file(manifest), False)
        validate_telemetry(telemetry)
        telemetry_v2 = telemetry_event_v2(source, sha256_file(manifest), False)
        validate_telemetry_v2(telemetry_v2)
        poisoned = copy.deepcopy(telemetry)
        poisoned["event"]["attributes"] = {"prompt": "do not serialize"}
        try:
            validate_telemetry(poisoned)
        except GateError as error:
            require(error.code in {"TELEMETRY_FORBIDDEN_FIELD", "TELEMETRY_FORBIDDEN_CONTENT", "TELEMETRY_ATTRIBUTES"}, "SELF_TEST_TELEMETRY", "telemetry redaction test failed")
        else:
            fail("SELF_TEST_TELEMETRY", "telemetry redaction accepted a forbidden field")
        poisoned_v2 = copy.deepcopy(telemetry_v2)
        poisoned_v2["event"]["attributes"] = {"prompt": "do not serialize"}
        try:
            validate_telemetry_v2(poisoned_v2)
        except GateError as error:
            require(error.code in {"TELEMETRY_FORBIDDEN_FIELD", "TELEMETRY_FORBIDDEN_CONTENT", "TELEMETRY_ATTRIBUTES"}, "SELF_TEST_TELEMETRY_V2", "telemetry v2 redaction test failed")
        else:
            fail("SELF_TEST_TELEMETRY_V2", "telemetry v2 redaction accepted a forbidden field")
        try:
            hook_record(repo, "self-test-signing-hook", "PASS", "HARTEVO_SELF_TEST_NO_SIGNING_EVIDENCE")
        except GateError as error:
            require(error.code == "SIGNING_EVIDENCE_MISSING", "SELF_TEST_SIGNING_HOOK", "signing hook PASS was not evidence-bound")
        else:
            fail("SELF_TEST_SIGNING_HOOK", "signing hook PASS was accepted without evidence")
        restore_path = temporary / "restore.json"
        restore = restore_drill(repo, restore_path, source, sha256_file(manifest), "LOCAL_SCOPED", True)
        validate_restore(restore, source, sha256_file(manifest))
        tampered = copy.deepcopy(restore)
        tampered["manifestSha256"] = "0" * 64
        try:
            validate_restore(tampered, source, sha256_file(manifest))
        except GateError as error:
            require(error.code == "RESTORE_MANIFEST", "SELF_TEST_RESTORE", "restore binding tamper was not rejected")
        else:
            fail("SELF_TEST_RESTORE", "restore binding tamper was accepted")
    print(json.dumps({"schema": "hartevo-distribution-self-test/v1", "status": "PASS", "releaseDecision": RELEASE_DECISION, "releasePassed": False}, sort_keys=True))


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIST-01 distribution and recovery contract gate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    gate_parser = subparsers.add_parser("gate")
    gate_parser.add_argument("--output", default="target/distribution")
    gate_parser.add_argument("--profile", choices=("debug", "release"), default="release")
    gate_parser.add_argument("--channel", choices=("alpha", "beta", "stable"), default="alpha")
    gate_parser.add_argument("--sequence", type=int, default=int(os.environ.get("HARTEVO_UPDATE_SEQUENCE", "1")))
    gate_parser.add_argument("--artifact")
    gate_parser.add_argument("--ci-status", choices=("CI_EXECUTED", "CI_NOT_EXECUTED", "LOCAL_SCOPED"), default=os.environ.get("HARTEVO_CI_STATUS", "LOCAL_SCOPED"))
    gate_parser.add_argument("--telemetry-opt-in", action="store_true")
    gate_parser.add_argument("--strict-clean", action="store_true")
    self_parser = subparsers.add_parser("self-test")
    self_parser.set_defaults()
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    repo = Path(git(Path.cwd(), "rev-parse", "--show-toplevel")).resolve()
    try:
        ensure_contracts(repo)
        if args.command == "gate":
            gate(args, repo)
        elif args.command == "self-test":
            self_test(repo)
        else:
            fail("COMMAND_UNKNOWN", args.command)
        return 0
    except BlockedEnvironment as error:
        print(json.dumps({"schema": "hartevo-distribution-gate-verification/v1", "status": error.status, "code": error.code, "message": error.message, "releaseDecision": RELEASE_DECISION, "releasePassed": False}, sort_keys=True))
        return 2
    except GateError as error:
        print(json.dumps({"schema": "hartevo-distribution-gate-verification/v1", "status": error.status, "code": error.code, "message": error.message, "releaseDecision": RELEASE_DECISION, "releasePassed": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
