#!/usr/bin/env python3
"""Classify GitHub job outcomes without conflating code and infrastructure."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.sax.saxutils import escape


TAXONOMY = ("PASS", "CODE_FAILURE", "INFRA_FAILURE", "CI_NOT_EXECUTED")
GITHUB_RESULTS = {"success", "failure", "cancelled", "skipped", "neutral", "timed_out"}
PLANNED_SCOPE_MARKER = "Planned scope skip marker"


@dataclass(frozen=True)
class Job:
    name: str
    result: str
    kind: str
    allowed_skip: bool = False
    no_steps: bool = False
    planned_scope: bool = False


def parse_mapping(values: list[str], label: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"{label} must use NAME=VALUE: {item!r}")
        name, value = item.split("=", 1)
        if not name or not value or name in parsed:
            raise ValueError(f"invalid or duplicate {label}: {item!r}")
        parsed[name] = value
    return parsed


def classify(job: Job) -> str:
    if (job.allowed_skip and job.result == "skipped") or (job.planned_scope and job.result == "success"):
        return "PASS"
    if job.no_steps:
        return "CI_NOT_EXECUTED"
    if job.result == "success":
        return "PASS"
    if job.result in {"skipped", "cancelled", "neutral"}:
        return "CI_NOT_EXECUTED"
    if job.result in {"failure", "timed_out"}:
        return "INFRA_FAILURE" if job.kind == "infra" else "CODE_FAILURE"
    return "INFRA_FAILURE"


def aggregate(jobs: list[Job]) -> tuple[str, list[dict[str, object]]]:
    entries: list[dict[str, object]] = []
    for job in jobs:
        planned_skip = (job.allowed_skip and job.result == "skipped") or (job.planned_scope and job.result == "success")
        classification = classify(job)
        reason = "validated planned scope markers" if job.planned_scope and planned_skip else ("scope-allowed skip" if planned_skip else None)
        if classification == "CI_NOT_EXECUTED":
            if job.no_steps:
                reason = "job did not execute: GitHub created no steps (runner/billing or hosted infrastructure gate)"
            else:
                reason = "job did not execute"
        entries.append(
            {
                "name": job.name,
                "githubResult": job.result,
                "kind": job.kind,
                "classification": classification,
                "allowedSkip": job.allowed_skip,
                "plannedSkip": planned_skip,
                "plannedScope": job.planned_scope,
                "noSteps": job.no_steps,
                "reason": reason,
            }
        )

    classifications = {entry["classification"] for entry in entries}
    if "INFRA_FAILURE" in classifications:
        overall = "INFRA_FAILURE"
    elif "CODE_FAILURE" in classifications:
        overall = "CODE_FAILURE"
    elif any(
        entry["classification"] == "CI_NOT_EXECUTED" and not entry["plannedSkip"]
        for entry in entries
    ):
        overall = "CI_NOT_EXECUTED"
    else:
        overall = "PASS"
    return overall, entries


def write_junit(path: Path, workflow: str, overall: str, entries: list[dict[str, object]]) -> None:
    failures = sum(entry["classification"] in {"CODE_FAILURE", "INFRA_FAILURE", "CI_NOT_EXECUTED"} and not entry["plannedSkip"] for entry in entries)
    lines = [
        f'<testsuite name="{escape(workflow)}" tests="{len(entries)}" failures="{failures}" skipped="0">'
    ]
    for entry in entries:
        name = escape(str(entry["name"]))
        classification = str(entry["classification"])
        lines.append(f'  <testcase classname="ci" name="{name}">')
        if classification != "PASS" and not entry["plannedSkip"]:
            detail = escape(str(entry.get("reason") or classification))
            lines.append(f"    <failure message=\"{classification}\">{detail}</failure>")
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_planned_scope_markers(
    records: list[object], expected_names: list[str], *, scope: str = "rust"
) -> dict[str, object]:
    if not expected_names or len(expected_names) != len(set(expected_names)):
        raise ValueError(f"planned {scope} scope requires unique child check names")
    by_name = {
        record.get("name"): record
        for record in records
        if isinstance(record, dict) and isinstance(record.get("name"), str)
    }
    evidence: list[dict[str, object]] = []
    for expected_name in expected_names:
        record = by_name.get(expected_name)
        if not isinstance(record, dict):
            raise ValueError(f"planned {scope} scope child check is missing: {expected_name}")
        if record.get("status") != "completed" or record.get("conclusion") != "success":
            raise ValueError(f"planned {scope} scope child check did not succeed: {expected_name}")
        steps = record.get("steps")
        if not isinstance(steps, list):
            raise ValueError(f"planned {scope} scope child check has malformed steps: {expected_name}")
        step_entries = [
            step
            for step in steps
            if isinstance(step, dict)
            and isinstance(step.get("name"), str)
            and isinstance(step.get("conclusion"), str)
        ]
        if len(step_entries) != len(steps):
            raise ValueError(f"planned {scope} scope child check has malformed step evidence: {expected_name}")
        step_names = [step["name"] for step in step_entries]
        marker_steps = [step for step in step_entries if step["name"] == PLANNED_SCOPE_MARKER]
        if len(marker_steps) != 1 or marker_steps[0]["conclusion"] != "success":
            raise ValueError(f"planned {scope} scope child check must run one marker: {expected_name}")
        executed = [
            step["name"]
            for step in step_entries
            if step["conclusion"] != "skipped"
        ]
        if executed != ["Set up job", PLANNED_SCOPE_MARKER, "Complete job"]:
            raise ValueError(f"planned {scope} scope child check executed non-marker steps: {expected_name}: {executed}")
        evidence.append(
            {
                "name": expected_name,
                "conclusion": record["conclusion"],
                "stepNames": step_names,
                "executedStepNames": executed,
                "marker": PLANNED_SCOPE_MARKER,
            }
        )
    return {
        "status": "PASS",
        "marker": PLANNED_SCOPE_MARKER,
        "jobCount": len(evidence),
        "jobs": evidence,
    }


def run_aggregate(args: argparse.Namespace) -> int:
    results = parse_mapping(args.job, "--job")
    kinds = parse_mapping(args.kind, "--kind")
    names = parse_mapping(args.job_name, "--job-name")
    allowed = set(args.allow_skipped)
    planned_scopes = set(args.planned_scope)
    supported_planned_scopes = {"rust", "macos", "common-rust", "desktop", "dependency"}
    if planned_scopes - supported_planned_scopes:
        raise ValueError(f"unsupported planned scope: {sorted(planned_scopes - supported_planned_scopes)}")
    if set(results) != set(kinds):
        raise ValueError("every job must have exactly one --kind")
    if not set(names).issubset(results):
        raise ValueError("every --job-name alias must have a matching --job")
    no_steps: set[str] = set()
    records: list[object] = []
    if args.github_jobs_json:
        payload = json.loads(args.github_jobs_json.read_text(encoding="utf-8"))
        records = payload.get("jobs") if isinstance(payload, dict) else payload
        if not isinstance(records, list):
            raise ValueError("GitHub jobs evidence must contain a jobs array")
        no_step_names = {
            record.get("name")
            for record in records
            if isinstance(record, dict) and isinstance(record.get("name"), str) and record.get("steps") == []
        }
        no_steps = {
            alias for alias, github_name in names.items() if github_name in no_step_names
        }
    planned_evidence: dict[str, object] = {}
    if "rust" in planned_scopes:
        required_rust_names = {
            "PR / Fast Rust matrix / PR / Fast Rust / fmt",
            "PR / Fast Rust matrix / PR / Fast Rust / clippy (ubuntu-24.04)",
            "PR / Fast Rust matrix / PR / Fast Rust / clippy (macos-15)",
            "PR / Fast Rust matrix / PR / Fast Rust / test (ubuntu-24.04)",
            "PR / Fast Rust matrix / PR / Fast Rust / test (macos-15)",
        }
        split_rust_names = {
            "PR / Fast Rust matrix / PR / Fast Rust / test shard 0 of 2 (ubuntu-24.04)",
            "PR / Fast Rust matrix / PR / Fast Rust / test shard 1 of 2 (ubuntu-24.04)",
        }
        if not required_rust_names.issubset(args.planned_job_name) or not split_rust_names.issubset(args.planned_job_name):
            raise ValueError("planned rust scope requires all split-lane child check names")
        rust_names = [name for name in args.planned_job_name if name in required_rust_names | split_rust_names]
        planned_evidence["rust"] = validate_planned_scope_markers(
            records, rust_names, scope="rust"
        )
    if "macos" in planned_scopes or "desktop" in planned_scopes:
        desktop_names = [name for name in args.planned_job_name if "(macos-15)" in name]
        if len(desktop_names) != 2:
            raise ValueError("planned desktop scope requires the two macOS child check names")
        planned_evidence["desktop" if "desktop" in planned_scopes else "macos"] = validate_planned_scope_markers(
            records, desktop_names, scope="desktop"
        )
    if "common-rust" in planned_scopes:
        common_names = [
            name for name in args.planned_job_name
            if "clippy (ubuntu-24.04)" in name
            or "test shard " in name
            or "test (ubuntu-24.04)" in name
        ]
        if len(common_names) != 4 or any("macos-15" in name for name in common_names):
            raise ValueError("planned common-rust scope requires Ubuntu clippy, two shards, and Ubuntu aggregate")
        planned_evidence["common-rust"] = validate_planned_scope_markers(
            records, common_names, scope="common-rust"
        )
    if "dependency" in planned_scopes:
        dependency_names = {
            "PR / Dependency only",
            "PR / Dependency Cordis smoke",
            "PR / Dependency desktop smoke",
        }
        if not dependency_names.issubset(args.planned_job_name):
            raise ValueError("planned dependency scope requires metadata and Cordis/desktop smoke names")
        planned_evidence["dependency"] = validate_planned_scope_markers(
            records, sorted(dependency_names), scope="dependency"
        )
    jobs = []
    planned_job_names = set(args.planned_job_name)
    for name in sorted(results):
        result = results[name]
        if result not in GITHUB_RESULTS:
            raise ValueError(f"unsupported GitHub job result for {name}: {result}")
        if kinds[name] not in {"code", "infra"}:
            raise ValueError(f"unsupported job kind for {name}: {kinds[name]}")
        jobs.append(Job(name, result, kinds[name], name in allowed, name in no_steps, name in planned_job_names))
    overall, entries = aggregate(jobs)
    payload = {
        "schema": "hartevo-ci-result/v1",
        "workflow": args.workflow,
        "runId": args.run_id,
        "commit": args.commit,
        "event": args.event,
        "overall": overall,
        "allowedOverall": overall == "PASS",
        "jobs": entries,
        "plannedScopes": planned_evidence,
        "taxonomy": list(TAXONOMY),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if args.junit:
        write_junit(args.junit, args.workflow, overall, entries)
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if overall == "PASS" else 1


def self_test() -> None:
    overall, entries = aggregate(
        [Job("pass", "success", "code"), Job("scope", "skipped", "code", True)]
    )
    assert overall == "PASS"
    assert {entry["classification"] for entry in entries} == {"PASS"}
    assert entries[1]["plannedSkip"] is True
    planned_no_steps, planned_no_steps_entries = aggregate([Job("scope", "skipped", "code", True, True)])
    assert planned_no_steps == "PASS"
    assert planned_no_steps_entries[0]["classification"] == "PASS"
    assert planned_no_steps_entries[0]["plannedSkip"] is True
    planned_rust, planned_rust_entries = aggregate([Job("rust", "success", "code", planned_scope=True)])
    assert planned_rust == "PASS"
    assert planned_rust_entries[0]["plannedSkip"] is True
    marker_names = [
        "PR / Fast Rust matrix / PR / Fast Rust / fmt",
        "PR / Fast Rust matrix / PR / Fast Rust / clippy (ubuntu-24.04)",
        "PR / Fast Rust matrix / PR / Fast Rust / clippy (macos-15)",
        "PR / Fast Rust matrix / PR / Fast Rust / test (ubuntu-24.04)",
        "PR / Fast Rust matrix / PR / Fast Rust / test (macos-15)",
    ]
    marker_records = [
        {
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {"name": "Set up job", "conclusion": "success"},
                {"name": PLANNED_SCOPE_MARKER, "conclusion": "success"},
                {"name": "Checkout reviewed source", "conclusion": "skipped"},
                {"name": "Cache Cargo and Rust toolchain", "conclusion": "skipped"},
                {"name": "Complete job", "conclusion": "success"},
            ],
        }
        for name in marker_names
    ]
    marker_evidence = validate_planned_scope_markers(marker_records, marker_names)
    assert marker_evidence["status"] == "PASS" and marker_evidence["jobCount"] == 5
    macos_names = [name for name in marker_names if "(macos-15)" in name]
    macos_records = [record for record in marker_records if record["name"] in macos_names]
    macos_evidence = validate_planned_scope_markers(macos_records, macos_names, scope="macos")
    assert macos_evidence["status"] == "PASS" and macos_evidence["jobCount"] == 2
    dependency_names = [
        "PR / Dependency only",
        "PR / Dependency Cordis smoke",
        "PR / Dependency desktop smoke",
    ]
    dependency_records = [
        {
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {"name": "Set up job", "conclusion": "success"},
                {"name": PLANNED_SCOPE_MARKER, "conclusion": "success"},
                {"name": "Complete job", "conclusion": "success"},
            ],
        }
        for name in dependency_names
    ]
    dependency_evidence = validate_planned_scope_markers(
        dependency_records, dependency_names, scope="dependency"
    )
    assert dependency_evidence["status"] == "PASS" and dependency_evidence["jobCount"] == 3
    try:
        validate_planned_scope_markers(
            marker_records[:-1]
            + [
                {
                    **marker_records[-1],
                    "steps": [
                        {"name": "Set up job", "conclusion": "success"},
                        {"name": PLANNED_SCOPE_MARKER, "conclusion": "success"},
                        {"name": "Checkout reviewed source", "conclusion": "success"},
                        {"name": "Complete job", "conclusion": "success"},
                    ],
                }
            ],
            marker_names,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("self-test accepted a planned scope child with non-marker steps")
    assert aggregate([Job("code", "failure", "code")])[0] == "CODE_FAILURE"
    assert aggregate([Job("runner", "timed_out", "infra")])[0] == "INFRA_FAILURE"
    assert aggregate([Job("never", "skipped", "code")])[0] == "CI_NOT_EXECUTED"
    no_steps_overrides_failure, no_steps_entries = aggregate([Job("billing", "failure", "code", no_steps=True)])
    assert no_steps_overrides_failure == "CI_NOT_EXECUTED"
    assert no_steps_entries[0]["noSteps"] is True
    print(json.dumps({"schema": "hartevo-ci-result-self-test/v1", "status": "PASS"}, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    aggregate_parser = sub.add_parser("aggregate")
    aggregate_parser.add_argument("--workflow", required=True)
    aggregate_parser.add_argument("--run-id", required=True)
    aggregate_parser.add_argument("--commit", required=True)
    aggregate_parser.add_argument("--event", required=True)
    aggregate_parser.add_argument("--output", type=Path, required=True)
    aggregate_parser.add_argument("--junit", type=Path)
    aggregate_parser.add_argument("--job", action="append", default=[])
    aggregate_parser.add_argument("--kind", action="append", default=[])
    aggregate_parser.add_argument("--job-name", action="append", default=[])
    aggregate_parser.add_argument("--github-jobs-json", type=Path)
    aggregate_parser.add_argument("--allow-skipped", action="append", default=[])
    aggregate_parser.add_argument("--planned-scope", action="append", default=[])
    aggregate_parser.add_argument("--planned-job-name", action="append", default=[])
    sub.add_parser("self-test")
    return root


def main(argv: Iterable[str]) -> int:
    args = parser().parse_args(list(argv))
    try:
        if args.command == "self-test":
            self_test()
            return 0
        return run_aggregate(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": "hartevo-ci-result/v1", "overall": "INFRA_FAILURE", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
