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


@dataclass(frozen=True)
class Job:
    name: str
    result: str
    kind: str
    allowed_skip: bool = False
    no_steps: bool = False


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
    if job.allowed_skip and job.result == "skipped":
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
        planned_skip = job.allowed_skip and job.result == "skipped"
        classification = classify(job)
        reason = "scope-allowed skip" if planned_skip else None
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


def run_aggregate(args: argparse.Namespace) -> int:
    results = parse_mapping(args.job, "--job")
    kinds = parse_mapping(args.kind, "--kind")
    names = parse_mapping(args.job_name, "--job-name")
    allowed = set(args.allow_skipped)
    if set(results) != set(kinds):
        raise ValueError("every job must have exactly one --kind")
    if not set(names).issubset(results):
        raise ValueError("every --job-name alias must have a matching --job")
    no_steps: set[str] = set()
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
    jobs = []
    for name in sorted(results):
        result = results[name]
        if result not in GITHUB_RESULTS:
            raise ValueError(f"unsupported GitHub job result for {name}: {result}")
        if kinds[name] not in {"code", "infra"}:
            raise ValueError(f"unsupported job kind for {name}: {kinds[name]}")
        jobs.append(Job(name, result, kinds[name], name in allowed, name in no_steps))
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
