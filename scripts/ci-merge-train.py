#!/usr/bin/env python3
"""Prepare and verify Hartevo's bounded repository merge train.

GitHub's hosted merge queue is not available to public repositories owned by
personal accounts.  This train preserves the important queue semantics without
weakening the protected Integration branch:

* one temporary ``merge-train/*`` pull request contains one to four reviewed
  root pull-request heads;
* the train history and tree are reconstructed and checked in CI;
* only that composite head runs the full Ubuntu/macOS matrix; and
* the composite pull request is merged normally, never by direct push or rule
  bypass.

``prepare`` intentionally stops after making local merge commits and the
content-free manifest commit.  The Integration Manager remains responsible for
reviewing, pushing the temporary branch, and opening the pull request.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence


SCHEMA = "hartevo-repository-merge-train/v1"
REPOSITORY = "tangpingqingwa/hartevo-desktop"
BASE_BRANCH = "bootstrap/macos-r0"
BRANCH_PREFIX = "merge-train/"
MANIFEST_PATH = Path(".github/merge-train/current.json")
MAX_CANDIDATES = 4
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
POLICY_PATH = Path(".github/policies/branch-ruleset-policy.json")


class TrainError(ValueError):
    """A fail-closed merge-train contract violation."""


def command(
    argv: Sequence[str],
    *,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        list(argv),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if check and process.returncode != 0:
        detail = (process.stderr or process.stdout).strip()
        raise TrainError(f"command failed ({' '.join(argv)}): {detail}")
    return process


def git(*args: str, check: bool = True) -> str:
    return command(("git", *args), check=check).stdout.strip()


def gh_json(*args: str) -> object:
    output = command(("gh", *args)).stdout
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise TrainError(f"GitHub CLI returned invalid JSON: {error}") from error


def required_checks() -> tuple[str, ...]:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    branches = policy.get("branches")
    if not isinstance(branches, list):
        raise TrainError("branch policy has no branch list")
    bootstrap = next(
        (
            item
            for item in branches
            if isinstance(item, dict) and item.get("name") == BASE_BRANCH
        ),
        None,
    )
    checks = bootstrap.get("requiredStatusChecks") if isinstance(bootstrap, dict) else None
    if not isinstance(checks, list) or not checks or not all(isinstance(item, str) for item in checks):
        raise TrainError("bootstrap required-check contract is missing")
    return tuple(checks)


def validate_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA_PATTERN.fullmatch(value) is None:
        raise TrainError(f"{label} must be a lowercase 40-character Git SHA")
    return value


def validate_manifest_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TrainError("merge-train manifest must be an object")
    if value.get("schema") != SCHEMA:
        raise TrainError("merge-train manifest schema drift")
    if value.get("repository") != REPOSITORY:
        raise TrainError("merge-train repository drift")
    if value.get("baseBranch") != BASE_BRANCH:
        raise TrainError("merge-train must target the sole Integration branch")
    validate_sha(value.get("baseCommit"), "baseCommit")
    branch = value.get("trainBranch")
    if not isinstance(branch, str) or not branch.startswith(BRANCH_PREFIX) or branch == BRANCH_PREFIX:
        raise TrainError("trainBranch must use the merge-train/ prefix")
    if value.get("maximumCandidateCount") != MAX_CANDIDATES:
        raise TrainError("maximumCandidateCount must remain four")
    candidates = value.get("candidates")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise TrainError("a merge train must contain between one and four candidates")
    if value.get("candidateCount") != len(candidates):
        raise TrainError("candidateCount does not match the candidate list")
    numbers: set[int] = set()
    heads: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise TrainError("merge-train candidates must be objects")
        number = candidate.get("number")
        if not isinstance(number, int) or number <= 0 or number in numbers:
            raise TrainError("candidate pull-request numbers must be positive and unique")
        numbers.add(number)
        if candidate.get("baseBranch") != BASE_BRANCH:
            raise TrainError(f"candidate #{number} is not a root Integration pull request")
        head_branch = candidate.get("headBranch")
        if not isinstance(head_branch, str) or not head_branch or head_branch.startswith(BRANCH_PREFIX):
            raise TrainError(f"candidate #{number} has an invalid head branch")
        head = validate_sha(candidate.get("headCommit"), f"candidate #{number} headCommit")
        if head in heads:
            raise TrainError("candidate head commits must be unique")
        heads.add(head)
    if value.get("nativeMergeQueueStatus") != "BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER":
        raise TrainError("native merge-queue availability must remain explicit")
    if value.get("release") is not False:
        raise TrainError("merge-train evidence cannot promote Release")
    return value


def load_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TrainError(f"cannot read merge-train manifest {path}: {error}") from error
    return validate_manifest_value(value)


def pull_request(repo: str, number: int) -> dict[str, object]:
    value = gh_json(
        "pr",
        "view",
        str(number),
        "--repo",
        repo,
        "--json",
        "number,state,isDraft,baseRefName,headRefName,headRefOid,statusCheckRollup",
    )
    if not isinstance(value, dict):
        raise TrainError(f"candidate #{number} metadata is not an object")
    return value


def verify_candidate_metadata(
    metadata: dict[str, object],
    candidate: dict[str, object] | None = None,
) -> dict[str, object]:
    number = metadata.get("number")
    if not isinstance(number, int) or number <= 0:
        raise TrainError("candidate metadata has no positive pull-request number")
    if metadata.get("state") != "OPEN" or metadata.get("isDraft") is not False:
        raise TrainError(f"candidate #{number} must be Open and Ready")
    if metadata.get("baseRefName") != BASE_BRANCH:
        raise TrainError(f"candidate #{number} must be based directly on {BASE_BRANCH}")
    head_branch = metadata.get("headRefName")
    if not isinstance(head_branch, str) or not head_branch or head_branch.startswith(BRANCH_PREFIX):
        raise TrainError(f"candidate #{number} has an invalid head branch")
    head = validate_sha(metadata.get("headRefOid"), f"candidate #{number} head")
    if candidate is not None:
        if candidate.get("number") != number:
            raise TrainError("candidate pull-request number changed")
        if candidate.get("baseBranch") != metadata.get("baseRefName"):
            raise TrainError(f"candidate #{number} base branch changed")
        if candidate.get("headBranch") != head_branch:
            raise TrainError(f"candidate #{number} head branch changed")
        if candidate.get("headCommit") != head:
            raise TrainError(f"candidate #{number} head commit changed")

    rollup = metadata.get("statusCheckRollup")
    if not isinstance(rollup, list):
        raise TrainError(f"candidate #{number} has no required-check rollup")
    expected = set(required_checks())
    observed: dict[str, list[dict[str, object]]] = {name: [] for name in expected}
    for item in rollup:
        if isinstance(item, dict) and item.get("name") in expected:
            observed[str(item["name"])].append(item)
    missing = sorted(name for name, items in observed.items() if not items)
    non_success = sorted(
        name
        for name, items in observed.items()
        if items
        and any(
            item.get("status") != "COMPLETED" or item.get("conclusion") != "SUCCESS"
            for item in items
        )
    )
    if missing or non_success:
        raise TrainError(
            f"candidate #{number} required checks are not current green "
            f"(missing={missing}, nonSuccess={non_success})"
        )
    return {
        "number": number,
        "baseBranch": BASE_BRANCH,
        "headBranch": head_branch,
        "headCommit": head,
    }


def ensure_clean_train_branch(branch: str) -> str:
    if not branch.startswith(BRANCH_PREFIX) or branch == BRANCH_PREFIX:
        raise TrainError("current branch must use the merge-train/ prefix")
    current = git("branch", "--show-current")
    if current != branch:
        raise TrainError(f"current branch {current!r} does not match requested train branch {branch!r}")
    if git("status", "--porcelain"):
        raise TrainError("prepare requires a clean worktree")
    git("fetch", "origin", BASE_BRANCH)
    base = git("rev-parse", f"origin/{BASE_BRANCH}")
    head = git("rev-parse", "HEAD")
    if head != base:
        raise TrainError("prepare must start exactly at the latest origin/bootstrap/macos-r0")
    return base


def ensure_no_open_train(repo: str) -> None:
    value = gh_json(
        "pr",
        "list",
        "--repo",
        repo,
        "--state",
        "open",
        "--limit",
        "1000",
        "--json",
        "number,headRefName",
    )
    if not isinstance(value, list):
        raise TrainError("open pull-request list is invalid")
    active = [
        item
        for item in value
        if isinstance(item, dict)
        and isinstance(item.get("headRefName"), str)
        and str(item["headRefName"]).startswith(BRANCH_PREFIX)
    ]
    if active:
        numbers = sorted(item.get("number") for item in active)
        raise TrainError(f"an existing repository merge train is already open: {numbers}")


def prepare(repo: str, branch: str, numbers: list[int], output: Path) -> dict[str, object]:
    if repo != REPOSITORY:
        raise TrainError("prepare is repository-bound")
    if not 1 <= len(numbers) <= MAX_CANDIDATES or len(numbers) != len(set(numbers)):
        raise TrainError("prepare requires one to four unique pull-request numbers")
    base = ensure_clean_train_branch(branch)
    ensure_no_open_train(repo)
    candidates = [verify_candidate_metadata(pull_request(repo, number)) for number in numbers]
    for candidate in candidates:
        number = int(candidate["number"])
        head = str(candidate["headCommit"])
        git(
            "fetch",
            "origin",
            f"+refs/pull/{number}/head:refs/merge-train/pr-{number}",
        )
        fetched = git("rev-parse", f"refs/merge-train/pr-{number}")
        if fetched != head:
            raise TrainError(f"candidate #{number} changed while preparing the train")
        if command(("git", "merge-base", "--is-ancestor", head, base), check=False).returncode == 0:
            raise TrainError(f"candidate #{number} is already contained in bootstrap")

    for index, candidate in enumerate(candidates):
        candidate_head = str(candidate["headCommit"])
        for other in candidates[index + 1 :]:
            other_head = str(other["headCommit"])
            if (
                command(
                    ("git", "merge-base", "--is-ancestor", candidate_head, other_head),
                    check=False,
                ).returncode
                == 0
                or command(
                    ("git", "merge-base", "--is-ancestor", other_head, candidate_head),
                    check=False,
                ).returncode
                == 0
            ):
                raise TrainError(
                    f"candidates #{candidate['number']} and #{other['number']} are stacked; "
                    "a bounded train accepts independent root pull requests only"
                )

    try:
        for candidate in candidates:
            number = int(candidate["number"])
            head = str(candidate["headCommit"])
            command(
                (
                    "git",
                    "merge",
                    "--no-ff",
                    "--no-edit",
                    "-m",
                    f"Merge PR #{number} into bounded repository merge train",
                    head,
                )
            )
    except TrainError:
        command(("git", "merge", "--abort"), check=False)
        raise

    manifest: dict[str, object] = {
        "schema": SCHEMA,
        "repository": repo,
        "baseBranch": BASE_BRANCH,
        "baseCommit": base,
        "trainBranch": branch,
        "candidateCount": len(candidates),
        "maximumCandidateCount": MAX_CANDIDATES,
        "candidates": candidates,
        "createdAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "createdBy": "integration-manager",
        "nativeMergeQueueStatus": "BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER",
        "fullMatrixRequired": ["ubuntu-24.04", "macos-15"],
        "release": False,
    }
    validate_manifest_value(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    git("add", "--", str(output))
    git("commit", "-m", f"ci: attest max-4 merge train for PRs {','.join(str(number) for number in numbers)}")
    return manifest


def synthetic_merge_commit(current: str, candidate: str) -> str:
    merge = command(("git", "merge-tree", "--write-tree", current, candidate), check=False)
    if merge.returncode != 0:
        detail = (merge.stderr or merge.stdout).strip()
        raise TrainError(f"candidate merge is not clean: {detail}")
    tree_line = merge.stdout.splitlines()[0].strip() if merge.stdout.splitlines() else ""
    tree = validate_sha(tree_line, "synthetic merge tree")
    commit_env = dict(os.environ)
    commit_env.update(
        {
            "GIT_AUTHOR_NAME": "Hartevo Integration Manager",
            "GIT_AUTHOR_EMAIL": "integration@hartevo.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_NAME": "Hartevo Integration Manager",
            "GIT_COMMITTER_EMAIL": "integration@hartevo.invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
    )
    created = command(
        ("git", "commit-tree", tree, "-p", current, "-p", candidate),
        env=commit_env,
    ).stdout.strip()
    return validate_sha(created, "synthetic merge commit")


def verify_exact_history(manifest: dict[str, object], head: str) -> None:
    candidates = manifest["candidates"]
    assert isinstance(candidates, list)
    head_parents = git("rev-list", "--parents", "-n", "1", head).split()
    if len(head_parents) != 2:
        raise TrainError("train head must be the single-parent manifest commit")
    current = head_parents[1]
    for candidate in reversed(candidates):
        assert isinstance(candidate, dict)
        parents = git("rev-list", "--parents", "-n", "1", current).split()
        expected_head = str(candidate["headCommit"])
        if len(parents) != 3 or parents[2] != expected_head:
            raise TrainError(
                f"train history does not contain exact candidate #{candidate['number']} as the next merge parent"
            )
        current = parents[1]
    if current != manifest["baseCommit"]:
        raise TrainError("train first-parent history does not terminate at the attested bootstrap commit")


def verify_exact_tree(manifest: dict[str, object], head: str, manifest_path: Path) -> None:
    current = str(manifest["baseCommit"])
    candidates = manifest["candidates"]
    assert isinstance(candidates, list)
    for candidate in candidates:
        assert isinstance(candidate, dict)
        current = synthetic_merge_commit(current, str(candidate["headCommit"]))
    changed = [
        line
        for line in git("diff", "--name-only", current, head).splitlines()
        if line
    ]
    if changed != [str(manifest_path)]:
        raise TrainError(
            f"train tree contains changes outside the exact candidate merges and manifest: {changed}"
        )
    hosted = command(("git", "show", f"{head}:{manifest_path}")).stdout
    local = manifest_path.read_text(encoding="utf-8")
    if hosted != local:
        raise TrainError("checked-out merge-train manifest does not match the attested head")


def verify_hosted(
    repo: str,
    manifest_path: Path,
    base: str,
    head: str,
    branch: str,
) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    if repo != manifest["repository"] or branch != manifest["trainBranch"]:
        raise TrainError("hosted repository or train branch does not match the manifest")
    validate_sha(base, "event base")
    validate_sha(head, "event head")
    if base != manifest["baseCommit"]:
        raise TrainError("bootstrap advanced; rebuild the merge train instead of reusing it")
    if git("rev-parse", "HEAD") != head:
        raise TrainError("checked-out head does not match the pull-request event head")
    candidates = manifest["candidates"]
    assert isinstance(candidates, list)
    for candidate in candidates:
        assert isinstance(candidate, dict)
        verify_candidate_metadata(pull_request(repo, int(candidate["number"])), candidate)
        candidate_head = str(candidate["headCommit"])
        if command(("git", "merge-base", "--is-ancestor", candidate_head, head), check=False).returncode != 0:
            raise TrainError(f"candidate #{candidate['number']} is not contained in the train head")
    verify_exact_history(manifest, head)
    verify_exact_tree(manifest, head, manifest_path)
    return {
        "schema": SCHEMA,
        "status": "PASS",
        "repository": repo,
        "baseCommit": base,
        "headCommit": head,
        "candidateCount": len(candidates),
        "candidateNumbers": [candidate["number"] for candidate in candidates if isinstance(candidate, dict)],
        "fullMatrixRequired": True,
        "release": False,
    }


def self_test() -> None:
    candidates = [
        {
            "number": index,
            "baseBranch": BASE_BRANCH,
            "headBranch": f"codex/candidate-{index}",
            "headCommit": f"{index:040x}",
        }
        for index in range(1, MAX_CANDIDATES + 1)
    ]
    valid: dict[str, object] = {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "baseBranch": BASE_BRANCH,
        "baseCommit": "a" * 40,
        "trainBranch": "merge-train/self-test",
        "candidateCount": len(candidates),
        "maximumCandidateCount": MAX_CANDIDATES,
        "candidates": candidates,
        "nativeMergeQueueStatus": "BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER",
        "release": False,
    }
    validate_manifest_value(valid)
    too_many = json.loads(json.dumps(valid))
    too_many["candidates"].append(
        {
            "number": 5,
            "baseBranch": BASE_BRANCH,
            "headBranch": "codex/candidate-5",
            "headCommit": "5" * 40,
        }
    )
    too_many["candidateCount"] = 5
    try:
        validate_manifest_value(too_many)
    except TrainError:
        pass
    else:
        raise AssertionError("self-test accepted a five-entry merge train")
    wrong_base = json.loads(json.dumps(valid))
    wrong_base["candidates"][0]["baseBranch"] = "main"
    try:
        validate_manifest_value(wrong_base)
    except TrainError:
        pass
    else:
        raise AssertionError("self-test accepted a non-root candidate")
    unclaimed = json.loads(json.dumps(valid))
    unclaimed["nativeMergeQueueStatus"] = "ACTIVE"
    try:
        validate_manifest_value(unclaimed)
    except TrainError:
        pass
    else:
        raise AssertionError("self-test accepted a false hosted queue claim")
    self_test_exact_composite()
    print(json.dumps({"schema": f"{SCHEMA}-self-test", "status": "PASS"}, sort_keys=True))


def self_test_exact_composite() -> None:
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="hartevo-merge-train-self-test-") as directory:
        root = Path(directory)
        os.chdir(root)
        try:
            command(("git", "init", "--quiet"))
            git("config", "user.name", "Hartevo CI")
            git("config", "user.email", "ci@hartevo.invalid")
            Path("base.txt").write_text("base\n", encoding="utf-8")
            git("add", "base.txt")
            git("commit", "--quiet", "-m", "base")
            base = git("rev-parse", "HEAD")

            git("switch", "--quiet", "--detach", base)
            git("switch", "--quiet", "-c", "candidate-one")
            Path("one.txt").write_text("one\n", encoding="utf-8")
            git("add", "one.txt")
            git("commit", "--quiet", "-m", "candidate one")
            first = git("rev-parse", "HEAD")

            git("switch", "--quiet", "--detach", base)
            git("switch", "--quiet", "-c", "candidate-two")
            Path("two.txt").write_text("two\n", encoding="utf-8")
            git("add", "two.txt")
            git("commit", "--quiet", "-m", "candidate two")
            second = git("rev-parse", "HEAD")

            git("switch", "--quiet", "--detach", base)
            git("switch", "--quiet", "-c", "merge-train/self-test")
            git("merge", "--quiet", "--no-ff", "--no-edit", "-m", "merge one", first)
            git("merge", "--quiet", "--no-ff", "--no-edit", "-m", "merge two", second)
            composite = git("rev-parse", "HEAD")
            manifest: dict[str, object] = {
                "schema": SCHEMA,
                "repository": REPOSITORY,
                "baseBranch": BASE_BRANCH,
                "baseCommit": base,
                "trainBranch": "merge-train/self-test",
                "candidateCount": 2,
                "maximumCandidateCount": MAX_CANDIDATES,
                "candidates": [
                    {
                        "number": 1,
                        "baseBranch": BASE_BRANCH,
                        "headBranch": "candidate-one",
                        "headCommit": first,
                    },
                    {
                        "number": 2,
                        "baseBranch": BASE_BRANCH,
                        "headBranch": "candidate-two",
                        "headCommit": second,
                    },
                ],
                "nativeMergeQueueStatus": "BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER",
                "release": False,
            }
            validate_manifest_value(manifest)
            MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
            MANIFEST_PATH.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            git("add", "--", str(MANIFEST_PATH))
            git("commit", "--quiet", "-m", "attest exact train")
            head = git("rev-parse", "HEAD")
            verify_exact_history(manifest, head)
            verify_exact_tree(manifest, head, MANIFEST_PATH)

            git("switch", "--quiet", "--detach", composite)
            Path("unexpected.txt").write_text("must fail closed\n", encoding="utf-8")
            MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
            MANIFEST_PATH.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            git("add", "--", str(MANIFEST_PATH), "unexpected.txt")
            git("commit", "--quiet", "-m", "tampered train")
            tampered = git("rev-parse", "HEAD")
            verify_exact_history(manifest, tampered)
            try:
                verify_exact_tree(manifest, tampered, MANIFEST_PATH)
            except TrainError:
                pass
            else:
                raise AssertionError("self-test accepted a train tree with unclaimed changes")
        finally:
            os.chdir(previous)


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--repo", default=REPOSITORY)
    prepare_parser.add_argument("--branch", required=True)
    prepare_parser.add_argument("--pr", type=int, action="append", required=True)
    prepare_parser.add_argument("--output", type=Path, default=MANIFEST_PATH)

    verify_parser = subparsers.add_parser("verify-hosted")
    verify_parser.add_argument("--repo", default=REPOSITORY)
    verify_parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    verify_parser.add_argument("--base", required=True)
    verify_parser.add_argument("--head", required=True)
    verify_parser.add_argument("--branch", required=True)

    manifest_parser = subparsers.add_parser("verify-manifest")
    manifest_parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    subparsers.add_parser("self-test")
    args = parser.parse_args(list(argv))
    try:
        if args.command == "prepare":
            result = prepare(args.repo, args.branch, args.pr, args.output)
            print(json.dumps({**result, "status": "PREPARED"}, sort_keys=True))
            return 0
        if args.command == "verify-hosted":
            print(
                json.dumps(
                    verify_hosted(args.repo, args.manifest, args.base, args.head, args.branch),
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "verify-manifest":
            manifest = load_manifest(args.manifest)
            print(
                json.dumps(
                    {
                        "schema": SCHEMA,
                        "status": "PASS",
                        "candidateCount": manifest["candidateCount"],
                        "release": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        self_test()
        return 0
    except (OSError, TrainError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(
            json.dumps({"schema": SCHEMA, "status": "FAIL", "message": str(error)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
