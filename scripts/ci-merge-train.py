#!/usr/bin/env python3
"""Prepare trains and verify recoverable protected-branch merges.

GitHub's hosted merge queue is not available to public repositories owned by
personal accounts.  This train preserves the important queue semantics without
weakening the protected Integration branch:

* one temporary ``merge-train/*`` pull request contains one to four reviewed
  root pull-request heads;
* the train history and tree are reconstructed and checked in CI;
* only that composite head runs the full Ubuntu/macOS matrix; and
* ordinary pull requests and composite trains are both merged normally, never
  by direct push or rule bypass.

``prepare`` stops after making local merge commits and the manifest-only final
commit.  ``publish`` then performs one exact verification, one normal push, and
one non-Draft train PR creation so the Integration Manager cannot lose the
base/head/body tuple between manual commands.
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

import repository_governance as governance


SCHEMA = "hartevo-repository-merge-train/v1"
REPOSITORY = "tangpingqingwa/hartevo-desktop"
BASE_BRANCH = "bootstrap/macos-r0"
BRANCH_PREFIX = "merge-train/"
MANIFEST_DIRECTORY = Path(".github/merge-train/manifests")
MAX_CANDIDATES = 4
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
GITHUB_MERGE_PATTERN = re.compile(r"^Merge pull request #([1-9][0-9]*) from [^\n]+(?:\n|$)")
GITHUB_PR_SUFFIX_PATTERN = re.compile(r"\(#([1-9][0-9]*)\)$")
TRUSTED_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = TRUSTED_REPOSITORY_ROOT / ".github/policies/branch-ruleset-policy.json"


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


def recover_github_pull_request_number(merge_message: str) -> int | None:
    """Recover a PR number from either accepted GitHub merge-title form."""
    match = GITHUB_MERGE_PATTERN.match(merge_message)
    if match is not None:
        return int(match.group(1))
    subject = merge_message.partition("\n")[0]
    match = GITHUB_PR_SUFFIX_PATTERN.search(subject)
    return int(match.group(1)) if match is not None else None


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
    expected = (
        "PR / Workflow policy",
        "Governance / PR admission",
        "PR / Scope plan",
        "PR / Result taxonomy",
    )
    if tuple(checks) != expected:
        raise TrainError("branch policy must use the four stable required contexts")
    return expected


def validate_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA_PATTERN.fullmatch(value) is None:
        raise TrainError(f"{label} must be a lowercase 40-character Git SHA")
    return value


def manifest_path_for_branch(branch: str) -> Path:
    if not isinstance(branch, str) or not branch.startswith(BRANCH_PREFIX) or branch == BRANCH_PREFIX:
        raise TrainError("train manifest path requires a merge-train branch")
    suffix = branch.removeprefix(BRANCH_PREFIX)
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", suffix):
        raise TrainError("train branch contains characters unsafe for a manifest path")
    return MANIFEST_DIRECTORY / f"{suffix.replace('/', '--')}.json"


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
        if candidate.get("baseCommit") != value.get("baseCommit"):
            raise TrainError(f"candidate #{number} is not bound to the exact train base")
        head_branch = candidate.get("headBranch")
        if not isinstance(head_branch, str) or not head_branch or head_branch.startswith(BRANCH_PREFIX):
            raise TrainError(f"candidate #{number} has an invalid head branch")
        head = validate_sha(candidate.get("headCommit"), f"candidate #{number} headCommit")
        if head in heads:
            raise TrainError("candidate head commits must be unique")
        heads.add(head)
        review = candidate.get("review")
        if not isinstance(review, dict):
            raise TrainError(f"candidate #{number} has no exact independent review receipt")
        review_type = review.get("reviewType", "receipt")
        if review_type == "github":
            if review.get("schema") != governance.GITHUB_REVIEW_SCHEMA:
                raise TrainError(f"candidate #{number} GitHub review schema drifted")
            if review.get("state") not in {"APPROVED", "COMMENTED"}:
                raise TrainError(f"candidate #{number} GitHub review state is invalid")
            reviewed_head = validate_sha(review.get("reviewedHeadSha"), f"candidate #{number} reviewedHeadSha")
            if reviewed_head != head:
                raise TrainError(f"candidate #{number} GitHub review is stale")
            reviewer_task = review.get("reviewerTaskId")
            if not isinstance(reviewer_task, str) or not reviewer_task.strip():
                raise TrainError(f"candidate #{number} GitHub review has no reviewer task")
        else:
            # Historical manifests use receipt-only review commits.  Keep this
            # contract immutable while allowing new ordinary candidates to
            # attest the exact-head GitHub review that admission now accepts.
            if review_type != "receipt":
                raise TrainError(f"candidate #{number} review type is invalid")
            if review.get("receiptPath") != governance.review_path(number).as_posix():
                raise TrainError(f"candidate #{number} review receipt path drifted")
            validate_sha(review.get("reviewedHeadSha"), f"candidate #{number} reviewedHeadSha")
            receipt_digest = review.get("receiptDigest")
            if not isinstance(receipt_digest, str) or governance.SHA256.fullmatch(receipt_digest) is None:
                raise TrainError(f"candidate #{number} review receipt digest is invalid")
            author_task = review.get("authorTaskId")
            reviewer_task = review.get("reviewerTaskId")
            if not isinstance(author_task, str) or not author_task or not isinstance(reviewer_task, str) or not reviewer_task or author_task == reviewer_task:
                raise TrainError(f"candidate #{number} review is not independently non-author")
        paths = review.get("exactPaths")
        if not isinstance(paths, list) or not paths or not all(isinstance(path, str) and path for path in paths) or paths != sorted(set(paths)):
            raise TrainError(f"candidate #{number} review path envelope is invalid")
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
        "number,state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,body,statusCheckRollup",
    )
    if not isinstance(value, dict):
        raise TrainError(f"candidate #{number} metadata is not an object")
    return value


def verify_candidate_metadata(
    metadata: dict[str, object],
    candidate: dict[str, object] | None = None,
    expected_base: str | None = None,
) -> dict[str, object]:
    number = metadata.get("number")
    if not isinstance(number, int) or number <= 0:
        raise TrainError("candidate metadata has no positive pull-request number")
    if metadata.get("state") != "OPEN" or metadata.get("isDraft") is not False:
        raise TrainError(f"candidate #{number} must be Open and Ready")
    if metadata.get("baseRefName") != BASE_BRANCH:
        raise TrainError(f"candidate #{number} must be based directly on {BASE_BRANCH}")
    base_oid = validate_sha(metadata.get("baseRefOid"), f"candidate #{number} base")
    if expected_base is not None and base_oid != expected_base:
        raise TrainError(f"candidate #{number} does not target the exact current protected base")
    head_branch = metadata.get("headRefName")
    if not isinstance(head_branch, str) or not head_branch or head_branch.startswith(BRANCH_PREFIX):
        raise TrainError(f"candidate #{number} has an invalid head branch")
    head = validate_sha(metadata.get("headRefOid"), f"candidate #{number} head")
    if candidate is not None:
        if candidate.get("number") != number:
            raise TrainError("candidate pull-request number changed")
        if candidate.get("baseBranch") != metadata.get("baseRefName"):
            raise TrainError(f"candidate #{number} base branch changed")
        if candidate.get("baseCommit") != base_oid:
            raise TrainError(f"candidate #{number} base commit changed")
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
        "baseCommit": base_oid,
        "headBranch": head_branch,
        "headCommit": head,
    }


def verify_candidate_review(
    repo: str,
    number: int,
    metadata: dict[str, object],
    base: str,
    head: str,
) -> dict[str, object]:
    """Verify the candidate's admission and exact independent review.

    Ordinary feature/dependency candidates use the trusted-base GitHub review
    marker.  High-risk and historical candidates continue to use the
    receipt-only commit contract.
    """
    body = metadata.get("body")
    admission = governance.extract_admission(body)
    changed = governance.changed_paths(Path("."), base, head)
    policy = governance.load_policy()
    events = governance.load_ledger()
    result = governance.verify_admission_value(
        admission,
        changed=changed,
        paused=governance.global_paused(events),
        policy=policy,
    )
    if result.get("ordinary") is True:
        reviews = governance.gh_json("api", f"repos/{repo}/pulls/{number}/reviews?per_page=100")
        github = governance.validate_github_review_records(
            reviews,
            head_sha=head,
            owner=str(result["owner"]),
        )
        return {
            "reviewType": "github",
            "schema": governance.GITHUB_REVIEW_SCHEMA,
            "state": github["state"],
            "reviewedHeadSha": head,
            "reviewerTaskId": github["reviewerTaskId"],
            "reviewId": github.get("reviewId"),
            "exactPaths": changed,
        }
    review = governance.verify_review_commit(Path("."), number, base, head)
    return {
        "reviewType": "receipt",
        "receiptPath": review["receiptPath"],
        "receiptDigest": review["receiptDigest"],
        "reviewedHeadSha": review["reviewedHeadSha"],
        "authorTaskId": review["authorTaskId"],
        "reviewerTaskId": review["reviewerTaskId"],
        "exactPaths": review["exactPaths"],
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


def prepare(repo: str, branch: str, numbers: list[int], output: Path | None) -> dict[str, object]:
    if repo != REPOSITORY:
        raise TrainError("prepare is repository-bound")
    if not 1 <= len(numbers) <= MAX_CANDIDATES or len(numbers) != len(set(numbers)):
        raise TrainError("prepare requires one to four unique pull-request numbers")
    base = ensure_clean_train_branch(branch)
    ensure_no_open_train(repo)
    manifest_path = manifest_path_for_branch(branch)
    if output is not None and output != manifest_path:
        raise TrainError(f"train manifest must use immutable historical path {manifest_path}")
    output = manifest_path
    metadata_by_number: dict[int, dict[str, object]] = {}
    candidates: list[dict[str, object]] = []
    for number in numbers:
        metadata = pull_request(repo, number)
        metadata_by_number[number] = metadata
        candidates.append(verify_candidate_metadata(metadata, expected_base=base))
    owned_paths: set[str] = set()
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
        try:
            review = verify_candidate_review(repo, number, metadata_by_number[number], base, head)
        except governance.GovernanceError as error:
            raise TrainError(f"candidate #{number} independent review failed: {error}") from error
        paths = set(str(path) for path in review["exactPaths"])
        overlap = sorted(paths & owned_paths)
        if overlap:
            raise TrainError(f"candidate #{number} overlaps an earlier train candidate: {overlap}")
        owned_paths.update(paths)
        candidate["review"] = review

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


def train_pull_request_body(
    manifest: dict[str, object],
    manifest_path: Path,
    issue: int,
    owner: str,
    head: str,
) -> str:
    if issue <= 0 or not owner.strip():
        raise TrainError("train publication requires a positive issue and one accountable owner")
    base = str(manifest["baseCommit"])
    changed = sorted(line for line in git("diff", "--name-only", f"{base}..{head}").splitlines() if line)
    if not changed or manifest_path.as_posix() not in changed:
        raise TrainError("train publication path envelope is missing its immutable manifest")
    admission = {
        "schema": "hartevo-pr-admission/v1",
        "changeClass": "integration-recovery",
        "issue": issue,
        "owner": owner.strip(),
        "ownedPaths": changed,
        "rollback": "Close this exact train PR and delete only its temporary merge-train branch; do not move the protected ref.",
        "externalEffects": False,
        "release": False,
    }
    candidates = manifest["candidates"]
    assert isinstance(candidates, list)
    numbers = [int(candidate["number"]) for candidate in candidates if isinstance(candidate, dict)]
    return (
        "## Bounded repository merge train\n\n"
        f"- Protected base: `{base}`\n"
        f"- Exact train head: `{head}`\n"
        f"- Candidates: {', '.join(f'#{number}' for number in numbers)}\n"
        f"- Immutable manifest: `{manifest_path.as_posix()}`\n"
        "- Release: `false`\n\n"
        "<!-- hartevo-governance\n"
        + json.dumps(admission, indent=2, sort_keys=True)
        + "\n-->\n"
    )


def publish(repo: str, branch: str, issue: int, owner: str) -> dict[str, object]:
    if repo != REPOSITORY:
        raise TrainError("publish is repository-bound")
    if git("branch", "--show-current") != branch or not branch.startswith(BRANCH_PREFIX):
        raise TrainError("publish requires the exact checked-out merge-train branch")
    if git("status", "--porcelain"):
        raise TrainError("publish requires a clean train worktree")
    head = validate_sha(git("rev-parse", "HEAD"), "train publish head")
    manifest_path = discover_manifest(head, branch)
    manifest = load_manifest(manifest_path)
    base = str(manifest["baseCommit"])
    live_base = command(("git", "ls-remote", "origin", f"refs/heads/{BASE_BRANCH}")).stdout.split()
    if len(live_base) != 2 or live_base[0] != base:
        raise TrainError("protected base advanced before train publication")
    verify_hosted(repo, manifest_path, base, head, branch)
    ensure_no_open_train(repo)
    remote = command(("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}")).stdout.split()
    if remote and (len(remote) != 2 or remote[0] != head):
        raise TrainError("remote train branch exists at another head")
    if not remote:
        command(("git", "push", "--set-upstream", "origin", f"HEAD:refs/heads/{branch}"))
    body = train_pull_request_body(manifest, manifest_path, issue, owner, head)
    title_numbers = ", ".join(
        f"#{candidate['number']}" for candidate in manifest["candidates"] if isinstance(candidate, dict)
    )
    created = command(
        (
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            BASE_BRANCH,
            "--head",
            branch,
            "--title",
            f"integration: bounded train for {title_numbers}",
            "--body",
            body,
        )
    ).stdout.strip()
    match = re.search(r"/pull/(\d+)$", created)
    if match is None:
        raise TrainError(f"GitHub did not return an exact train PR URL: {created!r}")
    number = int(match.group(1))
    metadata = gh_json(
        "pr",
        "view",
        str(number),
        "--repo",
        repo,
        "--json",
        "number,state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,url",
    )
    if (
        not isinstance(metadata, dict)
        or metadata.get("state") != "OPEN"
        or metadata.get("isDraft") is not False
        or metadata.get("baseRefName") != BASE_BRANCH
        or metadata.get("baseRefOid") != base
        or metadata.get("headRefName") != branch
        or metadata.get("headRefOid") != head
    ):
        raise TrainError("published train PR tuple drifted")
    return {
        "schema": SCHEMA,
        "status": "PUBLISHED",
        "pr": number,
        "url": metadata.get("url"),
        "baseCommit": base,
        "headCommit": head,
        "trainBranch": branch,
        "manifestPath": manifest_path.as_posix(),
        "candidateNumbers": [
            candidate["number"] for candidate in manifest["candidates"] if isinstance(candidate, dict)
        ],
        "normalPush": True,
        "draft": False,
        "release": False,
    }


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
    owned_paths: set[str] = set()
    for candidate in candidates:
        assert isinstance(candidate, dict)
        metadata = pull_request(repo, int(candidate["number"]))
        verify_candidate_metadata(
            metadata,
            candidate,
            expected_base=str(manifest["baseCommit"]),
        )
        candidate_head = str(candidate["headCommit"])
        if command(("git", "merge-base", "--is-ancestor", candidate_head, head), check=False).returncode != 0:
            raise TrainError(f"candidate #{candidate['number']} is not contained in the train head")
        expected_review = candidate.get("review")
        if not isinstance(expected_review, dict):
            raise TrainError(f"candidate #{candidate['number']} manifest review is missing")
        review_type = expected_review.get("reviewType", "receipt")
        try:
            if review_type == "github":
                review = verify_candidate_review(
                    repo,
                    int(candidate["number"]),
                    metadata,
                    str(manifest["baseCommit"]),
                    candidate_head,
                )
            else:
                review = governance.verify_review_commit(
                    Path("."),
                    int(candidate["number"]),
                    str(manifest["baseCommit"]),
                    candidate_head,
                )
                review = {
                    "reviewType": "receipt",
                    "receiptPath": review["receiptPath"],
                    "receiptDigest": review["receiptDigest"],
                    "reviewedHeadSha": review["reviewedHeadSha"],
                    "authorTaskId": review["authorTaskId"],
                    "reviewerTaskId": review["reviewerTaskId"],
                    "exactPaths": review["exactPaths"],
                }
        except governance.GovernanceError as error:
            raise TrainError(f"candidate #{candidate['number']} review failed in hosted verification: {error}") from error
        expected_keys = (
            ("reviewType", "schema", "state", "reviewedHeadSha", "reviewerTaskId", "exactPaths")
            if review_type == "github"
            else ("receiptPath", "receiptDigest", "reviewedHeadSha", "authorTaskId", "reviewerTaskId", "exactPaths")
        )
        for key in expected_keys:
            if expected_review.get(key) != review.get(key):
                raise TrainError(f"candidate #{candidate['number']} manifest review field {key} drifted")
        paths = set(str(path) for path in review["exactPaths"])
        overlap = sorted(paths & owned_paths)
        if overlap:
            raise TrainError(f"candidate #{candidate['number']} overlaps another hosted train candidate: {overlap}")
        owned_paths.update(paths)
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


def discover_manifest(head: str, branch: str) -> Path:
    """Discover the immutable manifest added by the train's final commit."""
    validate_sha(head, "train head")
    expected = manifest_path_for_branch(branch)
    parents = git("rev-list", "--parents", "-n", "1", head).split()
    if len(parents) != 2:
        raise TrainError("train head must be the single-parent manifest commit")
    changed = sorted(line for line in git("diff", "--name-only", f"{parents[1]}..{head}").splitlines() if line)
    if changed != [expected.as_posix()]:
        raise TrainError(f"train final commit must add only {expected}: {changed}")
    manifest = load_manifest(expected)
    if manifest.get("trainBranch") != branch:
        raise TrainError("discovered manifest train branch mismatch")
    return expected


def discover_manifest_at_head(head: str) -> tuple[Path, dict[str, object]]:
    validate_sha(head, "train head")
    parents = git("rev-list", "--parents", "-n", "1", head).split()
    if len(parents) != 2:
        raise TrainError("train head must be the single-parent manifest commit")
    changed = sorted(line for line in git("diff", "--name-only", f"{parents[1]}..{head}").splitlines() if line)
    manifest_paths = [
        Path(path)
        for path in changed
        if path.startswith(MANIFEST_DIRECTORY.as_posix() + "/") and path.endswith(".json")
    ]
    if len(changed) != 1 or len(manifest_paths) != 1:
        raise TrainError(f"train final commit must add exactly one immutable manifest: {changed}")
    path = manifest_paths[0]
    try:
        value = json.loads(git("show", f"{head}:{path.as_posix()}"))
    except json.JSONDecodeError as error:
        raise TrainError("train manifest at the attested head is invalid JSON") from error
    manifest = validate_manifest_value(value)
    if manifest_path_for_branch(str(manifest["trainBranch"])) != path:
        raise TrainError("train manifest path is not derived from its exact branch")
    return path, manifest


def verify_attested_reviews(manifest: dict[str, object]) -> list[int]:
    candidates = manifest["candidates"]
    assert isinstance(candidates, list)
    owned_paths: set[str] = set()
    numbers: list[int] = []
    for candidate in candidates:
        assert isinstance(candidate, dict)
        number = int(candidate["number"])
        numbers.append(number)
        expected = candidate.get("review")
        if not isinstance(expected, dict):
            raise TrainError(f"candidate #{number} manifest review is missing")
        review_type = expected.get("reviewType", "receipt")
        try:
            if review_type == "github":
                metadata = pull_request(REPOSITORY, number)
                verify_candidate_metadata(
                    metadata,
                    candidate,
                    expected_base=str(manifest["baseCommit"]),
                )
                review = verify_candidate_review(
                    REPOSITORY,
                    number,
                    metadata,
                    str(manifest["baseCommit"]),
                    str(candidate["headCommit"]),
                )
            else:
                review = governance.verify_review_commit(
                    Path("."),
                    number,
                    str(manifest["baseCommit"]),
                    str(candidate["headCommit"]),
                )
                review = {
                    "reviewType": "receipt",
                    "receiptPath": review["receiptPath"],
                    "receiptDigest": review["receiptDigest"],
                    "reviewedHeadSha": review["reviewedHeadSha"],
                    "authorTaskId": review["authorTaskId"],
                    "reviewerTaskId": review["reviewerTaskId"],
                    "exactPaths": review["exactPaths"],
                }
        except governance.GovernanceError as error:
            raise TrainError(f"candidate #{number} attested review failed: {error}") from error
        expected_keys = (
            ("reviewType", "schema", "state", "reviewedHeadSha", "reviewerTaskId", "exactPaths")
            if review_type == "github"
            else ("receiptPath", "receiptDigest", "reviewedHeadSha", "authorTaskId", "reviewerTaskId", "exactPaths")
        )
        for key in expected_keys:
            if expected.get(key) != review.get(key):
                raise TrainError(f"candidate #{number} attested review field {key} drifted")
        paths = set(str(path) for path in review["exactPaths"])
        overlap = sorted(paths & owned_paths)
        if overlap:
            raise TrainError(f"candidate #{number} overlaps another attested candidate: {overlap}")
        owned_paths.update(paths)
    return numbers


def verify_bootstrap_push(event_path: Path) -> dict[str, object]:
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TrainError(f"cannot read bootstrap push event: {error}") from error
    if not isinstance(event, dict) or event.get("ref") != f"refs/heads/{BASE_BRANCH}":
        raise TrainError("integration gate accepts only bootstrap/macos-r0 push events")
    if event.get("forced") is True or event.get("deleted") is True or event.get("created") is True:
        raise TrainError("protected integration push must be a normal existing-branch advance")
    before = validate_sha(event.get("before"), "push before")
    after = validate_sha(event.get("after"), "push after")
    if git("rev-parse", "HEAD") != after:
        raise TrainError("checked-out integration head does not match the push event")
    parents = git("rev-list", "--parents", "-n", "1", after).split()
    if len(parents) != 3 or parents[1] != before:
        raise TrainError("protected integration advance must be a normal merge whose first parent is the prior protected head")
    pull_request_head = parents[2]
    head_parents = git("rev-list", "--parents", "-n", "1", pull_request_head).split()
    changed_from_head_parent = (
        sorted(
            line
            for line in git("diff", "--name-only", f"{head_parents[1]}..{pull_request_head}").splitlines()
            if line
        )
        if len(head_parents) == 2
        else []
    )
    manifest_changes = [
        path
        for path in changed_from_head_parent
        if path.startswith(MANIFEST_DIRECTORY.as_posix() + "/") and path.endswith(".json")
    ]

    if manifest_changes:
        path, manifest = discover_manifest_at_head(pull_request_head)
        if manifest.get("baseCommit") != before:
            raise TrainError("merged train is stale relative to the prior protected head")
        verify_exact_history(manifest, pull_request_head)
        verify_exact_tree(manifest, pull_request_head, path)
        numbers = verify_attested_reviews(manifest)
        if git("rev-parse", f"{after}^{{tree}}") != git("rev-parse", f"{pull_request_head}^{{tree}}"):
            raise TrainError("protected merge tree differs from the hosted-green train tree")
        return {
            "schema": "hartevo-bootstrap-integration-gate/v1",
            "status": "PASS",
            "mode": "TRAIN",
            "before": before,
            "after": after,
            "trainHead": pull_request_head,
            "trainBranch": manifest["trainBranch"],
            "manifestPath": path.as_posix(),
            "candidateNumbers": numbers,
            "candidateCount": len(numbers),
            "release": False,
        }

    if command(("git", "merge-base", "--is-ancestor", before, pull_request_head), check=False).returncode != 0:
        raise TrainError("direct pull request head is not based on the prior protected head")
    if git("rev-parse", f"{after}^{{tree}}") != git("rev-parse", f"{pull_request_head}^{{tree}}"):
        raise TrainError("protected merge tree differs from the direct pull request head tree")
    merge_message = git("show", "-s", "--format=%B", after)
    number = recover_github_pull_request_number(merge_message)
    if number is None:
        raise TrainError("direct protected merge has no recoverable GitHub pull request number")
    return {
        "schema": "hartevo-bootstrap-integration-gate/v1",
        "status": "PASS",
        "mode": "DIRECT",
        "before": before,
        "after": after,
        "pr": number,
        "head": pull_request_head,
        "release": False,
    }


def self_test() -> None:
    candidates = [
        {
            "number": index,
            "baseBranch": BASE_BRANCH,
            "baseCommit": "a" * 40,
            "headBranch": f"codex/candidate-{index}",
            "headCommit": f"{index:040x}",
            "review": {
                "receiptPath": governance.review_path(index).as_posix(),
                "receiptDigest": f"{index:064x}",
                "reviewedHeadSha": f"{index + 10:040x}",
                "authorTaskId": f"author-{index}",
                "reviewerTaskId": f"reviewer-{index}",
                "exactPaths": [f"candidate-{index}/file"],
            },
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
    github_manifest = json.loads(json.dumps(valid))
    github_manifest["candidates"][0]["review"] = {
        "reviewType": "github",
        "schema": governance.GITHUB_REVIEW_SCHEMA,
        "state": "COMMENTED",
        "reviewedHeadSha": github_manifest["candidates"][0]["headCommit"],
        "reviewerTaskId": "github-reviewer-1",
        "exactPaths": ["candidate-1/file"],
    }
    validate_manifest_value(github_manifest)
    too_many = json.loads(json.dumps(valid))
    too_many["candidates"].append(
        {
            "number": 5,
            "baseBranch": BASE_BRANCH,
            "baseCommit": "a" * 40,
            "headBranch": "codex/candidate-5",
            "headCommit": "5" * 40,
            "review": {
                "receiptPath": governance.review_path(5).as_posix(),
                "receiptDigest": "5" * 64,
                "reviewedHeadSha": "6" * 40,
                "authorTaskId": "author-5",
                "reviewerTaskId": "reviewer-5",
                "exactPaths": ["candidate-5/file"],
            },
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
            first_reviewed = git("rev-parse", "HEAD")
            first_receipt = root / governance.review_path(1)
            governance.create_review_receipt(root, 1, base, first_reviewed, "author-1", "reviewer-1", first_receipt)
            git("add", governance.review_path(1).as_posix())
            git("commit", "--quiet", "-m", "review candidate one")
            first = git("rev-parse", "HEAD")
            first_review = governance.verify_review_commit(root, 1, base, first)

            git("switch", "--quiet", "--detach", base)
            git("switch", "--quiet", "-c", "candidate-two")
            Path("two.txt").write_text("two\n", encoding="utf-8")
            git("add", "two.txt")
            git("commit", "--quiet", "-m", "candidate two")
            second_reviewed = git("rev-parse", "HEAD")
            second_receipt = root / governance.review_path(2)
            governance.create_review_receipt(root, 2, base, second_reviewed, "author-2", "reviewer-2", second_receipt)
            git("add", governance.review_path(2).as_posix())
            git("commit", "--quiet", "-m", "review candidate two")
            second = git("rev-parse", "HEAD")
            second_review = governance.verify_review_commit(root, 2, base, second)

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
                        "baseCommit": base,
                        "headBranch": "candidate-one",
                        "headCommit": first,
                        "review": {
                            "receiptPath": first_review["receiptPath"],
                            "receiptDigest": first_review["receiptDigest"],
                            "reviewedHeadSha": first_review["reviewedHeadSha"],
                            "authorTaskId": first_review["authorTaskId"],
                            "reviewerTaskId": first_review["reviewerTaskId"],
                            "exactPaths": first_review["exactPaths"],
                        },
                    },
                    {
                        "number": 2,
                        "baseBranch": BASE_BRANCH,
                        "baseCommit": base,
                        "headBranch": "candidate-two",
                        "headCommit": second,
                        "review": {
                            "receiptPath": second_review["receiptPath"],
                            "receiptDigest": second_review["receiptDigest"],
                            "reviewedHeadSha": second_review["reviewedHeadSha"],
                            "authorTaskId": second_review["authorTaskId"],
                            "reviewerTaskId": second_review["reviewerTaskId"],
                            "exactPaths": second_review["exactPaths"],
                        },
                    },
                ],
                "nativeMergeQueueStatus": "BLOCKED_ENV_PERSONAL_ACCOUNT_OWNER",
                "release": False,
            }
            validate_manifest_value(manifest)
            manifest_path = manifest_path_for_branch("merge-train/self-test")
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            git("add", "--", str(manifest_path))
            git("commit", "--quiet", "-m", "attest exact train")
            head = git("rev-parse", "HEAD")
            verify_exact_history(manifest, head)
            verify_exact_tree(manifest, head, manifest_path)
            verify_attested_reviews(manifest)
            discovered_path, discovered_manifest = discover_manifest_at_head(head)
            if discovered_path != manifest_path or discovered_manifest != manifest:
                raise AssertionError("self-test did not rediscover the exact immutable train manifest")
            publication_body = train_pull_request_body(manifest, manifest_path, 99, "integration-manager", head)
            if '"changeClass": "integration-recovery"' not in publication_body or manifest_path.as_posix() not in publication_body:
                raise AssertionError("self-test train publication body lost admission or manifest binding")

            git("switch", "--quiet", "--detach", base)
            git("merge", "--quiet", "--no-ff", "--no-edit", "-m", "merge exact train", head)
            bootstrap = git("rev-parse", "HEAD")
            event_path = root / "push-event.json"
            event_path.write_text(
                json.dumps(
                    {
                        "ref": f"refs/heads/{BASE_BRANCH}",
                        "before": base,
                        "after": bootstrap,
                        "forced": False,
                        "created": False,
                        "deleted": False,
                    }
                ),
                encoding="utf-8",
            )
            bootstrap_result = verify_bootstrap_push(event_path)
            if bootstrap_result.get("mode") != "TRAIN" or bootstrap_result["candidateNumbers"] != [1, 2]:
                raise AssertionError("bootstrap gate lost the exact candidate set")

            git("switch", "--quiet", "--detach", base)
            git("switch", "--quiet", "-c", "direct-candidate")
            Path("direct.txt").write_text("direct\n", encoding="utf-8")
            git("add", "direct.txt")
            git("commit", "--quiet", "-m", "direct candidate")
            direct_head = git("rev-parse", "HEAD")
            git("switch", "--quiet", "--detach", base)
            git(
                "merge",
                "--quiet",
                "--no-ff",
                "--no-edit",
                "-m",
                "Merge pull request #42 from example/direct-candidate",
                direct_head,
            )
            direct_merge = git("rev-parse", "HEAD")
            event_path.write_text(
                json.dumps(
                    {
                        "ref": f"refs/heads/{BASE_BRANCH}",
                        "before": base,
                        "after": direct_merge,
                        "forced": False,
                        "created": False,
                        "deleted": False,
                    }
                ),
                encoding="utf-8",
            )
            direct_result = verify_bootstrap_push(event_path)
            if direct_result.get("mode") != "DIRECT" or direct_result.get("pr") != 42 or direct_result.get("head") != direct_head:
                raise AssertionError("bootstrap gate lost the recoverable direct pull request record")

            custom_title_merge = git(
                "commit-tree",
                f"{direct_head}^{{tree}}",
                "-p",
                base,
                "-p",
                direct_head,
                "-m",
                "feat(cordis): authorize desktop domain commands (#42)",
            )
            git("switch", "--quiet", "--detach", custom_title_merge)
            event_path.write_text(
                json.dumps(
                    {
                        "ref": f"refs/heads/{BASE_BRANCH}",
                        "before": base,
                        "after": custom_title_merge,
                        "forced": False,
                        "created": False,
                        "deleted": False,
                    }
                ),
                encoding="utf-8",
            )
            custom_title_result = verify_bootstrap_push(event_path)
            if custom_title_result.get("pr") != 42 or custom_title_result.get("head") != direct_head:
                raise AssertionError("bootstrap gate lost the PR suffix from a custom GitHub merge title")

            if recover_github_pull_request_number("custom title\n\nBody only reference (#42)") is not None:
                raise AssertionError("bootstrap gate accepted a PR number outside the merge subject")

            tampered_tree_merge = git(
                "commit-tree",
                f"{base}^{{tree}}",
                "-p",
                base,
                "-p",
                direct_head,
                "-m",
                "Merge pull request #42 from example/direct-candidate",
            )
            git("switch", "--quiet", "--detach", tampered_tree_merge)
            event_path.write_text(
                json.dumps(
                    {
                        "ref": f"refs/heads/{BASE_BRANCH}",
                        "before": base,
                        "after": tampered_tree_merge,
                        "forced": False,
                        "created": False,
                        "deleted": False,
                    }
                ),
                encoding="utf-8",
            )
            try:
                verify_bootstrap_push(event_path)
            except TrainError:
                pass
            else:
                raise AssertionError("self-test accepted a direct merge with a tampered tree")

            git("switch", "--quiet", "--detach", base)
            Path("wrong-parent.txt").write_text("wrong parent\n", encoding="utf-8")
            git("add", "wrong-parent.txt")
            git("commit", "--quiet", "-m", "wrong protected parent")
            wrong_parent = git("rev-parse", "HEAD")
            wrong_parent_merge = git(
                "commit-tree",
                f"{direct_head}^{{tree}}",
                "-p",
                wrong_parent,
                "-p",
                direct_head,
                "-m",
                "Merge pull request #42 from example/direct-candidate",
            )
            git("switch", "--quiet", "--detach", wrong_parent_merge)
            event_path.write_text(
                json.dumps(
                    {
                        "ref": f"refs/heads/{BASE_BRANCH}",
                        "before": base,
                        "after": wrong_parent_merge,
                        "forced": False,
                        "created": False,
                        "deleted": False,
                    }
                ),
                encoding="utf-8",
            )
            try:
                verify_bootstrap_push(event_path)
            except TrainError:
                pass
            else:
                raise AssertionError("self-test accepted a direct merge with the wrong first parent")

            git("switch", "--quiet", "--detach", composite)
            Path("unexpected.txt").write_text("must fail closed\n", encoding="utf-8")
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            git("add", "--", str(manifest_path), "unexpected.txt")
            git("commit", "--quiet", "-m", "tampered train")
            tampered = git("rev-parse", "HEAD")
            verify_exact_history(manifest, tampered)
            try:
                verify_exact_tree(manifest, tampered, manifest_path)
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
    prepare_parser.add_argument("--output", type=Path)

    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--repo", default=REPOSITORY)
    publish_parser.add_argument("--branch", required=True)
    publish_parser.add_argument("--issue", type=int, required=True)
    publish_parser.add_argument("--owner", required=True)

    verify_parser = subparsers.add_parser("verify-hosted")
    verify_parser.add_argument("--repo", default=REPOSITORY)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--base", required=True)
    verify_parser.add_argument("--head", required=True)
    verify_parser.add_argument("--branch", required=True)

    manifest_parser = subparsers.add_parser("verify-manifest")
    manifest_parser.add_argument("--manifest", type=Path, required=True)
    discover_parser = subparsers.add_parser("discover-manifest")
    discover_parser.add_argument("--head", required=True)
    discover_parser.add_argument("--branch", required=True)
    bootstrap_parser = subparsers.add_parser("verify-bootstrap-push")
    bootstrap_parser.add_argument("--event", type=Path, required=True)
    subparsers.add_parser("self-test")
    args = parser.parse_args(list(argv))
    try:
        if args.command == "prepare":
            result = prepare(args.repo, args.branch, args.pr, args.output)
            print(json.dumps({**result, "status": "PREPARED"}, sort_keys=True))
            return 0
        if args.command == "publish":
            print(json.dumps(publish(args.repo, args.branch, args.issue, args.owner), sort_keys=True))
            return 0
        if args.command == "verify-hosted":
            print(
                json.dumps(
                    verify_hosted(args.repo, args.manifest, args.base, args.head, args.branch),
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "discover-manifest":
            print(discover_manifest(args.head, args.branch))
            return 0
        if args.command == "verify-bootstrap-push":
            print(json.dumps(verify_bootstrap_push(args.event), sort_keys=True))
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
