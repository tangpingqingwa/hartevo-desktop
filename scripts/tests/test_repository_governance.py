from __future__ import annotations

import datetime as dt
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/repository_governance.py"
SPEC = importlib.util.spec_from_file_location("repository_governance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
governance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = governance
SPEC.loader.exec_module(governance)


def command(root: Path, *args: str) -> str:
    result = subprocess.run(args, cwd=root, text=True, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


class RepositoryGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = governance.load_policy(ROOT / governance.POLICY_PATH)
        self.events = governance.load_ledger(ROOT / governance.LEDGER_PATH)

    def admission(self, change_class: str = "governance") -> dict[str, object]:
        return {
            "schema": governance.ADMISSION_SCHEMA,
            "changeClass": change_class,
            "issue": 1,
            "owner": "root",
            "ownedPaths": [".github", "scripts/repository_governance.py"],
            "rollback": "Revert the exact commit and rerun every governance verifier.",
            "externalEffects": False,
            "release": False,
        }

    def snapshot(self) -> dict[str, object]:
        return {
            "schema": governance.SNAPSHOT_SCHEMA,
            "repository": governance.REPOSITORY,
            "observedAt": "2026-08-21T01:00:00Z",
            "protected": {"branch": governance.BASE_BRANCH, "sha": "a" * 40},
            "inventory": {
                "openPullRequests": 1,
                "draftPullRequests": 1,
                "nonDraftPullRequests": 0,
                "openIssues": 1,
                "branches": 3,
                "orphanBranches": 1,
                "openTrains": 0,
                "trainReadyPullRequests": 0,
                "oldestTrainReadySeconds": None,
            },
            "pullRequests": [
                {
                    "number": 9,
                    "draft": True,
                    "baseBranch": governance.BASE_BRANCH,
                    "baseSha": "b" * 40,
                    "headSha": "c" * 40,
                    "updatedAt": "2026-07-01T00:00:00Z",
                }
            ],
            "issues": [{"number": 8, "updatedAt": "2026-01-01T00:00:00Z"}],
            "orphanBranches": [{"name": "codex/orphan", "headSha": "d" * 40}],
            "openTrains": [],
            "repositorySettings": {
                "defaultBranch": governance.BASE_BRANCH,
                "deleteBranchOnMerge": False,
                "allowUpdateBranch": False,
                "allowMergeCommit": True,
                "allowSquashMerge": True,
                "allowRebaseMerge": True,
                "allowAutoMerge": False,
            },
        }

    def test_checked_in_policy_and_ledger_are_valid_and_paused(self) -> None:
        self.assertEqual(governance.verify_policy_value(self.policy)["status"], "PASS")
        self.assertTrue(governance.global_paused(self.events))

    def test_repository_lifecycle_settings_prefer_complete_rest_truth(self) -> None:
        repository = {
            "default_branch": governance.BASE_BRANCH,
            "delete_branch_on_merge": True,
            "allow_update_branch": True,
            "allow_merge_commit": True,
            "allow_squash_merge": False,
            "allow_rebase_merge": False,
            "allow_auto_merge": False,
        }
        with mock.patch.object(governance, "gh_json", return_value=repository) as github:
            observed, source = governance.hosted_repository(governance.REPOSITORY)
        self.assertEqual(source, "REST")
        self.assertEqual(observed, repository)
        github.assert_called_once_with("api", f"repos/{governance.REPOSITORY}")

    def test_repository_lifecycle_settings_fall_back_to_graphql(self) -> None:
        repository = {
            "default_branch": governance.BASE_BRANCH,
            **{field: None for field in governance.REPOSITORY_LIFECYCLE_FIELDS},
        }
        graph_values = {
            "deleteBranchOnMerge": True,
            "allowUpdateBranch": True,
            "mergeCommitAllowed": True,
            "squashMergeAllowed": False,
            "rebaseMergeAllowed": False,
            "autoMergeAllowed": False,
        }
        graph = {"data": {"repository": graph_values}}
        with mock.patch.object(governance, "gh_json", side_effect=[repository, graph]) as github:
            observed, source = governance.hosted_repository(governance.REPOSITORY)
        self.assertEqual(source, "GRAPHQL_READ_FALLBACK")
        for rest_field, graph_field in governance.REPOSITORY_LIFECYCLE_FIELDS.items():
            self.assertEqual(observed[rest_field], graph_values[graph_field])
        self.assertEqual(github.call_count, 2)
        self.assertEqual(github.call_args_list[1].args, ("api", "graphql"))
        self.assertEqual(
            github.call_args_list[1].kwargs["input_value"]["variables"],
            {"owner": "tangpingqingwa", "name": "hartevo-desktop"},
        )

    def test_repository_lifecycle_settings_fail_closed_when_graphql_is_incomplete(self) -> None:
        repository = {
            "default_branch": governance.BASE_BRANCH,
            **{field: None for field in governance.REPOSITORY_LIFECYCLE_FIELDS},
        }
        graph = {"data": {"repository": {"deleteBranchOnMerge": True}}}
        with mock.patch.object(governance, "gh_json", side_effect=[repository, graph]):
            with self.assertRaisesRegex(governance.GovernanceError, "allow_update_branch is unavailable"):
                governance.hosted_repository(governance.REPOSITORY)

    def test_pause_blocks_feature_and_preserves_governance_recovery(self) -> None:
        accepted = governance.verify_admission_value(
            self.admission(),
            changed=[".github/policies/test.json"],
            paused=True,
            policy=self.policy,
        )
        self.assertEqual(accepted["mode"], "PAUSED")
        with self.assertRaises(governance.GovernanceError):
            governance.verify_admission_value(
                self.admission("feature"),
                changed=[".github/policies/test.json"],
                paused=True,
                policy=self.policy,
            )

    def test_exact_path_lease_rejects_outside_change(self) -> None:
        value = self.admission()
        value["ownedPaths"] = ["scripts"]
        with self.assertRaises(governance.GovernanceError):
            governance.verify_admission_value(
                value,
                changed=[".github/workflows/ci.yml"],
                paused=True,
                policy=self.policy,
            )

    def test_paused_plan_has_no_executable_actions_but_keeps_deferred_work(self) -> None:
        plan = governance.build_plan(
            self.snapshot(),
            self.events,
            self.policy,
            dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(plan["mode"], "PAUSED")
        self.assertEqual(plan["actions"], [])
        self.assertTrue(plan["deferredActions"])
        self.assertIn("REPOSITORY_SETTING_DRIFT", {item["code"] for item in plan["incidents"]})

    def test_paused_plan_cannot_be_approved(self) -> None:
        plan = governance.build_plan(
            self.snapshot(),
            self.events,
            self.policy,
            dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(governance.GovernanceError):
                governance.create_approval(
                    plan,
                    "root",
                    Path(directory) / "approval.json",
                    dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
                )

    def test_unpaused_train_ready_sla_breach_is_an_incident(self) -> None:
        snapshot = self.snapshot()
        snapshot["inventory"]["trainReadyPullRequests"] = 1
        snapshot["inventory"]["oldestTrainReadySeconds"] = 121
        resumed = governance.seal_event(
            {
                "kind": "GLOBAL_RESUMED",
                "actorTaskId": "governance-owner",
                "payload": {"reason": "test exact drain-mode integration"},
            },
            str(self.events[-1]["digest"]),
        )
        plan = governance.build_plan(
            snapshot,
            [*self.events, resumed],
            self.policy,
            dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(plan["mode"], "DRAIN")
        self.assertIn("READY_TO_TRAIN_SLA_BREACH", {item["code"] for item in plan["incidents"]})
        self.assertEqual(plan["truth"]["metrics"]["ready_count"], 1)

    def test_lifecycle_nominations_are_exact_and_suppressed_while_paused(self) -> None:
        nominations = {
            "schema": governance.NOMINATION_SCHEMA,
            "repository": governance.REPOSITORY,
            "requestedBy": "root",
            "items": [
                {
                    "kind": "DELETE_BRANCH",
                    "branch": "codex/orphan",
                    "reason": "The branch has no open pull request and needs explicit inventory cleanup.",
                }
            ],
        }
        plan = governance.build_lifecycle_plan(
            self.snapshot(),
            nominations,
            self.events,
            self.policy,
            dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["deferredActions"][0]["kind"], "DELETE_BRANCH")
        self.assertTrue(plan["deferredActions"][0]["recoveryRef"].startswith("refs/tags/governance-recovery/"))

    def test_lifecycle_nomination_rejects_non_orphan_branch(self) -> None:
        nominations = {
            "schema": governance.NOMINATION_SCHEMA,
            "repository": governance.REPOSITORY,
            "requestedBy": "root",
            "items": [
                {
                    "kind": "DELETE_BRANCH",
                    "branch": governance.BASE_BRANCH,
                    "reason": "This deliberately unsafe test target must be rejected by governance.",
                }
            ],
        }
        with self.assertRaises(governance.GovernanceError):
            governance.build_lifecycle_plan(
                self.snapshot(),
                nominations,
                self.events,
                self.policy,
                dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
            )

    def test_exact_review_receipt_requires_a_receipt_only_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command(root, "git", "init", "--quiet")
            command(root, "git", "config", "user.name", "Governance Test")
            command(root, "git", "config", "user.email", "governance@example.invalid")
            (root / "base.txt").write_text("base\n", encoding="utf-8")
            command(root, "git", "add", "base.txt")
            command(root, "git", "commit", "--quiet", "-m", "base")
            base = command(root, "git", "rev-parse", "HEAD")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            command(root, "git", "add", "feature.txt")
            command(root, "git", "commit", "--quiet", "-m", "feature")
            reviewed = command(root, "git", "rev-parse", "HEAD")
            output = root / governance.review_path(7)
            governance.create_review_receipt(root, 7, base, reviewed, "author", "reviewer", output)
            command(root, "git", "add", output.relative_to(root).as_posix())
            command(root, "git", "commit", "--quiet", "-m", "review receipt")
            head = command(root, "git", "rev-parse", "HEAD")
            result = governance.verify_review_commit(root, 7, base, head)
            self.assertEqual(result["reviewedHeadSha"], reviewed)
            self.assertEqual(result["exactPaths"], ["feature.txt"])

    def test_trusted_base_admission_never_checks_out_untrusted_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command(root, "git", "init", "--quiet")
            command(root, "git", "config", "user.name", "Governance Test")
            command(root, "git", "config", "user.email", "governance@example.invalid")
            policy_path = root / governance.POLICY_PATH
            ledger_path = root / governance.LEDGER_PATH
            policy_path.parent.mkdir(parents=True)
            ledger_path.parent.mkdir(parents=True)
            policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
            ledger_path.write_text(
                "\n".join(json.dumps(event, sort_keys=True, separators=(",", ":")) for event in self.events) + "\n",
                encoding="utf-8",
            )
            (root / "base.txt").write_text("base\n", encoding="utf-8")
            command(root, "git", "add", ".github", "base.txt")
            command(root, "git", "commit", "--quiet", "-m", "base")
            base = command(root, "git", "rev-parse", "HEAD")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            command(root, "git", "add", "feature.txt")
            command(root, "git", "commit", "--quiet", "-m", "feature")
            head = command(root, "git", "rev-parse", "HEAD")
            command(root, "git", "switch", "--quiet", "--detach", base)
            event = {
                "pull_request": {
                    "number": 7,
                    "body": (
                        "<!-- hartevo-governance\n"
                        + json.dumps(
                            {
                                "schema": governance.ADMISSION_SCHEMA,
                                "changeClass": "governance",
                                "issue": 1,
                                "owner": "root",
                                "ownedPaths": ["feature.txt"],
                                "rollback": "Revert this exact fixture change.",
                                "externalEffects": False,
                                "release": False,
                            }
                        )
                        + "\n-->"
                    ),
                    "base": {"ref": governance.BASE_BRANCH, "sha": base},
                    "head": {"ref": "codex/governance-fixture", "sha": head},
                }
            }
            event_path = root / "event.json"
            event_path.write_text(json.dumps(event), encoding="utf-8")
            result = governance.verify_pr_event(
                root,
                event_path,
                "pull_request",
                trusted_base=True,
            )
            self.assertEqual(result["headSha"], head)
            self.assertEqual(command(root, "git", "rev-parse", "HEAD"), base)

    def test_review_receipt_rejects_author_reviewer_reuse(self) -> None:
        value = {
            "schema": governance.REVIEW_SCHEMA,
            "repository": governance.REPOSITORY,
            "pr": 1,
            "baseSha": "a" * 40,
            "reviewedHeadSha": "b" * 40,
            "authorTaskId": "same",
            "reviewerTaskId": "same",
            "disposition": "APPROVE",
            "syntheticPreflightGreen": True,
            "reviewedAt": "2026-08-21T00:00:00Z",
            "exactPaths": ["file"],
        }
        value["receiptDigest"] = governance.digest(value)
        with self.assertRaises(governance.GovernanceError):
            governance.validate_review_value(value)

    def test_ledger_digest_detects_payload_tamper(self) -> None:
        event = dict(self.events[0])
        event["payload"] = {"reason": "forged"}
        unsigned = dict(event)
        unsigned.pop("digest")
        self.assertNotEqual(governance.digest(unsigned), event["digest"])


if __name__ == "__main__":
    unittest.main()
