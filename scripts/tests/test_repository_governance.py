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
        self.paused_events = self.events[:1]

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

    def test_checked_in_policy_and_ledger_are_valid_resumed_and_normal(self) -> None:
        self.assertEqual(governance.verify_policy_value(self.policy)["status"], "PASS")
        self.assertEqual(self.policy["admissionModeWhenUnpaused"], "normal")
        latest_transition = next(
            event for event in reversed(self.events) if event["kind"] in {"GLOBAL_PAUSED", "GLOBAL_RESUMED"}
        )
        self.assertEqual(latest_transition["kind"], "GLOBAL_RESUMED")
        self.assertFalse(governance.global_paused(self.events))
        self.assertTrue(governance.global_paused(self.paused_events))
        self.assertEqual(
            self.policy["admissionStatus"],
            {
                "context": "Governance / PR admission",
                "controllerJob": "Governance / PR admission",
                "gate": "required-check-and-commit-status",
                "latestRunFence": "highest-actions-run-id-after-older-drain",
                "mutation": "exact-head-commit-status-only",
                "beforeExactReview": "pending",
                "validExactReview": "success",
                "invalidAdmission": "failure",
            },
        )

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

    def test_normal_mode_admits_minimal_feature_and_rejects_sensitive_paths(self) -> None:
        minimal = {
            "schema": governance.ADMISSION_SCHEMA,
            "changeClass": "feature",
            "owner": "root",
        }
        accepted = governance.verify_admission_value(
            minimal,
            changed=["src/feature.rs"],
            paused=False,
            policy=self.policy,
        )
        self.assertEqual(accepted["mode"], "NORMAL")
        self.assertTrue(accepted["directMerge"])
        self.assertNotIn("issue", accepted)
        with self.assertRaises(governance.GovernanceError):
            governance.verify_admission_value(
                minimal,
                changed=[".github/policies/test.json"],
                paused=False,
                policy=self.policy,
            )

    def test_dependency_admission_is_narrow_and_lightweight(self) -> None:
        minimal = {
            "schema": governance.ADMISSION_SCHEMA,
            "changeClass": "dependency",
            "owner": "root",
        }
        accepted = governance.verify_admission_value(
            minimal,
            changed=["Cargo.lock"],
            paused=False,
            policy=self.policy,
        )
        self.assertTrue(accepted["directMerge"])
        with self.assertRaises(governance.GovernanceError):
            governance.verify_admission_value(
                minimal,
                changed=["src/feature.rs"],
                paused=False,
                policy=self.policy,
            )

    def test_github_review_is_exact_head_and_task_independent(self) -> None:
        head = "a" * 40
        marker = (
            "<!-- hartevo-github-review\n"
            + json.dumps(
                {
                    "schema": governance.GITHUB_REVIEW_SCHEMA,
                    "headSha": head,
                    "disposition": "APPROVE",
                    "reviewerTaskId": "reviewer",
                }
            )
            + "\n-->"
        )
        valid = governance.validate_github_review_records(
            [{"state": "COMMENTED", "commit_id": head, "body": marker}],
            head_sha=head,
            owner="author",
        )
        self.assertEqual(valid["reviewerTaskId"], "reviewer")
        for stale in (
            {"state": "COMMENTED", "commit_id": "b" * 40, "body": marker},
            {
                "state": "COMMENTED",
                "commit_id": head,
                "body": marker.replace('"reviewerTaskId": "reviewer"', '"reviewerTaskId": "author"'),
            },
            {"state": "COMMENTED", "commit_id": head, "body": marker + "\nextra"},
        ):
            with self.assertRaises(governance.GovernanceError):
                governance.validate_github_review_records([stale], head_sha=head, owner="author")

        actor = {"login": "reviewer-account"}
        with self.assertRaisesRegex(governance.GovernanceError, "latest exact-head GitHub review requests changes"):
            governance.validate_github_review_records(
                [
                    {
                        "id": 1,
                        "submitted_at": "2026-08-29T00:00:00Z",
                        "user": actor,
                        "state": "COMMENTED",
                        "commit_id": head,
                        "body": marker,
                    },
                    {
                        "id": 2,
                        "submitted_at": "2026-08-29T00:01:00Z",
                        "user": actor,
                        "state": "CHANGES_REQUESTED",
                        "commit_id": head,
                        "body": "The exact head needs changes.",
                    },
                ],
                head_sha=head,
                owner="author",
            )

        restored = governance.validate_github_review_records(
            [
                {
                    "id": 1,
                    "submitted_at": "2026-08-29T00:00:00Z",
                    "user": actor,
                    "state": "CHANGES_REQUESTED",
                    "commit_id": head,
                    "body": "The exact head needs changes.",
                },
                {
                    "id": 2,
                    "submitted_at": "2026-08-29T00:01:00Z",
                    "user": actor,
                    "state": "COMMENTED",
                    "commit_id": head,
                    "body": marker,
                },
            ],
            head_sha=head,
            owner="author",
        )
        self.assertEqual(restored["reviewerTaskId"], "reviewer")

        with self.assertRaises(governance.AwaitingIndependentReview):
            governance.validate_github_review_records([], head_sha=head, owner="author")

    def test_admission_classification_is_pending_before_review_and_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps({"action": "opened"}), encoding="utf-8")
            waiting = governance.AwaitingIndependentReview("no current exact-head review")
            with mock.patch.object(governance, "verify_pr_event", side_effect=waiting):
                result = governance.classify_pr_event(ROOT, event_path, "pull_request")
            self.assertEqual(result["status"], "WAITING_REVIEW")
            self.assertEqual(result["commitStatus"], "pending")

            event_path.write_text(json.dumps({"action": "submitted"}), encoding="utf-8")
            with mock.patch.object(governance, "verify_pr_event", side_effect=waiting):
                result = governance.classify_pr_event(ROOT, event_path, "pull_request_review")
            self.assertEqual(result["status"], "INVALID")
            self.assertEqual(result["commitStatus"], "failure")

            with mock.patch.object(governance, "verify_pr_event", return_value={"status": "PASS"}):
                result = governance.classify_pr_event(ROOT, event_path, "pull_request_review")
            self.assertEqual(result["status"], "READY")
            self.assertEqual(result["commitStatus"], "success")

            with mock.patch.object(
                governance,
                "verify_pr_event",
                side_effect=governance.GovernanceError("invalid admission metadata"),
            ):
                result = governance.classify_pr_event(ROOT, event_path, "pull_request")
            self.assertEqual(result["status"], "INVALID")
            self.assertEqual(result["commitStatus"], "failure")

    def test_same_name_check_and_status_gate_fails_closed_on_status_api_failure(self) -> None:
        # Production-equivalent regression: this SHA was READY, a review/body
        # event invalidated it, and the new pending status write failed.  The
        # old commit status is still green, but the required controller
        # CheckRun is failed, so the same-name dual gate cannot merge.
        self.assertEqual(governance.admission_merge_gate("failure", "success"), "BLOCKED")
        self.assertEqual(governance.admission_merge_gate("success", "pending"), "BLOCKED")
        self.assertEqual(governance.admission_merge_gate("success", "failure"), "BLOCKED")
        self.assertEqual(governance.admission_merge_gate("success", "success"), "READY")

    def test_newer_invalid_run_reconciles_after_older_ready_fence_to_post_race(self) -> None:
        head = "a" * 40

        # A passed its final fence before B existed. Once B starts, B must not
        # publish until A has posted and completed.
        a_alone = governance.admission_run_order(
            {
                "total_count": 1,
                "workflow_runs": [{"id": 10, "head_sha": head, "status": "in_progress"}],
            },
            head_sha=head,
            run_id=10,
        )
        self.assertTrue(a_alone["current"])
        self.assertEqual(a_alone["olderActiveRunIds"], [])

        b_waits = governance.admission_run_order(
            {
                "total_count": 2,
                "workflow_runs": [
                    {"id": 12, "head_sha": head, "status": "in_progress"},
                    {"id": 10, "head_sha": head, "status": "in_progress"},
                ],
            },
            head_sha=head,
            run_id=12,
        )
        self.assertEqual(b_waits["olderActiveRunIds"], [10])

        # A may now land its stale success, but B observes A completed and is
        # necessarily the later final writer; B's INVALID failure is final.
        b_last = governance.admission_run_order(
            {
                "total_count": 2,
                "workflow_runs": [
                    {"id": 12, "head_sha": head, "status": "in_progress"},
                    {"id": 10, "head_sha": head, "status": "completed"},
                ],
            },
            head_sha=head,
            run_id=12,
        )
        self.assertTrue(b_last["current"])
        self.assertEqual(b_last["olderActiveRunIds"], [])
        self.assertEqual(governance.admission_merge_gate("success", "failure"), "BLOCKED")

        a_after_b_exists = governance.admission_run_order(
            {
                "total_count": 2,
                "workflow_runs": [
                    {"id": 12, "head_sha": head, "status": "in_progress"},
                    {"id": 10, "head_sha": head, "status": "in_progress"},
                ],
            },
            head_sha=head,
            run_id=10,
        )
        self.assertFalse(a_after_b_exists["current"])

    def test_admission_run_order_fails_closed_on_partial_or_unlisted_truth(self) -> None:
        head = "a" * 40
        with self.assertRaises(governance.GovernanceError):
            governance.admission_run_order(
                {
                    "total_count": 101,
                    "workflow_runs": [{"id": 12, "head_sha": head, "status": "in_progress"}],
                },
                head_sha=head,
                run_id=12,
            )
        with self.assertRaises(governance.GovernanceError):
            governance.admission_run_order(
                {
                    "total_count": 1,
                    "workflow_runs": [{"id": 10, "head_sha": head, "status": "completed"}],
                },
                head_sha=head,
                run_id=12,
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

    def test_release_and_destructive_classes_stay_on_high_risk_admission(self) -> None:
        for change_class in ("release", "destructive", "security"):
            accepted = governance.verify_admission_value(
                self.admission(change_class),
                changed=[".github/policies/test.json"],
                paused=False,
                policy=self.policy,
            )
            self.assertFalse(accepted["ordinary"])
            self.assertFalse(accepted["directMerge"])

    def test_paused_plan_has_no_executable_actions_but_keeps_deferred_work(self) -> None:
        plan = governance.build_plan(
            self.snapshot(),
            self.paused_events,
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
            self.paused_events,
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

    def test_normal_train_ready_sla_breach_is_an_incident(self) -> None:
        snapshot = self.snapshot()
        snapshot["inventory"]["trainReadyPullRequests"] = 1
        snapshot["inventory"]["oldestTrainReadySeconds"] = 121
        plan = governance.build_plan(
            snapshot,
            self.events,
            self.policy,
            dt.datetime(2026, 8, 21, 2, 0, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(plan["mode"], "NORMAL")
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
            self.paused_events,
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
                self.paused_events,
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
                "action": "opened",
                "pull_request": {
                    "number": 7,
                    "body": (
                        "<!-- hartevo-governance\n"
                        + json.dumps(
                            {
                                "schema": governance.ADMISSION_SCHEMA,
                                "changeClass": "feature",
                                "owner": "root",
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
            waiting = governance.classify_pr_event(
                root,
                event_path,
                "pull_request",
                trusted_base=True,
                github_reviews=[],
            )
            self.assertEqual(waiting["status"], "WAITING_REVIEW")
            self.assertEqual(waiting["commitStatus"], "pending")
            self.assertEqual(command(root, "git", "rev-parse", "HEAD"), base)
            result = governance.verify_pr_event(
                root,
                event_path,
                "pull_request",
                trusted_base=True,
                github_reviews=[
                    {
                        "state": "COMMENTED",
                        "commit_id": head,
                        "body": (
                            "<!-- hartevo-github-review\n"
                            + json.dumps(
                                {
                                    "schema": governance.GITHUB_REVIEW_SCHEMA,
                                    "headSha": head,
                                    "disposition": "APPROVE",
                                    "reviewerTaskId": "independent-reviewer",
                                }
                            )
                            + "\n-->"
                        ),
                    }
                ],
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

    def test_ledger_append_only_rejects_recomputed_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command(root, "git", "init", "--quiet")
            command(root, "git", "config", "user.name", "Governance Test")
            command(root, "git", "config", "user.email", "governance@example.invalid")
            ledger = root / governance.LEDGER_PATH
            ledger.parent.mkdir(parents=True)
            ledger.write_text(
                "\n".join(json.dumps(event, sort_keys=True, separators=(",", ":")) for event in self.events) + "\n",
                encoding="utf-8",
            )
            command(root, "git", "add", governance.LEDGER_PATH.as_posix())
            command(root, "git", "commit", "--quiet", "-m", "base ledger")
            base = command(root, "git", "rev-parse", "HEAD")

            rewritten: list[dict[str, object]] = []
            previous = governance.ZERO_DIGEST
            for index, source in enumerate(self.events):
                raw = dict(source)
                raw.pop("digest", None)
                raw.pop("previousDigest", None)
                if index == 0:
                    raw["payload"] = {"reason": "rewritten historical fact"}
                sealed = governance.seal_event(raw, previous)
                rewritten.append(sealed)
                previous = str(sealed["digest"])
            ledger.write_text(
                "\n".join(json.dumps(event, sort_keys=True, separators=(",", ":")) for event in rewritten) + "\n",
                encoding="utf-8",
            )
            command(root, "git", "add", governance.LEDGER_PATH.as_posix())
            command(root, "git", "commit", "--quiet", "-m", "rewrite self-consistent ledger")
            rewritten_head = command(root, "git", "rev-parse", "HEAD")
            with self.assertRaisesRegex(governance.GovernanceError, "rewrites the protected-base byte prefix"):
                governance.verify_ledger_append_only(root, base, rewritten_head)

            command(root, "git", "switch", "--quiet", "--detach", base)
            appended = governance.seal_event(
                {
                    "kind": "GOVERNANCE_MODE_CHANGED",
                    "actorTaskId": "append-only-test",
                    "payload": {"mainline": "Cordis"},
                },
                str(self.events[-1]["digest"]),
            )
            with ledger.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(appended, sort_keys=True, separators=(",", ":")) + "\n")
            command(root, "git", "add", governance.LEDGER_PATH.as_posix())
            command(root, "git", "commit", "--quiet", "-m", "append ledger event")
            appended_head = command(root, "git", "rev-parse", "HEAD")
            events = governance.verify_ledger_append_only(root, base, appended_head)
            self.assertEqual(events[-1]["eventId"], appended["eventId"])


if __name__ == "__main__":
    unittest.main()
