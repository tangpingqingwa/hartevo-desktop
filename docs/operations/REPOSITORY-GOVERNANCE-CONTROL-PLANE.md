# Repository governance control plane

This runbook describes the lightweight Cordis mainline. GitHub API facts,
exact Git objects, required checks, and the hash-chained governance ledger are
the source of truth. Chat, task heartbeats, commits, pushes, and local green
runs are not merge evidence.

## Ordinary Cordis flow

Every ordinary `feature` or routine `dependency` change targeting
`bootstrap/macos-r0` follows exactly four plain steps:

1. Open a PR with the minimal `hartevo-governance` admission block: schema, `changeClass`, and `owner`.
2. Run scoped checks: common Rust packages on Ubuntu, desktop packages on macOS, or the locked dependency-only lane; non-Rust paths report honest planned skips.
3. Obtain one independent GitHub review with a strict `hartevo-github-review/v1` marker containing the exact head SHA, `APPROVE` disposition, and a reviewer task ID different from the owner.
4. Directly merge as a normal protected merge commit.

The protected branches require exactly these stable contexts: `PR / Workflow
policy`, `Governance / PR admission`, `PR / Scope plan`, and `PR / Result
taxonomy`. `requiredApprovingReviews` remains zero because there is one GitHub
collaborator; trusted admission enforces the independent exact-head review and
avoids a solo-maintainer ruleset deadlock. Protected refs still require a PR,
current base, resolved conversations, no force push, no deletion, and
merge-commit-only history.

Full Integration runs on a milestone, release, scheduled, or explicit-full
request. It is not repeated on every protected push. A protected push verifies
only a recoverable normal merge record; the full Ubuntu-common,
macOS-desktop, Postgres, contracts, OpenInterpreter, Dioxus, and dependency
matrix runs through `workflow_dispatch` or the weekday schedule.

## Trusted admission and review freshness

`governance-admission.yml` runs from the protected base for both PR updates and
`pull_request_review` events. It fetches the untrusted head as a Git object and
never checks out or executes PR code with privileged authority. The workflow's
required CheckRun and its replaceable exact-head commit status use the same
name, `Governance / PR admission`; GitHub requires both to pass. The workflow
publishes pending before review and before checkout. A valid ordinary PR
therefore stays blocked without showing an expected red failure. A review is
accepted only when its state is `COMMENTED` or `APPROVED`, its API commit ID
equals the current head, its body is exactly one machine-readable marker with
`APPROVE`, and its reviewer task ID differs from the admission owner.
Acceptance updates the status to success; invalid facts update it to failure
while the controller CheckRun succeeds. A later correction can replace that
status, so Rust checks are not rerun merely to clear an old admission failure.
Any code push changes the head and invalidates old records.

The trusted token has `statuses: write` solely for this exact-head commit
status. Contents and pull requests remain read-only. Checkout, review-API,
verifier, or status-API failures fail the same-name required CheckRun, so an
older green status cannot fail open. A maximum observed workflow-run-id fence,
checked before pending and again before the final decision, prevents an older
READY event from overwriting a newer WAITING or INVALID event on the same SHA.
Same-head runs are not cancelled, avoiding cancelled required CheckRuns. The
protected ruleset still requires the same four contexts; neither approval
count nor bypass policy changes.

## High-risk changes

Workflow, policy, governance, ledger, merge-train, security, destructive,
release, and integration-recovery changes cannot be classified as ordinary.
They retain the positive Issue, accountable owner, exact owned paths, concrete
rollback, false external-effect and release claims, and independent
receipt-only review commit. The trusted verifier fails closed when any field,
path envelope, base, head, or receipt-only commit is wrong. A feature PR that
touches a sensitive path is rejected rather than downgraded to a normal lane.

`events.jsonl` is append-only and hash chained. The latest
`GLOBAL_PAUSED`/`GLOBAL_RESUMED` event controls admission; a pause blocks
ordinary classes but preserves deferred recovery actions. Governance-mode
events record the lightweight mode, Cordis mainline, frozen historical PR
waves, and removal of triple validation without rewriting prior lines.

## Optional trains and historical compatibility

Trains are optional and reserved for multi-PR integration, release milestones,
or explicit high-risk combinations. They compose one to four independent root
PRs and run the full Integration matrix once. Ordinary candidates attest the
same exact-head GitHub review used by direct merge; high-risk candidates retain
receipt-only evidence. Already merged manifests remain immutable and continue
to validate their historical receipt fields. No protected branch requires a
`Governance / Train-only merge` context.

The bounded operator path is:

```bash
git switch --detach origin/bootstrap/macos-r0
git switch -c merge-train/YYYYMMDD-HHMM
python3 scripts/ci-merge-train.py prepare \
  --branch merge-train/YYYYMMDD-HHMM --pr 123 --pr 124
python3 scripts/ci-merge-train.py publish \
  --branch merge-train/YYYYMMDD-HHMM \
  --issue <integration-issue> --owner <integration-manager-task>
```

Publication verifies the current base, stable checks, admission, review
evidence, exact history, tree, path overlap, and the single-open-train
invariant. It pushes one normal train branch and opens one non-Draft PR; it
does not merge or bypass protection. The immutable manifest remains history.

## Lifecycle safety

Inventory and lifecycle plans are read-only or dry-run by default. Closing a
PR/Issue or deleting a branch requires a short-lived approval artifact bound to
the exact plan digest, and branch deletion first creates a recovery tag.
Automatic destructive execution remains disabled.

```bash
mkdir -p target/governance
python3 scripts/repository_governance.py snapshot \
  --output target/governance/snapshot.json
python3 scripts/repository_governance.py plan \
  --snapshot target/governance/snapshot.json \
  --output target/governance/plan.json
```

The complete verifier suite is available through `bash scripts/ci-tests.sh`.
