# Repository governance control plane

This directory contains durable coordination evidence. GitHub state, exact
Git objects, required checks, and the append-only ledger are the source of
truth; chat, task heartbeats, local commits, and local green runs are not.

## Cordis mainline and ordinary flow

Cordis is the absolute mainline. Historical PR waves are frozen, and the old
triple-validation requirement has been removed. An ordinary `feature` or
routine `dependency` PR uses the following four plain steps:

1. Open a PR against `bootstrap/macos-r0` with one minimal admission block containing `changeClass` and `owner`.
2. Run the scoped checks for the changed lane: common Rust on Ubuntu, desktop Rust on macOS, or the dependency-only lane.
3. Obtain one independent GitHub review whose strict `hartevo-github-review` marker names the exact head SHA, says `APPROVE`, and uses a reviewer task ID different from the owner.
4. Directly merge the PR as a normal protected merge commit.

Full Integration is a milestone, release, scheduled, or explicit-full run. It
is not repeated for every ordinary protected push. Trains remain optional for
multi-PR integration, release, or an explicitly high-risk combination.

The trusted `pull_request_target` admission workflow checks out only the
protected base, fetches the event head as an object, and reads review records
without executing PR code. Its required CheckRun and replaceable exact-head
commit status deliberately share the name `Governance / PR admission`; both
must pass. The status is pending before review, success only after a valid
exact-head review, and failure for invalid governance facts. Waiting and
correctable invalid facts therefore do not create a sticky failed CheckRun,
while a checkout, verifier, or status-API failure still fails the required
CheckRun and cannot reuse an older green status. A maximum-run-id fence stops
an older READY event from overwriting a newer WAITING or INVALID decision.
The token may write statuses only; repository contents and pull requests remain
read-only. A code push changes the exact head and therefore invalidates older
GitHub review records. `requiredApprovingReviews` is zero on both protected
branches because this repository has one GitHub collaborator; the admission
verifier enforces task-independent exact-head review without a ruleset
deadlock.

## High-risk governance

Governance, workflow, policy, ledger, security, destructive, release, and
integration-recovery changes are never classified as ordinary work. They still
require a positive Issue, one accountable owner, exact owned paths, concrete
rollback, false external-effect and release claims, and an independent
receipt-only review commit. The verifier fails closed when any of those facts
or the exact base/head tuple is missing. Ordinary classes cannot claim a
sensitive path, even if a legacy body includes heavyweight fields.

`events.jsonl` is append-only and hash chained. The newest
`GLOBAL_PAUSED`/`GLOBAL_RESUMED` event controls admission; a pause suppresses
ordinary work while preserving deferred recovery actions. Governance-mode
events record the lightweight Cordis mainline transition without rewriting
history.

## Optional merge trains

`ci-merge-train.py` can compose one to four independent root PRs for a
multi-PR integration or release milestone. New ordinary candidates carry the
exact-head GitHub review evidence; high-risk candidates retain receipt-only
evidence. Already merged manifests remain immutable and continue to validate
their historical receipt fields. A train is not a prerequisite for an
ordinary Cordis PR and there is no `Governance / Train-only merge` required
context.

The complete activation and operating procedure is in
`docs/operations/REPOSITORY-GOVERNANCE-CONTROL-PLANE.md`.
