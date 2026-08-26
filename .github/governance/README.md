# Repository governance control plane

This directory contains durable coordination evidence. Chat messages, task
heartbeats, commits, pushes, and local green tests are not repository truth.

The closed loop is:

1. live GitHub/Git snapshot;
2. policy-bound PR admission;
3. exact non-author task review receipt;
4. required hosted checks on the receipt commit;
5. one bounded, non-overlapping repository merge train;
6. normal protected PR merge;
7. protected-base advance invalidates every old tuple automatically;
8. inventory is projected again from live facts.

`events.jsonl` is append-only and hash chained. The newest
`GLOBAL_PAUSED`/`GLOBAL_RESUMED` event controls admission. A pause suppresses
execution but preserves deferred actions, so no later chat receipt can
silently resume work.

Positive review evidence lives in `reviews/pr-<number>.json`. It is added by a
dedicated receipt-only commit whose parent is the exact reviewed code head.
The merge-train verifier rejects author/reviewer task reuse, base/head drift,
path drift, extra receipt-commit changes, missing checks, stacked candidates,
and overlapping ownership.

Trusted admission runs from the protected branch through
`governance-admission.yml`. Its train-only required check blocks direct
candidate merges; untrusted PR code cannot relax that check. The scheduled
inventory computes exact train readiness every five minutes and surfaces an
unserved 120-second Ready-to-train SLA as an incident.

Lifecycle plans are always dry-run by default. Closing issues or pull
requests, or deleting branches, additionally requires a short-lived approval
artifact bound to the exact plan digest. The checked-in policy disables
automatic destructive execution.

The complete activation and operating procedure is in
`docs/operations/REPOSITORY-GOVERNANCE-CONTROL-PLANE.md`.
