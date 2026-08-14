# Dagster run-result plugin contract

This directory owns the standalone Layer-1 contract for Issue #383
(`EXT-DAGSTER-01`). It binds one Dagster deployment, repository, code location,
job, run, optional partition, asset, repository commit, and exact Hartevo
Project/Mission/Work Product revisions.

The typed seam is intentionally narrow:

- `DagsterRunResultService` exposes deployment/repository/code-location/job/
  asset descriptions, bounded run evidence, a review-only proposal, an
  in-memory recording, and digest verification.
- `DagsterProvider` exposes only typed GraphQL read operations. Cursor pages,
  response bytes, event counts, materialization metadata, and data-version
  digests are bounded and verified before projection.
- `MissionDagsterRunConsumer` checks the exact Mission scope and records a
  replay-safe proposal decision below the Domain Kernel. It does not adopt a
  Kernel Outcome.

`SecretReference` is opaque. A deployment token or API secret is never accepted
as a payload, serialized, logged, or included in a digest; only its reference
digest, kind, and credential revision are recordable. Registration is version,
contract, provider, permission, credential, and scope bound, and supports
reversible unmount/remount plus terminal revoke/reverse evidence.

Only recording, fake, loopback, and `BLOCKED_ENV` transports are included. They
always report `connected = false`, `native = false`, and `firstParty = false`.
They retain no raw GraphQL response, run config, log, secret, or artifact body.

The Layer-1 boundary does not launch, re-execute, terminate, mutate assets,
control schedules/sensors, select arbitrary operations, retain unbounded event
streams, resolve native credentials, persist a provider receipt, or adopt a
Mission Work Product/Outcome. Native token resolution, bounded HTTPS reads,
durable receipts, independent run/materialization reconciliation, and verified
Work Product adoption remain Layer-2 gaps.

Primary references:

- <https://docs.dagster.io/api/graphql>
- <https://release-1-5-9.dagster.dagster-docs.io/concepts/webserver/graphql>
- <https://docs.dagster.io/concepts/dagster-software-defined-assets>
