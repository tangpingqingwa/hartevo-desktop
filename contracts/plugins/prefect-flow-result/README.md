# Prefect flow-run result plugin contract

This directory owns the standalone Layer-1 contract for Issue #412
(`EXT-PREFECT-01`). It binds one exact Prefect server host, account, workspace,
flow, deployment, flow run, task run, allowlisted state set, and Hartevo
Project/Mission/Work Product revision.

The typed seam is deliberately read-only:

- `PrefectFlowResultService` exposes bounded descriptions, flow-run/task-run/
  state-history evidence, a revision-fenced proposal, and deterministic
  verification.
- `PrefectProvider` exposes only typed reads for flow-run detail, task-run
  projections, state history, and bounded flow-run filters. It does not accept
  arbitrary Prefect filter DSL.
- `MissionPrefectFlowConsumer` checks the exact Mission scope and produces a
  non-adoptable decision record below the Domain Kernel.

`SecretReference` is opaque and API-key-only. It contains only a reference
digest, exact scope digest, credential revision, and revocation state. No API
key, bearer header, raw response, log, or result value is accepted or retained.

Registration binds version, contract, provider, API, server host, account,
workspace, flow, deployment, flow run, task run, state, permission, revision,
scope, and credential digests. It is reversible and revocable. Fixture,
recording, fake, loopback, and `BLOCKED_ENV` transports always report
`connected = false`, `native = false`, and `first_party = false`.

The boundary excludes flow creation, state mutation/cancellation, deployment or
worker mutation, raw logs/results, arbitrary filter DSL, workflow-registry or
kernel authority, and Work Product adoption. Native API-key resolution,
bounded live HTTPS, durable provider receipts, independent read-back, and
verified Work Product adoption remain Layer-2 gaps.

Primary references:

- <https://docs.prefect.io/v3/api-ref/rest-api>
- <https://docs.prefect.io/v3/api-ref/python/prefect-server-api-flow_runs>
- <https://docs.prefect.io/v3/concepts/states>
- <https://docs.prefect.io/v3/api-ref/rest-api/server/flow-runs/flow-run-history>

This provider-specific orchestration seam is distinct from Airflow #404,
Dagster #383, Temporal #297, and Step Functions #305; none of those plugin
roots are modified by this contract.
