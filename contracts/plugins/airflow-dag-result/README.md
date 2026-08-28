# Airflow DAG-run result plugin contract

This directory owns the standalone Layer-1 contract for Issue #404
(`EXT-AIRFLOW-01`). It binds one exact Airflow host and tenant, DAG, DAG run,
task instance, logical date, commit-or-release reference, and Hartevo
Project/Mission/Work Product revision.

The typed seam is deliberately read-only:

- `AirflowDagResultService` exposes bounded descriptions, DAG-run/task-instance
  evidence, a revision-fenced review proposal, and deterministic verification.
- `AirflowProvider` exposes only allowlisted GET-shaped stable REST reads for a
  DAG run and its task instance. Offset/limit and logical-date bounds are
  validated before a transport is called.
- `MissionAirflowRunConsumer` checks the exact Mission scope and produces a
  non-adoptable decision record below the Domain Kernel.

`SecretReference` is opaque and is not serializable. It contains only a
reference digest, bearer/OIDC kind, exact scope digest, and credential
revision. No bearer, OIDC token, authorization header, cookie, response body,
variable, connection, log, or XCom value is accepted or retained.

Registration is version, contract, provider, API, permission, scope, revision,
and credential bound. It is reversible and revocable, with explicit unmount,
remount, revoke, and reverse transition evidence. Any registration, secret,
Mission revision, logical-date, run-id, task, or provider response drift fails
closed.

The provider reads only the stable REST resources:

- `GET /api/v1/dags/{dag_id}/dagRuns/{dag_run_id}`
- `GET /api/v1/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances`
- `GET /api/v1/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances/{task_id}`

Only bounded allowlisted state and metadata fields are represented. Typed
materialization metadata is a digest-only summary derived from those fields;
it is not XCom or a provider receipt. Fixture, recording, loopback, and
`BLOCKED_ENV` transports always report `connected = false`, `native = false`,
and `firstParty = false`.

This Layer-1 boundary does not trigger a DAG, clear or retry a task, read
variables or connections, read raw logs or XCom, control a scheduler or UI,
resolve a native credential, retain a durable provider receipt, perform
independent read-back, assert Airflow Truth/Effect authority, or adopt a
Mission Work Product. Native bearer/OIDC resolution, bounded live HTTPS,
durable receipts, independent reconciliation, and verified Work Product
adoption remain Layer-2 gaps.

Primary references:

- <https://airflow.apache.org/docs/apache-airflow/stable-rest-api-ref.html>
- <https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/dag-run.html>

This provider-specific orchestration seam is distinct from Dagster #383,
Temporal #297, Modal #372, and Step Functions #305; none of those plugins are
modified by this contract.
