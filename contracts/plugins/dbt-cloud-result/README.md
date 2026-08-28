# dbt Cloud transformation-result plugin contract

This directory owns the standalone Layer-1 contract for Issue #353
(EXT-DBT-01).

Layer 1 exposes three typed seams:

- DbtCloudResultService composes the exact account/project/environment/job,
  repository/commit, model/test selectors, artifact allowlist, and
  Project/Mission/Work Product revisions.
- DbtCloudProvider performs bounded, read-only job/run/results/metadata reads
  through a typed transport. It has no trigger, cancel, retry, SQL, or
  credential mutation operation.
- MissionDbtResultConsumer validates a proposal against the exact Mission
  scope and records an in-memory consumption/replay decision. It does not
  mutate a Domain Kernel Outcome.

SecretReference is opaque and cannot be serialized. Registrations are
version-, digest-, and scope-bound; unmount is reversible and revoke is
terminal. Payloads are typed, paginated, digest-checked, truncated/size
bounded, and artifact-body-free. Fixture, fake, recording, loopback, and
BLOCKED_ENV evidence always reports connected=false and native=false.

The standalone crate is at
hartevo-rs/dbt-cloud-result-plugin/. Its Layer-1 receipt is an explicitly
non-durable recording. Native token resolution, bounded HTTPS transport,
consented live effects, durable native receipts, independent artifact
read-back, and verified Work Product adoption remain Layer-2 gaps.

Primary references:

- https://docs.getdbt.com/dbt-cloud/api-v3
- https://docs.getdbt.com/dbt-cloud/api-v2
- https://docs.getdbt.com/reference/artifacts/dbt-artifacts
- https://dbt.rest/
