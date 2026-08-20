# Google Cloud Bigtable table result Layer 1

This standalone contract is a bounded, read-only table-posture seam below
Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, and Work
Product authority. It binds one exact `project/instance/table` scope and
allows only the documented Bigtable Admin `tables.get` and `clusters.get`
reads.

The result contains digest-only database, table, schema, family, and cluster
posture projections. It never retains rows, cells, raw values, raw provider
payloads, credentials, or PII. Unexpected pagination, truncation, duplicate
cluster entries, stale fences, and digest mismatches fail closed.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`; local recordings
are not durable provider receipts.

## Layer-2 gaps

Native OAuth/service-account resolution and live HTTPS; durable provider
receipts; independent readback and permission/consent adoption; row/cell
evidence; schema mutation; backup/restore; IAM mutation; and kernel
Truth/Consent/Effect/Receipt/Verification/Outcome authority remain Layer-2
work.

## Official API basis

- <https://docs.cloud.google.com/bigtable/docs/reference/admin/rest/v2/projects.instances.tables/get>
- <https://docs.cloud.google.com/bigtable/docs/reference/admin/rest/v2/projects.instances.clusters/get>
