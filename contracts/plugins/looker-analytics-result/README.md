# Looker Analytics Result — Layer 1

This directory defines the standalone `EXT-LOOKER-01` Layer-1 contract. The
Rust crate is intentionally outside the root Cargo workspace so it can be
reviewed and tested as an isolated provider seam.

The contract is pinned to the official [Looker API reference](https://docs.cloud.google.com/looker/docs/reference/looker-api/latest),
currently using the read-only metadata methods for dashboards, looks, folders,
queries, LookML models/explores, and bounded dashboard/look/content search.

Layer 1 returns redacted, bounded metadata aggregates only. It does not return
warehouse rows, query results, SQL, filter expressions, dashboard element
bodies, user identifiers, descriptions, URLs, client secrets, or native
provider receipts. It has no dashboard mutation, query execution, SQL Runner,
render task, scheduling, causal, business-success, or Outcome authority. Query
and search text plus pagination cursors are opaque digest bindings only.

The crate's fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are
deterministic test seams. Every transport reports `connected = false`,
`native = false`, and `first_party = false`; native HTTPS and credential
resolution remain Layer-2 work.
