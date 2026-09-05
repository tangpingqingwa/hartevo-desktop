# Pendo product-usage result contract

This Layer-1 contract is a bounded, aggregate-only evidence and proposal seam
for Pendo page, feature, and guide adoption metrics. It is deliberately not a
visitor export, PII store, event stream, guide/segment mutation API, dashboard,
causal inference engine, product Truth authority, or Outcome authority.

The typed Rust implementation is a standalone nested workspace at
`hartevo-rs/pendo-product-usage-result-plugin`. It exposes a
`PendoProductUsageResultService`, `PendoProvider`, and
`MissionPendoUsageConsumer` without depending on Hartevo application, desktop,
domain, storage, connector, or provider crates.

The only Layer-1 transports are fixture, recording, loopback, and
`BLOCKED_ENV`. The provider builds safe allowlisted request projections for
the Pendo Aggregation API (`POST /api/v1/aggregation`) and report metadata
reads (`GET /api/v1/page`, `/api/v1/feature`, and `/api/v1/guide`), but no
transport in this crate resolves credentials or performs native HTTPS.

Account, segment, page, feature, guide, and integration-key references are
hashed at construction. `SecretReference` is opaque, redacted in `Debug`, and
fails serialization. Responses retain bounded counts/rates and digests only;
raw visitor rows, identifiers, event payloads, and response bodies are never
part of evidence, proposal, record, or verification projections.

The contract is informed by the [Pendo API](https://engageapi.pendo.io/), the
[Pendo developer documentation](https://support.pendo.io/hc/en-us/articles/38099922926875-Pendo-developer-documentation),
and Pendo's [aggregation guidance](https://support.pendo.io/hc/en-us/articles/15309243057819-Analyze-Page-parameters-with-the-API).
Layer-2 gaps remain native integration-key resolution, native HTTPS, durable
provider receipts, independent native read-back, and verified work-product or
outcome adoption.
