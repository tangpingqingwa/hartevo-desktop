# Hartevo OpenSearch retrieval-evidence plugin

This is the standalone Layer-1 root for Issue #341 (`EXT-OPENSEARCH-01`).
The machine-readable contract lives at
`contracts/plugins/opensearch-retrieval/opensearch-retrieval.v1.json`.

The crate owns a typed `OpenSearchRetrievalService`, `OpenSearchProvider`,
and `MissionRetrievalEvidenceConsumer`. It binds every proposal to the exact
HTTPS domain, cluster, index/alias, mapping revision/digest, query/source/sort
allowlists, Project, and Mission scope. Query input is a closed bounded AST;
pagination is PIT plus a stable `_id` search-after tie-breaker. Hits retain
only bounded allowlisted source values and deterministic query, mapping, PIT,
page, result, registration, receipt-candidate, and read-verification digests.

Fixture, recording, fake, loopback, and blocked-environment providers are
recording seams only. They report `BLOCKED_ENV`, `connected=false`, and
`native=false`; they do not execute HTTPS, resolve SigV4 credentials, or
serialize bearer/basic credentials, certificates, private keys, PIT tokens, or
raw provider bodies. No indexing, document writes, deletes, scroll, durable
receipt, Truth/Memory authority, or Work Product adoption exists here.

Layer 2 may add host-owned HTTPS/SigV4 or `SecretReference` resolution,
durable native receipts, independent read-back, and explicit adoption through
Hartevo-owned authorities. Those gaps remain typed as unavailable in Layer 1.

Run the scoped checks from this directory:

```text
cargo fmt --all
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```
