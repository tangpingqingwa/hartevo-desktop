# AWS Athena query-result Layer 1

This standalone contract exposes a bounded, review-only analytical result
seam below Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, and
Work Product authority.

The only provider operations are `GetQueryExecution` and an optional capped
`GetQueryResults` metadata/shape read. Parameterized `SELECT` and
`EXPLAIN SELECT` queries must use an explicit catalog/database/table allowlist
and a numeric `LIMIT` within the caller's bounds. Raw SQL, parameter values,
rows, cells, S3 output locations, credentials, signed headers, and opaque page
tokens are retained only as digests or bounded shapes.

Registration binds version, contract, provider/API revision, permissions,
exact AWS and Mission scope, and evidence-contract digests. It is reversible
and revocable. Fixture, recording, loopback, and `BLOCKED_ENV` provenance is
always non-connected, non-native, and non-first-party. This crate never starts
or cancels Athena queries and never reads S3 output objects.

Layer-2 exits are native SigV4/HTTPS and credential resolution, live query
submission or cancellation with explicit kernel authority, durable provider
receipts, independent read-back/reconciliation, and verified Work Product
adoption.
