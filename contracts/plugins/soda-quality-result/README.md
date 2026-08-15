# Soda quality result contract

This standalone Layer-1 contract gives a Mission a bounded, review-only
projection of Soda dataset, check, scan, and quality-health evidence. It does
not execute checks, expose rows or check payloads, mutate a dataset, certify
data correctness, create a Hartevo provider receipt, or adopt a Work Product.

The Rust crate at `hartevo-rs/soda-quality-result-plugin` is a nested workspace.
Its provider accepts only an opaque, scope-bound API-token `SecretReference`
and only fixture, recording, fake, loopback, or `BLOCKED_ENV` transports. Every
transport is explicitly `connected=false`, `native=false`, and
`first_party=false`; native credential resolution and live Soda Reporting API
access remain Layer-2 work.

Evidence keeps only bounded counts, statuses, metric values, digests, and
redacted request/cost receipts. Dataset names, check names, scan identifiers,
organization identifiers, data-source identifiers, metric names, opaque
markers, API tokens, raw rows, raw response bodies, and provider authorization
material are never retained in a proposal or Mission result.

Registration is reversible and revocable. Its digest binds the plugin,
contract, provider/API revision, read permissions, complete scope, revisions,
and `SecretReference` digest. Revision and idempotency fences reject stale,
cross-scope, replay-conflicting, tampered, or revoked evidence.

Official API basis: [Soda overview and Reporting API](https://docs.soda.io/soda/product-overview.html).

## Layer-2 gaps

Native API-token resolution; live Soda HTTPS; durable first-party provider
receipts; independent reread/read-back verification; check execution; dataset,
check, scan, or metric mutation; raw row or payload export; consented effects;
data-correctness certification; and verified Mission Work Product adoption.
