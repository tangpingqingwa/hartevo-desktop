# AWS CloudWatch Logs Insights result Layer-1 contract

This contract is a bounded, read/proposal/record/verify-only seam for
revision-fenced CloudWatch Logs Insights summaries. It is intentionally below
Hartevo Truth, Consent, Effect, Receipt, Verification, and Outcome authority.

The provider allowlist contains only `StartQuery`, `GetQueryResults`, and
`DescribeQueries`. Layer 1 accepts fixture, recording, loopback, and
`BLOCKED_ENV` transports only; each is explicitly non-native, non-connected,
and non-first-party. The crate does not resolve credentials, sign SigV4
requests, execute native HTTPS, retain raw log events, retain `@message` or
`@ptr`, retain PII or request bodies, or accept arbitrary query text.

Evidence retains only the allowlisted query/template and scope digests, query
status/timing, bounded counts, safe field names, typed error-class aggregates,
correlation-fingerprint digests, opaque page-token digests, and integrity
digests. Partial, running, expired, access-loss, provider-unknown, replay,
tamper, and revoked states are non-adoptable and fail closed.
