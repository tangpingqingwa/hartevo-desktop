# AWS Trusted Advisor recommendation result contract

This is a standalone Layer-1, read-only AWS Support Trusted Advisor seam. It
projects bounded check definitions, refresh status, result status, category
counts, timestamps, and digest-only flagged-resource metadata into a Mission
proposal. It is not an optimizer, support-case client, remediation executor,
AWS Truth authority, kernel Outcome authority, or native AWS connector.

The nested Rust crate at
`hartevo-rs/aws-trusted-advisor-result-plugin` accepts only fixture, recording,
loopback, and `BLOCKED_ENV` transports. All four are explicitly non-connected,
non-native, and non-first-party. The opaque SigV4 `SecretReference` hashes the
host-owned handle and never serializes or resolves it.

AWS Trusted Advisor support-plan eligibility, `us-east-1` endpoint scope,
refresh freshness, check/category identity, response bounds, pagination,
permission/consent fences, registration drift, tampering, and revocation fail
closed. Flagged resource identifiers are retained only as SHA-256 digests and
their bounded AWS regions; descriptions, metadata arrays, raw payloads,
account identifiers, and unbounded resource lists are not retained.

Native SigV4 resolution, live AWS Support HTTPS, durable provider receipts,
independent repeat-read verification, kernel Consent/Effect/Receipt authority,
and consented remediation remain explicit Layer-2 gaps.
