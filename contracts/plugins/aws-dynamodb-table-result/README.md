# AWS DynamoDB table-result Layer 1

This contract is a standalone, bounded metadata-only read/proposal/record/verify
seam for DynamoDB table posture. It is deliberately below Hartevo Truth,
Consent, Effect, Receipt, Verification, Outcome, and durable Work Product
authority.

The provider boundary exposes only `ListTables`, `DescribeTable`,
`DescribeContinuousBackups`, `DescribeTimeToLive`, and `ListTagsOfResource`.
Every Layer-1 transport is recording, fixture, loopback, or `BLOCKED_ENV`; all
four are non-connected, non-native, and non-first-party. The opaque SigV4
`SecretReference` is a digest-bound reference only. It never serializes,
resolves credentials, or contains credential material.

The projection retains typed scope and digest-only table identity, table status,
key-schema/index/replica/encryption posture, PITR/recovery-window and TTL
posture, bounded tag-key digests, timestamps, pagination fences, and evidence
digests. It never retains items, key/value data, streams, raw tag values, raw
policies, account PII, or provider payloads.

The service rejects table replacement, schema/index drift, stale metadata,
pagination loops, filter drift, malformed or partial provider responses, access
loss, throttling, unknown provider failures, replay conflicts, tampering, and
revoked registrations as non-adoptable evidence or closed errors. A completed
posture result is provider metadata only; it is not a recoverability guarantee.

Native SigV4 resolution, live HTTPS, durable provider receipts, independent
metadata/data reconciliation, consented table effects, and verified Mission
adoption remain Layer-2 work. The crate has no item read, Query/Scan, write,
restore, export, native Connected claim, or Hartevo kernel authority.
