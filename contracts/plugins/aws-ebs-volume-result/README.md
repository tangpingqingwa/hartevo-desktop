# AWS EBS volume and snapshot posture result Layer 1

This contract is a standalone, bounded metadata read/proposal/record/verify
seam for EC2 EBS volumes, volume status, snapshots, and fast snapshot restore
posture. It is below Hartevo Truth, Consent, Effect, Receipt, Verification,
Outcome, and Work Product authority.

The provider names only the four read APIs
`DescribeVolumes`, `DescribeVolumeStatus`, `DescribeSnapshots`, and
`DescribeFastSnapshotRestores`. The crate accepts recording, fixture, loopback,
and `BLOCKED_ENV` transports only. None of these transports is Connected,
native, first-party, or a durable provider receipt.

Evidence is allowlist- and digest-bound. Volume, attachment, status event,
snapshot, and Availability Zone identifiers are projected as digests; volume
type, size, encryption, multi-attach, impairment, lifecycle, age, and fast
restore state remain bounded metadata. The crate retains no block bytes, mount
paths, tag values, KMS material, account PII, or storage mutation authority.

Pagination cursors are opaque digests bound to the exact operation, account,
region, volume/snapshot allowlists, scope, filter, and page number. Resource
replacement, pagination loops, stale status, partial/unknown/access-loss
evidence, tampering, replay, and registration revocation are non-adoptable.

Native SigV4 resolution, live EC2 HTTPS, durable provider receipts,
independent metadata/data reconciliation, consented storage effects, and
verified Work Product adoption remain Layer-2 work. A completed metadata read
is not a production recoverability guarantee.
