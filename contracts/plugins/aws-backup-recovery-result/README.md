# AWS Backup recovery-result Layer 1

This contract is a bounded, metadata-only read/proposal/record/verify seam for
AWS Backup recovery points. It is deliberately standalone and below Hartevo
Truth, Consent, Effect, Receipt, Verification, and Outcome authority.

The provider boundary names the AWS Backup `ListRecoveryPointsByBackupVault`
and `DescribeRecoveryPoint` reads. The crate can only use recording, fixture,
loopback, or `BLOCKED_ENV` transports. None of those transports is Connected,
native, first-party, or a durable provider receipt.

The projection retains typed scope, lifecycle/completion/expiry state, size as
metadata, encryption-key reference digests, pagination completeness, and
evidence digests. It never retains backup bytes, recovery payloads, raw tags,
KMS material, raw provider status messages, or unbounded resource metadata.

A completed recovery point is external provider-state evidence only. It is not
proof that a restore will succeed and cannot be adopted as a Hartevo Outcome or
Work Product. Native SigV4 resolution, live HTTPS, durable provider receipts,
independent recovery readback, and consented restore effects remain Layer-2
work under host Consent/Effect/Receipt/Verification authority.
