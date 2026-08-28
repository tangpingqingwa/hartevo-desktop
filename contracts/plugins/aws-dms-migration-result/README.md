# AWS DMS migration-result Layer 1

This contract is a bounded, read/proposal/record/verify-only seam for AWS
Database Migration Service replication tasks, serverless replications, and
assessment-result metadata. It is deliberately below Hartevo Truth, Consent,
Effect, Receipt, Verification, Outcome, and verified Work Product authority.

The provider boundary names only `DescribeReplicationTasks`,
`DescribeReplications`, and `DescribeReplicationTaskAssessmentResults`. The
crate accepts fixture, recording, loopback, and `BLOCKED_ENV` transports only.
All four are explicitly non-connected, non-native, and non-first-party; the
crate never emits a native or connected claim.

The projection keeps the exact account/region, replication/task identity,
source and target endpoint identity digests, optional replication-instance
identity, task revision, bounded migration window, task state, migration type,
full-load counters, stop-reason digest, assessment status/date, and assessment
report digest. It never retains endpoint credentials, table mappings, row data,
assessment bodies in S3, raw provider markers, or unbounded logs.

Task/endpoint/revision drift, marker replay, pagination truncation, partial or
unknown provider responses, access loss, throttling, timeout, tampering,
idempotency conflicts, and revoked registrations fail closed. A completed task
is external provider-state evidence and a Mission-scoped review proposal only;
it is not proof of migration safety or successful target read-back.

Native SigV4 resolution and HTTPS, durable provider receipts, independent
source/target read-back, consented migration effects, assessment execution,
operational migration claims, and verified Work Product adoption remain
Layer-2 host work.
