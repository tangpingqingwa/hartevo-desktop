# AWS Batch job-result Layer-1 contract

This standalone contract is a bounded evidence seam for deciding whether an
AWS Batch job, array job, or multi-node parallel job is adoptable by a Mission.
It retains identifiers, bounded lifecycle timestamps/statuses, retry and exit
code summaries, and digest-only container/artifact metadata.

The slice is read-only. Its provider surface is limited to `DescribeJobs` and
`ListJobs`; it never submits, cancels, terminates, or mutates AWS Batch work.
Fixture, recording, loopback, and `BLOCKED_ENV` transports are intentionally
non-connected and non-native. SigV4 secrets are host-owned opaque references
that are not serializable and are represented in evidence only by digests and
credential revisions.
