# AWS Firehose delivery-result Layer 1 contract

This contract defines the standalone `EXT-AWSFIREHOSE-01-L1/v1` seam for a
Mission that needs bounded Kinesis Data Firehose stream and destination-health
evidence before deciding how to handle a data handoff.

The seam is deliberately read/proposal/record/verify-only. It binds the exact
AWS account, region, stream allowlist, target stream, stream version, source
revision, permission snapshot, Project, Mission, and Work Product revisions.
`SecretReference` and `ExclusiveStartDeliveryStreamName` values remain opaque
and are represented outside evidence by digests only.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deterministic
test/provenance modes. None can claim Connected, native, first-party, a durable
provider receipt, delivery completion, or verified Work Product adoption.

Layer 2 still owns native SigV4/HTTPS, durable provider receipts, delivery
acknowledgement, independent destination read-back/reconciliation, consented
delivery effects, and verified adoption by Hartevo Truth/Outcome/Work Product
authority. This contract never exposes payloads, S3 objects, transformation
code, destination configuration, delivery logs, or credential material.
