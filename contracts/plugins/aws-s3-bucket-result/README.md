# EXT-AWS-S3-BUCKET-01 Layer-1 contract

This contract is a bounded, read/proposal/record/verify-only seam for AWS S3
bucket durability posture. It retains typed posture projections and stable
digests only; it never retains object keys or bytes, bucket policies, KMS
material, replication role ARNs, tags, credentials, or raw provider payloads.

The accepted transports are fixture, fake, recording, loopback, and
`BLOCKED_ENV`. Every one is explicitly `connected=false`, `native=false`, and
`first_party=false`. Native SigV4 resolution/HTTPS, durable native receipts,
independent native rereads, effects, and verified Work Product adoption remain
Layer-2 host authority.
