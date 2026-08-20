# AWS Kinesis stream-result Layer 1

This standalone contract is a bounded, metadata-only read/proposal/record seam
for one explicitly scoped Kinesis Data Stream. It retains stream status, mode,
retention, open-shard count, monitoring/encryption posture, optional exact
consumer metadata, and digest-only shard lineage. It never reads records,
partition keys, sequence numbers, hash-key ranges, payloads, or key material.

`DescribeStreamSummary`, `ListShards`, and optional exact
`DescribeStreamConsumer` are the only provider reads. Fixture, recording,
loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`; none is a durable
provider receipt.

Reversible and revocable registration binds version, provider/API, permission,
consent, exact stream/version/filter/consumer scope, and opaque SecretReference
digests. Native SigV4/HTTPS, durable receipt, independent reread, consented
effects, Truth/Consent/Effect/Receipt/Verification/Outcome authority, and
verified Mission Work Product adoption remain Layer-2 work.
