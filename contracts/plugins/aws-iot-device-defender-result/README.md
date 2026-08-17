# AWS IoT Device Defender audit result — Layer 1

This is the standalone Layer-1 contract for bounded, read-only AWS IoT Device
Defender audit evidence. It covers only `ListAuditTasks`, `DescribeAuditTask`,
and `ListAuditFindings` for an explicitly bound account, region, audit task,
check allowlist, resource allowlist, Mission, Project, and Work Product
revision.

The contract is proposal/recording-only. Fixture, recording, loopback, and
`BLOCKED_ENV` transports are always reported as non-connected, non-native, and
non-first-party. The contract contains no native SigV4 resolver, HTTP client,
AWS write operation, audit-task start/cancel operation, mitigation or
suppression mutation, thing/certificate/policy mutation, raw finding payload,
kernel authority, durable native receipt, independent reread, or verified Work
Product adoption.

Evidence retains only redacted audit status, check state, severity, suppression
flags, bounded resource-type/resource digests, provider response digests, and
failure categories. Credentials are represented by an opaque,
non-serializing `SecretReference`; raw credential material never enters this
contract or crate.
