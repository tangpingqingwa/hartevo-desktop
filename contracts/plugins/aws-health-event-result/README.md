# AWS Health event result contract

This is a standalone Layer-1, read-only evidence and proposal seam for the
AWS Health `DescribeEvents`, `DescribeEventDetails`, and optional
`DescribeAffectedEntities` APIs. It retains only bounded event identity,
provider-reported lifecycle/actionability and digest-only affected-entity
references.

The checked-in Rust crate is
`hartevo-rs/aws-health-event-result-plugin`. Its transports are explicitly
fixture, recording, loopback, and `BLOCKED_ENV`; none claims Connected, native
SigV4, a durable provider receipt, independent readback, outage causality, or
Hartevo operational Truth. Native SigV4 resolution and provider execution are
Layer-2 gaps.
