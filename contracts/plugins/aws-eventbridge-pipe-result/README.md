# AWS EventBridge Pipes result contract

This directory defines the standalone Layer-1 contract for bounded AWS
EventBridge Pipes state evidence. The paired Rust crate is
`hartevo-rs/aws-eventbridge-pipe-result-plugin`.

The seam permits only `ListPipes` and `DescribePipe` read projections,
proposal construction, and redacted idempotent recording. It binds account,
region, pipe, source, target, Mission, Project, permission, provider, and
opaque SecretReference digests. It never retains event payloads or arbitrary
EventBridge configuration.

Recording, fixture, loopback, and `BLOCKED_ENV` transports are explicitly
non-connected and non-native. Native SigV4 resolution, live HTTPS, durable
provider receipts, lifecycle effects, delivery proof, and verified Work
Product adoption remain Layer-2 host authority.
