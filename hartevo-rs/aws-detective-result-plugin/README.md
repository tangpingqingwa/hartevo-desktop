# AWS Detective result plugin

This directory is a standalone Layer-1 Cargo workspace for the governed
Amazon Detective investigation-evidence result slice in
`contracts/plugins/aws-detective-result/`.

It owns only bounded, read-oriented seams for `ListInvestigations`,
`GetInvestigation`, `ListIndicators`, and `ListMembers`. The public evidence
model retains normalized identifiers, digests, revisions, time windows, and
severity/status/tactic/technique projections. It does not represent raw graph
search, graph edges, entity ARN/email data, indicator text, CloudTrail/VPC
Flow payloads, credentials, or mutation operations.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deliberately
non-connected, non-native, and non-first-party. Native SigV4/HTTPS,
host-owned Consent/Effect/Receipt/Verification, and Work Product adoption are
Layer-2 exits.

Run the scoped checks from this directory:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
```
