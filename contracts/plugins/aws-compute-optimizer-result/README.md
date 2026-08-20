# AWS Compute Optimizer recommendation evidence contract

This standalone Layer-1 slice provides bounded, read-only evidence for an
AWS Compute Optimizer capacity decision. The allowlist contains only
`GetEC2InstanceRecommendations` and
`GetAutoScalingGroupRecommendations`. Evidence is scoped to one account and
region, an explicit resource allowlist, a closed recommendation window, and
Mission/Project/Work Product bindings.

The nested Rust crate at
`hartevo-rs/aws-compute-optimizer-result-plugin` accepts only fixture,
recording, loopback, and `BLOCKED_ENV` transports. These modes are always
non-connected and non-native. Pagination tokens, accounts, resources,
recommendation identifiers, and configuration values are represented by
digests; raw utilization series and provider payloads are not representable.

Registration binds plugin/API/contract/provider/permission/scope,
resource-allowlist, recommendation-window, evidence-policy, and opaque
SigV4-reference digests. Proposal, record, verify, and registration lifecycle
operations fail closed on drift, freshness loss, pagination replay, tamper,
access loss, truncation, and revocation.

Native SigV4 resolution, live HTTPS reads, durable provider receipts,
independent post-change readback, consented preference/resource effects, and
kernel Outcome adoption remain explicit Layer-2 exits. No savings guarantee or
capacity mutation is made by this contract.
