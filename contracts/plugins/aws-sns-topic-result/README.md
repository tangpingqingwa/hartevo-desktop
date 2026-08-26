# EXT-AWS-SNS-01 — governed SNS topic-fanout result

This Layer-1 contract provides a bounded, review-only metadata seam for an
allowlisted SNS topic and its allowlisted subscriptions. It covers
`ListTopics`, `GetTopicAttributes`, `ListSubscriptionsByTopic`, and
`GetSubscriptionAttributes` through recording, fixture, loopback, and
`BLOCKED_ENV` transports.

Topic identity and subscription identity are digest-only in evidence. The
projection retains FIFO/content-protection posture, protocol and confirmation
state, redrive-policy and filter-policy digests, delivery-policy digest, and a
bounded endpoint class. It never retains message bodies, endpoint addresses,
raw policy JSON, filter values, credentials, or subscriber PII.

The nested Rust crate is intentionally standalone and below Hartevo Truth,
Consent, Effect, Receipt, Verification, Outcome, and Work Product authority.
All registration, permission, scope, provider, contract, secret-reference,
proposal, record, and evidence bindings are digest-fenced and reversible.

There is no native SigV4 resolution or HTTPS client in Layer 1. The native
credential path, durable provider receipt, independent delivery readback,
consented effects, and verified Work Product adoption remain Layer-2 work.
