# AWS Resource Explorer inventory result contract

This is a standalone Layer-1 contract and Rust crate for bounded AWS Resource
Explorer inventory evidence. It exposes only constrained `Search` and
`ListIndexes` read seams, proposal/record/verify boundaries, reversible
registration, and Mission observation.

The evidence surface retains digests for resource identity, query, index/view,
and resource properties. It never retains raw Resource Explorer properties,
tags, PII, provider response bodies, provider pagination tokens, credentials, or
arbitrary IAM roles. The `SecretReference` is an opaque, non-serializing SigV4
reference and is not a credential resolver.

The nested crate accepts only fixture, recording, loopback, and `BLOCKED_ENV`
transports. All of them explicitly report `connected=false` and
`native=false`; `BLOCKED_ENV` is a fail-closed environment state, not a native
connection. Native SigV4 signing and credential resolution, live AWS execution,
independent readback, durable receipts, deployment/compliance authority, and
kernel Outcome authority remain Layer-2 gaps.
