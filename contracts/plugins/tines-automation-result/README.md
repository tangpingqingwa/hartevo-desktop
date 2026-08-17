# Tines automation result contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
Tines story, story-run, action, event, case, and audit-log metadata. It is not a
playbook executor, trigger/retry API, credential manager, raw-payload/log
exporter, external-effect receipt, kernel authority, or Outcome authority.

The Rust crate is a standalone nested workspace at
`hartevo-rs/tines-automation-result-plugin`. Its only transports are fixture,
recording, loopback, and `BLOCKED_ENV`. Native credentials, live HTTPS,
external writes, durable native receipts, independent readback, and adoption
remain explicit Layer-2 gaps.

The API surface is based on the official [Tines API documentation](https://www.tines.com/api/):
versioned `/api/v1` GET endpoints, bounded pagination, and status-classified
responses. Raw event payloads, action inputs/outputs, case content, audit-log
inputs/outputs, credentials, and provider diagnostics are retained only as
digests or omitted.
