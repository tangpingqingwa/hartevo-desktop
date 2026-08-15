# AWS AppFlow flow-execution result — Layer 1

This directory owns the versioned Layer-1 contract for Issue #798. It is a
bounded, metadata-only read/proposal/record/verify seam for a Mission deciding
whether one Amazon AppFlow flow execution is reviewable. It does not expose
source or target records and it does not grant flow execution authority.

The typed provider allowlist is exactly `ListFlows`, `DescribeFlow`, and
`DescribeFlowExecutionRecords`. Pagination tokens are retained only as opaque
digests, and flow/execution revisions are part of every request fence. Flow
names, ARNs, connector labels, descriptions, status text, and provider error
messages are projected to bounded enums, counters, or digests before they can
enter evidence.

The `SecretReference` accepts only a host-owned opaque SigV4 handle, hashes it
against the exact account/region/flow/execution/source/target/trigger and
Project/Mission/Work Product scope, then drops the handle. It cannot serialize
credential material or print it in `Debug` output.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deliberately
honest: all report `connected = false`, `native = false`, and
`first_party = false`. A successful fixture or recording proposal is review
evidence only; it is not a delivery-correctness claim, provider receipt,
independent destination read-back, Truth/Effect/Verification/Outcome authority,
or Work Product adoption.

Native SigV4 resolution, live AWS HTTPS, flow start/stop/delete/update effects,
connector credential mutation, durable provider receipts, source/target record
access, independent destination reconciliation, and kernel adoption remain
Layer-2 gaps.

Primary API references:

- <https://docs.aws.amazon.com/appflow/1.0/APIReference/API_ListFlows.html>
- <https://docs.aws.amazon.com/appflow/1.0/APIReference/API_DescribeFlow.html>
- <https://docs.aws.amazon.com/appflow/1.0/APIReference/API_DescribeFlowExecutionRecords.html>
