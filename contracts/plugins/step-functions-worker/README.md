# AWS Step Functions worker/result contract v1

This is the Layer-1 portability contract for running a Hartevo Mission through
AWS Step Functions. The owned Rust crate is independently testable at
`hartevo-rs/step-functions-worker-plugin` and binds every proposal, receipt,
status projection, task-token receipt, and Mission adoption proposal to:

- the AWS account and region;
- the exact state-machine ARN;
- the exact Mission ID;
- the execution input digest;
- the provider version and implementation digest; and
- the reversible registration digest.

Layer 1 is evidence-only. It can prepare typed HTTPS/SigV4 requests, use an
opaque `SecretReference` authentication boundary, replay deterministic fixture
responses, and project untrusted task-token callbacks. It does not invoke
`StartExecution`, `DescribeExecution`, `SendTaskSuccess`, or
`SendTaskFailure` against AWS. It never reports `Connected` or native authority
for fixtures, loopback, or `BLOCKED_ENV`.

The exact native gaps remain Layer 2 work: live StartExecution, a durable
execution receipt, bounded native DescribeExecution reconciliation, task-token
completion callbacks, independent output readback, and recovery of ambiguous
starts.
