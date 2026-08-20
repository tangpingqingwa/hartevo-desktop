# AWS SSM Automation result Layer 1

This standalone contract and Rust crate expose a bounded, read/proposal/
record/verify seam for AWS Systems Manager Automation metadata. The only
allowlisted AWS reads are `DescribeAutomationExecutions`,
`GetAutomationExecution`, and `DescribeAutomationStepExecutions`.

The scope is bound to an AWS account and region, Automation document and
version, execution, optional step and target selectors, Mission, Project, and
Work Product revisions. Filters and pagination cursors are opaque digests bound
to that scope and the permission fence. Execution replacement and status
regression fail closed.

Only fixture, recording, loopback, and `BLOCKED_ENV` transports are available.
All are explicitly non-connected, non-native, and non-first-party. SigV4
references are reduced to an opaque digest; raw credential material is never
serialized or retained. Provider output, logs, parameters, target values, and
error messages are represented only by bounded digests.

This Layer 1 boundary does not start or stop Automation, send commands, mutate
parameters or targets, retain raw output/logs/secrets, create a durable
provider receipt, or adopt a Hartevo Outcome. Native SigV4, live HTTPS,
independent readback, and any consented effect remain Layer 2 work.
