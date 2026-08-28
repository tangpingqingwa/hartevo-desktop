# Modal job-result plugin contract

This directory contains the versioned Layer-1 contract for Hartevo’s Modal
FunctionCall job/result seam. The implementation is the standalone nested
workspace at `hartevo-rs/modal-job-result-plugin`.

Layer 1 is intentionally limited to typed scope description, deployed App and
Function lookup metadata, one bounded `spawn`/FunctionCall poll projection,
Mission-scoped proposal compilation, and safe recording. It never resolves a
Modal token, performs live Modal HTTPS or SDK work, cancels a call, mutates an
App/deployment/endpoint, starts a container or sandbox, executes arbitrary
code, retains logs/files/result bodies, creates a provider receipt, adopts an
Outcome, or claims Connected/native/first-party evidence.

The scope binds the exact HTTPS host, Workspace, App deployment, Function,
Environment, FunctionCall, serialized input, retry/poll policy, Mission,
Project, and Work Product revisions. Results are metadata-only: digests,
bounded byte counts, expiry, status, retry/poll counts, serialization flags,
and safe usage evidence. Recording, fake, loopback, and `BLOCKED_ENV`
transports are all explicitly non-native, non-connected, and non-first-party.

The provider shape follows Modal’s documented deployed-function job queue:

- [job processing](https://modal.com/docs/guide/job-queue)
- [`FunctionCall`](https://modal.com/docs/sdk/py/latest/modal.FunctionCall)
- [invoking deployed Functions](https://modal.com/docs/guide/trigger-deployed-functions)
- [Modal Python SDK changelog](https://modal.com/docs/reference/changelog)

Native token resolution, live invocation, durable provider receipts,
independent result readback/reconciliation, and verified Work Product/Outcome
adoption remain explicit Layer-2 gaps.
