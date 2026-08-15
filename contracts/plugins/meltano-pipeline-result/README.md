# Meltano pipeline result Layer 1

This contract is a bounded, metadata-only read/proposal/recording seam for
Meltano Cloud/Singer pipelines, jobs, incremental state, and configuration
digests. It is deliberately below Hartevo Truth, Consent, Effect, Receipt,
Verification, Work Product, and Outcome authority.

The provider accepts only an opaque API-token `SecretReference`. The crate
never resolves native credentials, executes, stops, or deletes a pipeline/job,
installs plugins, mutates a project/environment/state, reads raw logs or rows,
retains Singer state blobs, or serializes secrets or provider cursors.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are all explicitly
non-connected, non-native, and non-first-party. Native credentials, live
Meltano transport, durable provider receipts, independent terminal rereads,
consented effects, and verified Work Product/Outcome adoption remain Layer-2
gaps.

The contract is grounded in the official [Meltano Cloud pipelines API](https://docs.meltano.com/reference/cloud/api/resources/pipelines/),
[jobs API](https://docs.meltano.com/reference/cloud/api/resources/jobs/),
[pagination links](https://docs.meltano.com/reference/cloud/api/links), and
[CLI state semantics](https://docs.meltano.com/reference/command-line-interface).
