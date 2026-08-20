# AWS SQS queue-health result Layer 1

This contract is a bounded, metadata-only read/proposal/record/verify seam for
Amazon SQS queue and dead-letter posture. It is deliberately below Hartevo
Truth, Consent, Effect, Receipt, Verification, Outcome, and Work Product
authority.

The provider allowlist is exactly `ListQueues`, `GetQueueUrl`,
`GetQueueAttributes`, and `ListDeadLetterSourceQueues`. The crate has no AWS
SDK, SigV4 signer, credential resolver, live HTTPS client, queue mutation, or
message read path. `SendMessage`, `ReceiveMessage`, `DeleteMessage`,
`PurgeQueue`, `CreateQueue`, and `SetQueueAttributes` are not representable as
provider methods.

Evidence retains typed queue identity and digest-only DLQ relationships,
FIFO/encryption/redrive posture, timestamps, bounded approximate available /
not-visible / delayed counts, pagination digests, and freshness fences. SQS
approximate counts are eventually consistent observations. They are never
delivery proof, a production guarantee, or a certification claim.

Recording, fixture, loopback, and `BLOCKED_ENV` transports are explicit
non-native, non-connected, non-first-party seams. They can produce review
proposals and idempotent recordings, but cannot be adopted as a kernel Outcome
or verified Work Product. Native SigV4/HTTPS execution, durable provider
receipts, independent message-delivery reconciliation, and consented effects
remain Layer-2 host work.
