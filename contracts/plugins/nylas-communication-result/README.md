# Nylas Communication Result — Layer 1

This directory defines the standalone `EXT-NYLAS-01-L1` contract. The Rust
crate lives outside the protected desktop Cargo workspace so it can be
reviewed and tested as an isolated provider seam.

Layer 1 reads bounded Nylas unified-grant message, thread, calendar, and event
metadata. It exposes only selected metadata fields and deterministic digests:
message, thread, and event identity and metadata are represented by SHA-256
digests, while body content, calendar descriptions, attachments, recipients,
and credential material are discarded at the boundary.

Registration binds the plugin and contract versions, provider definition,
permission snapshot, exact application/grant/mailbox/calendar/thread/message/
event/Project/Mission/Work Product scope, revision fences, secret reference,
and evidence-contract digest. Registration and the opaque secret reference are
reversible and revocable. Opaque cursors, bounded page limits, selected-field
digests, rate/backoff receipts, proposal idempotency, recording, verification,
tamper fences, and replay rejection are explicit.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are
deterministic test seams. Every one reports `connected = false`, `native =
false`, and `first_party = false`; `BLOCKED_ENV` is not a native-success
claim. Layer 1 does not resolve API keys or access tokens, open native HTTPS,
send or schedule messages, delete or update messages/events/threads, register
webhooks, download attachments, retain raw bodies or recipient PII, create a
durable provider receipt, independently read back native state, or assert
kernel Truth/Consent/Effect/Receipt/Verification/Outcome authority. Those are
Layer-2 gaps.

The API basis is the official [Nylas API reference](https://developer.nylas.com/docs/reference/api/),
[Messages API](https://developer.nylas.com/docs/reference/api/messages/),
[Threads API](https://developer.nylas.com/docs/reference/api/threads/), and
[Calendar API](https://developer.nylas.com/docs/v3/calendar/).
