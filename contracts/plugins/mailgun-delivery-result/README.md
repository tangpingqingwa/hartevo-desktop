# Mailgun delivery-result Layer 1

This standalone contract provides a bounded, redacted read/proposal/record/
verify seam for Mailgun delivery and event evidence. It includes delivery
status, event identity digests, retry/backoff metadata, suppression metadata,
opaque cursor pagination, and webhook tamper/replay fences.

The scope is exact and binds the Mailgun account/domain/tag/message/event/
recipient-fingerprint selectors to Project, Mission, Work Product, consent,
and revision digests. Message bodies, MIME, recipient addresses, raw event
payloads, webhook tokens, and credential material never cross the seam.

The Rust crate at `hartevo-rs/mailgun-delivery-result-plugin` is a standalone
nested workspace. Fixture, recording, fake, loopback, and `BLOCKED_ENV`
transports are deterministic test seams and always report
`connected=false`, `native=false`, and `first_party=false`. Native credential
resolution, live HTTPS, durable provider receipts, independent delivery
readback, send effects, and verified Work Product adoption remain Layer-2.
