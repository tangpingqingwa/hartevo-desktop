# Deepgram transcript-result Layer 1 plugin

This standalone nested workspace owns a bounded, read-only Deepgram transcript
result seam. It binds an exact Deepgram host and provider project to a request,
model revision/configuration, digest-only audio fingerprint, bounded utterance
window, Hartevo Project, Mission, Work Product, and consent revision.

`DeepgramTranscriptResultService`, `DeepgramProvider`, and
`MissionDeepgramTranscriptConsumer` project transcript metadata, language and
quality indicators, and digest-only segment evidence. The public result never
contains audio bytes, transcript text, raw words, media, provider error text, or
an opaque credential/page-token value. Registration, consent, scope, revision,
request, evidence, proposal, and idempotency digests are verified at every
boundary.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are bounded
test seams. All report `connected = false`, `native = false`, and
`first_party = false`; recording is in-memory diagnostic evidence and is not a
durable provider receipt. No live HTTPS, credential resolution, audio effect,
media write, raw transcript retention, Work Product adoption, Outcome adoption,
or kernel authority is implemented.

Native secret resolution, live Deepgram reads, consented media effects,
durable provider receipts, independent transcript readback, and verified Work
Product adoption remain explicit Layer-2 gaps.
