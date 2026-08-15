# Coda structured-result Layer 1 contract

This contract is a bounded, read-only metadata seam for Coda API v1. It is
limited to workspace/doc/page/table/view/column/row metadata and produces
redacted, digest-bound Mission proposals. It does not export raw rich text or
PII, execute formulas, press buttons, mutate rows/pages, or register a generic
knowledge source.

The API surface is based on the official [Coda API v1 reference](https://coda.io/developers/apis/v1).
Layer 1 accepts only fixture, recording, fake, loopback, and `BLOCKED_ENV`
transport seams; all of them truthfully report `connected = false`,
`native = false`, and `first_party = false`.

Native API-token resolution, live HTTPS, durable provider receipts,
independent readback, consented effects, and verified Work Product/Outcome
adoption are Layer 2 gaps.
