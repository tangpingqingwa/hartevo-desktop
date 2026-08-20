# Brex spend-result Layer 1

This contract is a bounded, redacted read/proposal/record/verify seam for
Brex spend, limit, and policy observations. It is deliberately standalone and
below Hartevo Truth, Effect, Receipt, Verification, Outcome, and durable Work
Product authority.

The crate exposes typed `BrexSpendResultService`, `BrexSpendProvider`, and
`MissionBrexSpendConsumer` boundaries. Scope is bound to organization, user,
card, transaction, limit, policy, Project, Mission, and Work Product digests,
with explicit scope, permission, consent, and registration revisions. The
Brex credential is an opaque non-serializing `SecretReference`; no raw
credential, card number, merchant PII, or provider diagnostic is retained in
evidence, receipts, or `Debug` output.

Only bounded `recording`, `fixture`, `fake`, `loopback`, and `BLOCKED_ENV`
transports are available. Every one is explicitly `connected=false`,
`native=false`, and `first_party=false`. No transport creates, approves, pays,
refunds, or mutates Brex data. Layer 2 remains responsible for native
credential resolution, live Brex HTTPS, durable provider receipts, independent
provider read-back, consented effects, and verified Work Product/Outcome
adoption.
