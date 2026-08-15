# Aha! Roadmap Result — Layer 1

This directory defines the standalone `EXT-AHA-01` Layer-1 contract. The Rust
crate is deliberately outside the protected desktop Cargo workspace so it can
be reviewed and tested as an isolated provider seam.

The contract follows the Aha! REST API roadmap hierarchy—account, workspace,
product line, initiative, release, feature, and requirement—while binding the
result to an exact Project, Mission, and Work Product scope. The official API
surface is documented at [Aha! REST API](https://www.aha.io/api).

Layer 1 exposes bounded, redacted metadata aggregates and proposal evidence
only. It retains digests for identifiers, titles, statuses, cursors, response
material, permissions, revisions, and registration fences; raw responses,
descriptions, URLs, write payloads, and API-token material do not cross the
transport boundary. Registration is reversible and revocable, and replay,
cursor, scope, revision, tamper, partial, empty, timeout, provider-unknown,
rate-limit, and redaction states are explicit.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are
deterministic test seams. Every one reports `connected = false`, `native =
false`, and `first_party = false`. Layer 1 does not resolve credentials, open
native HTTPS, prioritize roadmap work, edit releases/features/requirements,
send notifications, create durable provider receipts, independently read back
native state, or assert kernel Truth/Consent/Effect/Receipt/Verification/
Outcome authority. Those are later-layer gaps.
