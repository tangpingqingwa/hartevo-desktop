# Productboard Roadmap and Insight Result — Layer 1

This directory defines the standalone `EXT-PRODUCTBOARD-01` Layer-1 contract.
The Rust crate is intentionally outside the protected desktop Cargo workspace
so the provider seam can be reviewed and tested without changing core, UI,
catalog, or kernel authority.

The contract follows Productboard REST API v2's configuration-driven notes and
entity model. It binds every result to one exact workspace, configuration,
note/insight, and product-hierarchy scope plus a Project, Mission, and Work
Product. The official API basis is the [Productboard REST API v2
overview](https://developer.productboard.com/reference/introduction).

Layer 1 exposes bounded, redacted metadata aggregates and proposal evidence
only. It retains digests for identifiers, safe metadata, relationship shape,
response material, permissions, revisions, cursors, and registration fences.
Raw responses, note bodies, customer/member content, URLs, write payloads, and
Public API token material never cross the result boundary.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are
deterministic test seams. Every one reports `connected = false`, `native =
false`, and `first_party = false`. Layer 1 does not resolve credentials, open
native HTTPS, mutate notes/entities/relationships, send webhooks, create
durable provider receipts, independently read back native state, or assert
kernel Truth/Consent/Effect/Receipt/Verification/Outcome authority. Those are
Layer-2 gaps.
