# Statuspage incident-result contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
published Statuspage page, component, component-group, incident, update, and
scheduled-maintenance observations. It is not an uptime guarantee, customer-
wide availability authority, incident-management API, notification sender,
subscriber manager, webhook receiver, postmortem exporter, or remediation
authority.

The Rust implementation is a standalone nested workspace at
`hartevo-rs/statuspage-incident-result-plugin`. It exposes the typed
`StatuspageIncidentResultService`, `StatuspageProvider`, and
`MissionStatuspageIncidentConsumer`. Fixture, recording, loopback, and
`BLOCKED_ENV` transports are the only Layer-1 transports. All four report
`connected=false`, `native=false`, and `first_party=false`; no transport opens
native HTTPS or resolves a Statuspage token.

## Bounded API surface

The provider emits only GET requests under the documented Statuspage API v1
prefix:

- `/pages/{page_id}` for a page profile;
- `/pages/{page_id}/components` for component status;
- `/pages/{page_id}/component-groups` for component-group membership;
- `/pages/{page_id}/incidents` for bounded incidents and incident updates; and
- `/pages/{page_id}/incidents/scheduled` for scheduled maintenance incidents.

The page, component, component-group, incident, update, time-window, Project,
Mission, Work Product, Consent, permission, provider, contract, and opaque
`SecretReference` digests are bound into registration, evidence, proposal, and
verification fences. Registration can be revoked and restored; secret
references can be revoked. Scope, stale revision, tampered digest, replay,
rate-limit, malformed-response, access-loss, and partial-result cases fail
closed or remain explicitly typed.

Raw JSON, update bodies, postmortem/internal notes, subscriber/contact data,
custom tweets, automation addresses, metadata, and other unbounded provider
fields are discarded. Evidence retains only bounded IDs or digests, normalized
status, timestamps, component transitions, response/request digests, and
bounded rate-limit receipts. A public Statuspage observation does not prove
causality, remediation, customer-wide uptime, or business outcome.

## Authority and Layer-2 boundary

Layer 1 does not resolve native credentials, execute live HTTPS, create/update
incidents or components, send notifications, manage subscribers, register
webhooks, export private notes, persist durable provider receipts, independently
reread native state, or adopt kernel Outcome. Layer 2 may add explicitly
consented effects and verified readback under host-owned Effect, Receipt,
Verification, Consent, and Outcome authority.

The contract is versioned at
`contracts/plugins/statuspage-incident-result/statuspage-incident-result.v1.json`.
Its API shape is based on the official
[Statuspage API documentation](https://developer.statuspage.io/), including
the versioned REST GET endpoints and documented 420/429 rate limits.
