# Opsgenie incident-result Layer 1

This contract is a bounded, read-only evidence and proposal seam for scoped
Opsgenie alerts, alert aliases, incidents, schedules, escalations, and alert
timelines. It is not an alert-management API, notification sender, escalation
engine, schedule editor, incident mutation authority, durable provider receipt,
Hartevo Truth, Outcome, or Work Product adoption authority.

The Rust implementation is a standalone nested workspace at
`hartevo-rs/opsgenie-incident-result-plugin`. It exposes typed
`OpsgenieIncidentResultService`, `OpsgenieProvider`, and
`MissionOpsgenieIncidentConsumer` boundaries. Its only transports are fixture,
recording, loopback, and `BLOCKED_ENV`; all report `connected=false`,
`native=false`, and `first_party=false`. No transport opens native HTTPS or
resolves an Opsgenie token.

## Exact scope and bounded reads

Every registration, request, evidence envelope, proposal, and verification
fence binds account, API region, team, service, alert, alias, incident,
schedule, escalation, and timeline identifiers together with exact Project,
Mission, and Work Product revisions, consent, least-privilege permissions, and
the opaque `SecretReference` digest.

The provider allowlist contains only these GET seams:

- `/v2/alerts/{alertId}`;
- `/v2/alerts/{alertId}/timeline`;
- `/v1/incidents/{incidentId}`;
- `/v2/schedules/{scheduleId}`; and
- `/v2/escalations/{escalationId}`.

Timeline pagination, response bytes, item counts, duplicate IDs, request and
response digests, and rate-limit receipts are bounded. Raw messages, notes,
descriptions, recipients, contacts, headers, and response bodies are discarded
from evidence. Empty, partial, denied, access-loss, rate-limited, stale,
malformed, not-found, tampered, and provider-unknown states remain explicit and
non-adoptable.

Registration is versioned, provider- and scope-digest bound, reversible, and
revocable. Revoke and restore increment the registration revision and reseal
its digest. The secret reference stores no credential material and has a
redacted debug/serialization surface.

## Authority and Layer-2 gap

Layer 1 does not resolve native credentials, execute live Opsgenie HTTPS,
acknowledge/close/snooze/assign/delete alerts, create or update incidents,
mutate schedules or escalations, accept live webhooks, retain raw alert
content, create durable provider receipts, independently read native state, or
adopt a kernel Outcome or Work Product. Those are explicit Layer-2 gaps that
require host-owned consent, Effect, Receipt, Verification, and Truth authority.
