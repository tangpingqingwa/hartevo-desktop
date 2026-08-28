# Zendesk support-result Layer 1

This directory owns Hartevo Issue #397 (`EXT-ZENDESK-01`) as a standalone
Layer-1 contract. The plugin binds one Zendesk subdomain/account, ticket and
exact ticket revision, requester, organization, SLA target, ticket metric,
audit revision, customer-resolution objective, and exact Project/Mission/Work
Product revisions.

`ZendeskSupportResultService`, `ZendeskProvider`, and
`MissionZendeskSupportConsumer` expose only typed support evidence:

- bounded ticket metadata, status, priority, type, requester/org IDs;
- SLA target state, including active, breached, paused, satisfied, unavailable,
  and unknown states;
- bounded response-time and ticket metrics;
- cursor and incremental audit pages with replay-safe event deduplication;
- satisfaction availability and score summary without comment retention; and
- digest-fenced proposal, recording, and verification surfaces for the next
  Mission decision.

The `SecretReference` is opaque and supports OAuth and API-token kinds. Only a
reference digest, scope digest, kind, and credential revision are recordable;
the supplied reference is never retained, serialized, formatted, or handed to
a live client. Version, contract, provider, permission, credential, and exact
scope registration is reversible and revocable.

Recording, fake, loopback, and `BLOCKED_ENV` transports are deterministic
Layer-1 fixtures. All report `connected = false`, `native = false`, and
`firstParty = false`. The boundary retains no raw comment, attachment, subject,
requester PII, audit export, or provider response body.

This plugin does not send comments, assign tickets, mutate status, create
webhooks, own Hartevo Inbox or human handoff, register a generic CRM, adopt a
Kernel Outcome, or claim a Connected/native/first-party integration. REL-01
Issue #76 owns CRM/Inbox/human-handoff authority and write/effect journeys;
Twilio Issue #304 owns message delivery.

Layer-2 gaps are native OAuth/API-token resolution, live HTTPS reads, durable
provider receipts, independent ticket/SLA reconciliation, and verified Work
Product adoption.

Official Zendesk references:

- <https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/>
- <https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_metrics/>
- <https://developer.zendesk.com/documentation/ticketing/reference-guides/ticket-audit-events-reference/>
- <https://developer.zendesk.com/api-reference/ticketing/introduction/pagination/>
