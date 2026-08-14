# Intercom conversation-result Layer 1

This directory owns Hartevo Issue #427 (`EXT-INTERCOM-01`) as a standalone
Layer-1 contract. The plugin binds one Intercom workspace, one conversation,
the exact conversation revision, a customer-conversation objective, and exact
Project/Mission/Work Product revisions.

`IntercomConversationResultService`, `IntercomProvider`, and
`MissionIntercomConversationConsumer` expose only typed evidence:

- bounded conversation state, priority, assignment/team IDs, and lifecycle
  timestamps;
- bounded conversation parts/replies with digest-only content;
- closed, reopened, assignment-change, access-loss, partial, and
  provider-unknown projections; and
- digest-fenced non-mutating adoption proposals and recording receipts.

`SecretReference` is opaque and supports OAuth and access-token kinds. Only a
reference digest, scope digest, kind, and credential revision are recordable;
the supplied reference is never retained, serialized, formatted, or handed to
a live client. Version, contract, provider, permission, credential, and exact
scope registration is reversible and revocable.

Recording, fake, loopback, and `BLOCKED_ENV` transports are deterministic
Layer-1 fixtures. All report `connected = false`, `native = false`, and
`first_party = false`. No names, emails, phone numbers, message bodies,
attachments, or raw provider response bodies are retained.

This plugin does not send replies, close or reopen conversations, assign
conversations, tag conversations, create webhooks, own Hartevo Inbox or human
handoff, register a generic CRM, adopt a Kernel Outcome, or claim a
Connected/native/first-party integration. Zendesk Issue #397 owns ticket/SLA
evidence and Twilio Issue #304 owns human-handoff delivery; the existing
kernel/REL-01 CRM/Inbox authority remains unchanged.

Layer-2 gaps are native OAuth/access-token resolution, live HTTPS reads,
durable provider receipts, independent conversation reconciliation, and
verified Work Product adoption.

Official API reference:

- <https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/conversation>
