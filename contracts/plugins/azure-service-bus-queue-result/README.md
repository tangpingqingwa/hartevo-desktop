# Azure Service Bus queue posture result — Layer 1

This contract is a bounded, read-only posture seam for one exact Azure Service
Bus namespace and queue. Its provider allowlist contains only ARM `GET` queue
description and namespace queue-list operations for API version `2026-01-01`.
It never reads, sends, receives, peeks, settles, or deletes messages and never
mutates queues, topics, subscriptions, IAM, keys, or dead-letter data.

The contract binds tenant, subscription, resource group, namespace, queue,
dead-letter posture, Project, Mission, Work Product, permissions, provider
revision, and an opaque Entra `SecretReference` through deterministic digests.
ARM resource IDs, endpoint details, authorization rules, connection strings,
continuations, message bodies/properties, lock tokens, session state, and PII
are not retained in projections or receipts. Numeric counts, sizes, durations,
and page/response budgets are bounded before they enter the projection.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are explicitly
`connected=false`, `native=false`, and `firstParty=false`. Queue counts are
bounded posture evidence only; they are not delivery verification or kernel
Truth, Consent, Effect, Receipt, Verification, or Outcome authority.

Official API basis:

- [Queues - Get](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/queues/get?view=rest-servicebus-controlplane-2026-01-01)
- [Queues - List By Namespace](https://learn.microsoft.com/en-us/rest/api/servicebus/controlplane/queues/list-by-namespace?view=rest-servicebus-controlplane-2026-01-01)
