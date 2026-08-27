# CockroachDB Cloud posture result — Layer 1

This contract is a standalone, versioned read/proposal/record/verify seam for
bounded CockroachDB Cloud cluster, health, settings-metadata, and SQL-activity
posture evidence. It is bound to exact organization, Cloud project, cluster,
region, database, branch, SQL-activity window, Hartevo Project, Mission, Work
Product, permission, and revision scope.

The Rust crate accepts only fixture, recording, fake, loopback, and
`BLOCKED_ENV` transports. Every mode is explicitly `connected=false`,
`native=false`, and `first_party=false`. Cursors are opaque digests bound to
the exact scope, query shape, page, and expiry.

Evidence retains bounded typed projections and digests only. It does not retain
API credentials, connection strings, passwords, raw SQL, raw result rows, raw
provider payloads, cluster endpoints, or unbounded settings/activity data.
Healthy or current posture is a provider-reported observation, not a health,
security, availability, Truth, Effect, Receipt, Verification, Outcome, or Work
Product authority claim.

Layer 2 remains responsible for native credential resolution, live Cloud API
reads, SQL-activity reads, durable provider receipts, independent provider
read-back, consented effects, cluster/branch/settings mutation, and verified
Work Product or Outcome adoption.
