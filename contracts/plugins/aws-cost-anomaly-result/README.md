# AWS Cost Anomaly result Layer 1

This standalone contract and crate provide a bounded AWS Cost Anomaly
Detection read/proposal/record/verify seam. The boundary is below Hartevo
Truth, Consent, Effect, Receipt, Verification, Outcome, and Work Product
authority.

Only `GetAnomalies`, `GetAnomalyMonitors`, and `GetAnomalySubscriptions` are
allowlisted. Requests are bound to one management account, account, region,
monitor, anomaly date window and identity, subscription, deployment/service
revision, Mission, Project, and Work Product. Opaque pagination cursors and a
90-day retention fence are enforced before evidence can be proposed.

The `SecretReference` accepts an opaque SigV4 handle only long enough to hash
it. The handle is then discarded; it is not `Serialize`, `Display`, or part of
`Debug`. Anomaly, monitor, and subscription projections retain digests and
bounded status metadata only. They retain no subscriber addresses, billing
line items, exact impact amounts, raw cost-category expressions, raw root-cause
dimensions, notification payloads, or credential material.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are test seams,
not native providers. Every such result is `connected=false`, `native=false`,
`first_party=false`, and has no durable provider receipt. Layer-2 work still
owns native SigV4/HTTPS, credential resolution, durable provider receipts,
independent rereads, consented effects, notifications, billing mutations,
financial advice, and verified Work Product adoption.
