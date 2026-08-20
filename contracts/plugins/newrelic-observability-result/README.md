# New Relic observability result Layer 1

This standalone contract is a bounded, read-only New Relic NerdGraph
observability projection below Hartevo Truth, Consent, Effect, Receipt,
Verification, Outcome, and Work Product authority.

The provider names only allowlisted reads for entity search and alertable
entity summaries, alert policy and NRQL condition metadata, AI Issues, and
issue events. Entity-search, condition-search, and AI Issues cursors are
opaque, query-bound, and page-bounded. The AI Issues experimental opt-in is a
recorded API requirement only; Layer 1 never performs a live NerdGraph call.

Evidence retains bounded identifier/severity/state/timestamp digests and
deterministic request, page, response, and result digests. It does not retain
NRQL text, raw telemetry, tags, URLs, PII, titles, credentials, or unbounded
GraphQL payloads. Registration binds version, contract, provider, account,
entity, workload, policy, condition, permissions, query policy, time window,
Mission scope, and the opaque secret-reference digest; registration is
reversible and revocable.

Recording, fixture, loopback, and `BLOCKED_ENV` transports always report
`connected=false`, `native=false`, and `first_party=false`. A projection is
external provider-state evidence, not a health/SLO certification, causal
finding, remediation, native provider receipt, or adopted kernel Outcome.

## Official API basis

- [NerdGraph entity data](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-entities-api-tutorial/)
- [NerdGraph issue and alert queries](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-issues-api-via-github/)
- [NerdGraph NRQL condition alerts](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-api-nrql-condition-alerts/)

## Layer-2 gaps

Native API-key resolution, live HTTPS, durable provider receipts, independent
native read-back, policy/condition/mute/workflow mutation, NRQL execution, raw
event export, dashboards, paging, webhooks, remediation, and verified Mission
Work Product or kernel Outcome adoption remain Layer-2 work.
