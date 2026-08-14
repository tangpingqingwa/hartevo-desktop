# Fivetran Sync Result Layer-1 contract

This directory owns the standalone root contract for Hartevo Issue #411
(`EXT-FIVETRAN-01`). It binds one exact Fivetran account, group, destination,
connection, sync, schema, table, Hartevo Project, Mission, Work Product, and
revision fence.

The typed seam is intentionally bounded and read/proposal/recording-only:

- `FivetranSyncResultService` exposes connection, connection-state, bounded
  connection-list, and connection-schema/table projections, a deterministic
  sync-result proposal, and ephemeral recording evidence.
- `FivetranProvider` only permits the four allowlisted GET routes:
  `GET /v1/connections/{connection_id}`,
  `GET /v1/connections/{connection_id}/state`,
  `GET /v1/connections`, and
  `GET /v1/connections/{connection_id}/schemas`.
- `MissionFivetranSyncConsumer` validates the exact Project/Mission/Work
  Product scope and Mission revision and emits a non-adoptable observation
  below the Domain Kernel.

`SecretReference` is opaque, scoped, and deliberately not serializable. Only
digests of the external API-key reference, scope, permission snapshot, and
credential revision enter registration metadata. No API key, API secret,
Authorization header, connector config, row payload, source record, webhook,
or raw response body is retained or exposed.

Fivetran's connection-state endpoint returns connector-defined freeform state;
Layer 1 records only a bounded digest and field-count summary of that opaque
state, never its cursor or source-specific contents. The schema endpoint's
schema/table/column map is normalized into bounded metadata and fingerprints;
unknown configuration fields are discarded.

The projection records the Fivetran setup states `connected`, `broken`, and
`incomplete`; sync states `scheduled`, `syncing`, `paused`, and `rescheduled`;
update states `on_schedule` and `delayed`; latest success/failure timestamps;
schema/table fingerprints; and destination identity without credentials.
State revisions are monotonic, exact scope drift fails closed, pagination is
bounded, and rate-limit/backoff plus 401/403/404/409/429, timeout/5xx,
malformed/partial payloads, redaction, replay/tamper, stale Mission revision,
and registration revocation are explicit outcomes.

Fixture, recording, loopback, and `BLOCKED_ENV` transports always report
`connected = false`, `native = false`, and `firstParty = false`. Upstream
Fivetran's setup label `connected` is retained only as a provider-reported
setup state and never becomes Hartevo native connectivity authority.

This root does not trigger or re-sync a connection; create, update, move, or
delete connections; mutate schemas/tables/columns; ingest webhooks; read row
payloads or source records; provide a generic connector registry; own durable
receipts or destination read-back; or hold kernel/Outcome/Work Product
authority. Airbyte #354 owns Airbyte Cloud connector/sync evidence, dbt #353
owns transformation/model/test evidence, and Fivetran is a separately scoped
data-movement provider.

Layer 2 may add consented sync effects, durable receipts, webhook
reconciliation, native API-key resolution, bounded live HTTPS, and independent
destination read-back.

Primary references:

- <https://fivetran.com/docs/rest-api/getting-started>
- <https://fivetran.com/docs/rest-api/api-reference/connections>
- <https://fivetran.com/docs/rest-api/api-reference/connections/list-connections>
- <https://fivetran.com/docs/rest-api/api-reference/connection-schema>
