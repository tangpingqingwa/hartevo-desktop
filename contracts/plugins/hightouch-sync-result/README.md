# Hightouch sync-result Layer 1

This contract is a standalone Layer-1, read/proposal/recording-only seam for
bounded Hightouch reverse-ETL metadata. It binds a workspace, source, model,
sync, destination, run, commit, Project, Mission, and Work Product scope.

The plugin only accepts allowlisted `GET` metadata reads. It projects resource
and run metadata to digests, bounded counters, and typed states; it never
retains source rows, destination payloads, raw API keys, raw cursors, raw
responses, or provider error text. Fixture, recording, fake, loopback, and
`BLOCKED_ENV` transports are explicitly non-native and non-connected.

Layer 2 owns native API-key resolution, live Hightouch HTTPS, durable provider
receipts, independent run readback, sync triggering/cancellation, destination
writes, source-row access, and Work Product/Outcome adoption.

API basis: [Hightouch API overview](https://hightouch.com/docs/developer-tools/api-guide).
