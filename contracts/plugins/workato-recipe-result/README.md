# Workato recipe/job result Layer 1

This directory owns the standalone Layer-1 contract for Issue #443
(`EXT-WORKATO-01`). It binds one Workato workspace, project, folder, recipe,
recipe version, job/retry identity, bounded step scope, and exact Hartevo
Project/Mission/Work Product and Consent revisions.

The typed seam is intentionally narrow:

- `WorkatoRecipeResultService` reads bounded recipe, version, and job metadata;
- `WorkatoProvider` exposes only allowlisted Developer API `GET` resources;
- `MissionWorkatoRecipeConsumer` validates the digest-fenced proposal for the
  next Mission decision without adopting a Kernel Outcome; and
- redacted request/result receipts, local recording, verification, consent,
  effect, and read-back seams make the Layer-2 boundary explicit.

Recipe status and step projections include completed, failed, processing,
paused, aborted, retried, retention-gap, partial, access-lost, and
provider-unknown outcomes. Runtime datapills and input/output payloads are
accepted only as transient transport fixture data and are discarded before a
projection, digest, receipt, recording, or Mission result is returned.

`SecretReference` is opaque and non-serializable. Only its digest, scope
digest, kind, and credential revision are recordable. Fixture, recording,
loopback, and `BLOCKED_ENV` transports always report `connected = false`,
`native = false`, and `first_party = false`.

This Layer-1 crate does not force-run, repeat, resume, start, stop, or poll a
recipe; mutate connections or lookup tables; retain runtime data; own a
scheduler or worker; resolve a native token; issue a durable native receipt;
perform an independent read-back; or adopt a Mission Work Product/Outcome.

Native token resolution, bounded HTTPS reads, durable provider receipts,
independent job reconciliation/read-back, and verified Work Product adoption
remain Layer-2 gaps.

Primary Workato references:

- <https://docs.workato.com/workato-api.html>
- <https://docs.workato.com/workato-api/jobs.html>
- <https://docs.workato.com/en/workato-api/resources.html>
- <https://docs.workato.com/recipes/jobs>
