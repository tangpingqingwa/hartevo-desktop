# PlanetScale branch-result Layer 1 contract

This root is a proposal-and-recording contract for bounded PlanetScale database
branch, deploy-request, and schema-posture metadata. It binds an exact
organization/database/branch/deploy/schema scope to Hartevo Project, Mission,
Work Product, consent, provider, revision, digest, cursor, and idempotency
fences.

Layer 1 has no live PlanetScale transport, credential resolution, branch or
deploy mutation, schema deployment, query execution, raw SQL, raw schema body,
raw API response, or durable Work Product adoption. Fixture, recording, fake,
loopback, and `BLOCKED_ENV` evidence is always `connected=false` and
`native=false`.

The bounded read posture is based on the official [PlanetScale API
reference](https://planetscale.com/docs/api/reference/getting-started-with-planetscale-api);
the API's direct data access, schema effects, and query execution remain out
of scope here.
