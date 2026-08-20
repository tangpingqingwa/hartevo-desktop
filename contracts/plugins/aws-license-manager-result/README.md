# AWS License Manager result Layer 1

This standalone contract exposes a bounded, metadata-only AWS License Manager
read/proposal/record/verify seam for a Mission-scoped license-capacity check.
It binds account, region, one allowlisted license configuration, one
allowlisted managed resource, a finite consumption window, and immutable
Project/Mission/Work Product revisions.

The only provider operations are normalized seams for
`ListLicenseConfigurations`, `GetLicenseConfiguration`, and
`ListUsageForLicenseConfiguration`. Pagination is opaque and digest-bound;
responses are bounded and contain no raw provider payload, resource inventory,
license rules, credentials, account identity, or provider status text.

The projection retains only license count/limit, license type, configuration
status, discovery time, allowlisted resource type, bounded usage count and
consumed-license totals, resource-status digests, quota state, and evidence
digests. Configuration, scope, provider, permission, pagination, usage-window,
tamper, replay, and registration-revocation drift fail closed.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deliberately
`connected=false`, `native=false`, and `first_party=false`. Layer 1 does not
resolve SigV4 credentials, perform live HTTPS, mutate configurations or
associations, retain raw license text, give financial/legal advice, create a
durable native receipt, perform independent native reread, or adopt a Hartevo
Outcome or Work Product. Those remain Layer-2 host-authority gaps.
