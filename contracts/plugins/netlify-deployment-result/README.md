# Netlify deployment-result Layer 1

This contract is a standalone, bounded read/proposal/record/verify seam for
Netlify site and deployment metadata. It is below Hartevo Truth, Consent,
Effect, Receipt, Verification, Outcome, and Work Product authority.

The provider surface is limited to `GET /api/v1/sites/{site_id}/deploys`
with bounded `Link` pagination and `GET /api/v1/deploys/{deploy_id}` state
readback. Site and deploy identifiers are explicit allowlists, and every read
is bound to a team, branch, commit, context, Project, Mission, and Work
Product revision. File information is metadata only: bounded count/byte totals
and a manifest digest. Source bundles, raw file bytes, environment variables,
logs, and secrets never enter the projection.

OAuth and personal-token material crosses the boundary only as an opaque,
non-serializing `SecretReference`. Registration binds plugin/API/provider
versions, contract/provider/permission/consent/scope/site/deploy/secret and
evidence digests. Registration is reversible and revocable; a revoked or
drifted registration fails closed.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deterministic
test seams. None claims Connected, native, first-party, a durable provider
receipt, or verified hosted content. A `ready` deploy state is only a bounded
provider-state proposal. Native secret resolution, live HTTPS, durable deploy
receipts, independent URL/content read-back, and verified Work Product
adoption remain Layer-2 work.
