# HCP Packer artifact-version result Layer 1

This standalone contract is a bounded, read-only metadata seam for one exact
HCP Packer organization, project, bucket, version, channel, cloud, and region.
It projects bucket, channel, version, build, and artifact metadata without
retaining raw artifact locations, credentials, build logs, or labels outside an
explicit scope allowlist.

The provider surface is limited to the documented HCP Packer read operations
`GetBucket`, `GetChannel`, `GetVersion`, `ListBuilds`, and `ListArtifacts`.
Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`; local proposals and
recordings are not durable provider receipts.

Registration binds the plugin and contract versions, provider/API revisions,
permission fence, exact scope, evidence fence, and opaque SecretReference
digest. Registration is reversible and revocable, and pagination, truncation,
stale metadata, tamper, replay, access loss, provider-unknown, and revocation
fail closed.

Native HCP bearer credential resolution and HTTPS transport, durable provider
receipts, independent rereads, consented provider effects, verified Mission
Work Product adoption, and Hartevo Truth/Consent/Effect/Receipt/Verification/
Outcome authority remain Layer-2 work.
