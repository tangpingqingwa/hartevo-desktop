# GitHub artifact-attestation result — Layer 1

This standalone contract is a bounded, read/proposal/record/verify-only seam
for GitHub’s official subject-SHA256 attestation listing endpoint:
`GET /repos/{owner}/{repo}/attestations/{subject_digest}`. The scope binds one
installation, organization, repository and visibility, subject digest,
predicate type, and Mission/Project/Work Product revisions. When GitHub
provides its numeric repository identity, that identity is an additional
fail-closed fence on returned records.

The provider retains only bounded identifiers and metadata digests for the
signer identity, certificate, signature, timestamp, predicate metadata, and
verification metadata. It never retains the attestation bundle or URL,
artifact bytes, raw provider payload, raw credentials, or raw signed metadata.
Pagination cursors are opaque and represented by digests only.

The Mission result is serializable only after all provider values have crossed
the redacted digest boundary; `SecretReference` itself is deliberately not
serializable and retains no credential material.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are always
non-connected, non-native, and non-first-party. Layer 1 does not resolve an
App/OAuth secret, perform native HTTPS, cryptographically verify signatures or
timestamps, mutate trust roots, delete attestations, download artifacts,
approve releases, create a durable provider receipt, or adopt a kernel Outcome.
Those remain explicit Layer-2 host Verification/Effect/Receipt/Outcome gaps.
