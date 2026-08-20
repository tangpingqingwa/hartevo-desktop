# Docker Hub image result Layer 1

This standalone contract is a bounded, read-only Docker Hub repository/tag
metadata seam below Hartevo Truth, Consent, Effect, Receipt, Verification,
Outcome, and durable Work Product authority.

The provider allowlist contains only the Docker Hub API v2 exact-tag read:
GET /v2/namespaces/{namespace}/repositories/{repository}/tags/{tag}. The
scope is one exact namespace, repository, tag, manifest/image identity fence,
and bounded platform tuple set. The projection retains tag status, the
provider-reported last-updated timestamp, immutable image/manifest digest
identities, bounded platform tuples, size/layer counts, and deterministic
digests.

Descriptions, collaborators, usernames, layer URLs, layer digests,
Dockerfile history/instructions, scan details, raw response bodies, tokens,
and credential material are discarded. No login, pull, push, delete, tag,
build, scan, webhook mutation, layer download, or image execution is exposed.
Tag metadata is not content integrity, a signature, attestation, SBOM,
vulnerability result, runtime fact, Hartevo Truth, or Outcome.

Fixture, recording, fake, loopback, and BLOCKED_ENV transports are always
connected=false, native=false, and first_party=false; none is a first-party
provider receipt.

## Layer-2 gaps

Native Docker Hub authentication and HTTPS, durable provider receipts, live
provider transport, registry manifest/layer reads, signature or attestation
verification, SBOM/vulnerability scanning, image download or execution,
mutation, webhook handling, production content-integrity certification, and
verified Mission Work Product adoption remain Layer-2 work.
