# Google Cloud Memorystore for Redis instance result Layer 1

This contract is a standalone, bounded, read-only management-plane evidence
and proposal seam for one exact Google Cloud Memorystore for Redis instance.
It verifies the exact project/location/instance binding with `v1`
`projects.locations.instances.list` at one exact location followed by
`projects.locations.instances.get`. It does not read Redis keys or values and
does not control the instance.

The nested Rust crate only accepts fixture, recording, fake, loopback, and
`BLOCKED_ENV` transports. Every one of those transports remains
`connected=false`, `native=false`, and `first_party=false`; Layer 1 does not
resolve OAuth or service-account material or perform live HTTPS.

Projection and receipts retain only bounded scalar metadata and digests. Raw
resource paths, endpoints, AUTH strings, certificates, non-allowlisted label
keys/values, Redis keys/values, command output, and response bodies are never
serialized or emitted. Pagination tokens are opaque and digest-bound to the
exact scope, page size, page number, and API revision.

Registration is version-, contract-, provider-, API-, permission-, scope-,
credential-reference-, and evidence-bound. It can be reversed or revoked and
all mismatches fail closed. Layer-2 work remains native credential resolution,
live Google HTTPS, durable provider receipts, independent read-back, and any
host Consent/Effect/Receipt/Verification/Outcome or Work Product authority.
