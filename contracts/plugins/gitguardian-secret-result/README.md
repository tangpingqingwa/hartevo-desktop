# GitGuardian secret result Layer 1

This directory defines the `EXT-GITGUARDIAN-01` boundary. The contract and
standalone Rust crate provide a bounded read, proposal, and local-recording
seam for GitGuardian secret incidents, occurrences, detectors, and provider
status.

Layer 1 accepts only an opaque, non-serializing `SecretReference` for an API
key or service account. It never resolves that reference, performs live HTTP,
retains a secret or occurrence content, exports raw provider payloads, mutates
an incident, or certifies compliance. Incident, occurrence, detector,
workspace, perimeter, repository, commit, and request values are bounded and
digest-bound where provider text could be sensitive.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are intentionally
`connected=false`, `native=false`, and `first_party=false`. A local recording
is not a provider receipt, independent readback, remediation, or Work Product
adoption.

The official API reference is [GitGuardian API](https://api.gitguardian.com/docs).
Native credential resolution, live GitGuardian transport, durable provider
receipts, independent rereads, consented revoke/rotate/delete effects, source
content export, compliance certification, and verified Work Product/Outcome
adoption remain Layer-2 work.
