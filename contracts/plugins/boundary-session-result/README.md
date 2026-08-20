# Boundary session-result Layer-1 contract

This contract is the standalone, read-only Layer-1 seam for bounded HashiCorp
Boundary session evidence. It permits only an exact session list/read and an
exact target metadata read. The implementation retains opaque IDs, lifecycle
timestamps, bounded connection counts, and redacted digests.

The contract does not authorize, connect, or cancel sessions; broker
credentials; mutate targets, hosts, or auth methods; execute SSH/RDP; download
recordings; or expose host addresses, host sets, connection details, users,
tokens, credentials, recording bytes, or raw provider bodies. Session state is
not authorization correctness, reachability, user activity, Truth, or Outcome.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
`connected: false`, `native: false`, and `firstParty: false`.

The API basis is the official HashiCorp Boundary documentation:

- <https://developer.hashicorp.com/boundary/api-docs/session-service>
- <https://developer.hashicorp.com/boundary/docs/targets/sessions>
- <https://developer.hashicorp.com/boundary/docs/api>
