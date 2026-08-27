# HashiCorp Nomad deployment result Layer 1

This contract is a standalone, read-only Layer-1 boundary for bounded
HashiCorp Nomad job, deployment, and allocation metadata. It produces
digest-bound Mission proposals and local recordings only. It cannot submit,
stop, scale, deregister, or otherwise mutate a Nomad job, deployment, or
allocation, and it never exposes task logs, task events, environment values,
Vault material, ACL token material, or raw job payloads.

The typed surface is intentionally exact: `Project`, `Mission`, `WorkProduct`,
and the Nomad provider scope are all bound into the registration, evidence,
proposal, and verification digests. `SecretReference` is opaque and does not
implement serialization; only its digest crosses a durable boundary.

The bounded read allowlist follows the official Nomad API surfaces:

- [Jobs API](https://developer.hashicorp.com/nomad/api-docs/jobs)
- [Deployments API](https://developer.hashicorp.com/nomad/api-docs/deployments)
- [Allocations API](https://developer.hashicorp.com/nomad/api-docs/allocations)

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are all
explicitly disconnected, non-native, and non-first-party. Native ACL/Vault
resolution, live HTTPS transport, durable provider receipts, independent
read-back, consented Nomad effects, and verified Work Product or Outcome
adoption remain Layer-2 work under Hartevo Truth, Consent, Effect, Receipt,
Verification, and Outcome authority.
