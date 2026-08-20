# AWS AppConfig deployment result Layer 1

This contract is a bounded metadata-only read, proposal, and recording seam
for AWS AppConfig `ListDeployments` and `GetDeployment`. It binds an AppConfig
application, environment, deployment, configuration profile, and version to a
Mission, Project, and Work Product projection without reading configuration
values or owning rollout effects.

The standalone crate has no AWS SDK, SigV4 resolver, HTTP client, or mutation
operation. Recording, fixture, loopback, and `BLOCKED_ENV` transports are
always non-connected, non-native, and non-first-party. A `SecretReference` is
opaque, non-serializable, debug-redacted, and represented in evidence only by
its digest.

The projection retains deployment strategy, bounded progress/state/timestamps,
and event digests. It never retains configuration values, raw event bodies,
secrets, or arbitrary rollout telemetry. Proposals and recordings remain below
Hartevo Truth, Receipt, Verification, Outcome, and Work Product authority.

Native SigV4 resolution, live HTTPS, durable provider receipts, independent
deployment read-back, Start/Stop/ValidateConfiguration or deployment effects,
and verified Mission adoption remain Layer-2 work. Fixtures, recordings,
loopback, and `BLOCKED_ENV` never claim Connected or native evidence.
