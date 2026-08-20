# Fly.io deployment result Layer 1

This directory defines the versioned `EXT-FLYIO-01-L1/v1` contract for a
bounded, read-only Fly.io Apps and Machines evidence seam.

The companion Rust crate in
`hartevo-rs/flyio-deployment-result-plugin/` is an independent nested Cargo
workspace. It exposes the typed `FlyioDeploymentResultService`,
`FlyioMachinesProvider`, and `MissionFlyioDeploymentConsumer` seam without
editing the protected root workspace.

Layer 1 is deliberately recording/fixture/loopback/`BLOCKED_ENV` only. Each
transport reports `connected=false`, `native=false`, and `first_party=false`.
The opaque non-serializing `SecretReference` never exposes a Fly API token.
Only bounded GET-shaped app and Machine list/detail evidence is projected:
state, region, timestamps, restart-policy summary, service-port metadata,
image/release digests, and bounded event type/status/timestamps. Private IPs,
environment, commands/arguments, mounts, checks, metadata values, lease
nonces, tokens, raw config, host details, user identity, logs, filesystems, and
network exports are not retained.

The provider has no create/start/stop/update/suspend/cordon/lease/delete or
other external-write authority. Registration is version/contract/provider/API/
permission/scope/evidence-digest bound, reversible, revocable, and fail-closed
on drift, stale Mission revisions, replay, tamper, access loss, truncation, or
provider uncertainty. A Machine state is provider evidence below Hartevo
Verification/Outcome and is not proof of reachability, health, release
success, or Work Product adoption.

Official API basis:

- [Machines API](https://fly.io/docs/machines/api/)
- [Machines resource](https://fly.io/docs/machines/api/machines-resource/)
- [Apps resource](https://fly.io/docs/machines/api/apps-resource/)

Native token resolution/HTTPS, durable provider receipts, independent
repeat-read/reconciliation, verified Work Product adoption, and any consented
deployment or Machine effect remain Layer 2.
