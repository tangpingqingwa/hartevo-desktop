# AWS ECS deployment result — Layer 1

This contract is a bounded read/proposal/record/verify seam for ECS deployment
observations. It owns typed account, region, cluster, service, deployment,
task-definition, task, Mission, Project, Work Product, permission, consent and
digest/revision fences.

The crate intentionally has no AWS SDK, signer, credential resolver, HTTP
client, mutation operation, ECS Exec, log reader, environment/secret exporter,
image-content reader, kernel authority, or Outcome adoption. Fixture, recording,
loopback, and `BLOCKED_ENV` transports are always non-native, non-connected and
non-first-party. `BLOCKED_ENV` is an explicit honest native gap, not a successful
connection.

The only task failure material retained is a digest of a stopped reason. Raw
next tokens are opaque and only their digests cross the evidence boundary.
Truncated, partial, unknown and access-loss evidence is non-adoptable.
