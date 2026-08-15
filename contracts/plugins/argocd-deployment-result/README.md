# Argo CD deployment result Layer 1

This contract describes a standalone, read-only Layer-1 boundary for bounded
Argo CD Application, resource-tree, sync-status, and operation metadata. It
can compile a redacted proposal and an idempotent Mission recording, but it
cannot sync, roll back, terminate, write Kubernetes resources, resolve a
bearer token, or claim that Argo CD is connected or native.

The only transport proven by this package is deterministic fixture, recording,
fake, loopback, or `BLOCKED_ENV` evidence. Native bearer-token resolution,
live Argo CD HTTPS access, durable provider receipts, raw manifest/secret/log
handling, Hartevo authority, and verified Work Product adoption remain Layer-2
gaps.
