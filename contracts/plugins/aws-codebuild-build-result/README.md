# AWS CodeBuild build-result Layer 1

This contract defines a standalone, read-only Layer-1 evidence boundary for
bounded `ListBuildsForProject`, `BatchGetBuilds`, and `BatchGetProjects` seams.
It is limited to fixture, recording, loopback, and `BLOCKED_ENV` transports.

The root retains normalized identities, statuses, bounded timestamps, and
metadata digests only. It never resolves or serializes credentials, performs
native SigV4/HTTPS, mutates a build or project, retains commands/environments/
logs/source or artifact bytes, issues a durable native provider receipt, reads
artifacts independently, or adopts a Mission outcome or Work Product.
