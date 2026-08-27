# GitHub deployment-status result contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
one GitHub Deployment and its paginated Deployment Status history. It binds a
repository, deployment, ref, commit SHA, environment, installation, Mission,
Project, and Work Product. Deployment and status URL values are retained only
as digests; logs, source, artifacts, payloads, creator/reviewer identity, and
generic release-dashboard data are outside the seam.

The checked-in Rust crate is a standalone nested workspace at
`hartevo-rs/github-deployment-status-result-plugin`. Its transports are only
fixture, recording, loopback, and `BLOCKED_ENV`. Native GitHub App/OAuth
resolution, native HTTPS, durable provider receipts, independent read-back,
webhooks, and deployment/status writes remain explicit Layer-2 gaps.
