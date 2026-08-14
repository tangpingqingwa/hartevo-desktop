# Octopus release-result Layer 1 contract

This directory defines the standalone Layer-1 contract for bounded Octopus
release and deployment-result evidence. The Rust implementation lives in
hartevo-rs/octopus-release-result-plugin as its own nested workspace; the
protected Hartevo root workspace and host applications are intentionally not
edited.

The contract binds one exact HTTPS server, space, project, channel, release,
environment, tenant (or explicit untenanted scope), deployment, target,
Mission, Hartevo Project, and Consent scope. Registrations bind the plugin
version, contract identity, provider/API revisions, permission snapshot,
scope, opaque SecretReference digest, and registration revision. They can be
revoked or reversed and fail closed on drift.

The provider exposes only bounded GET seams for:

- spaces, space projects, project channels, environments, and tenants;
- one release and deployment-process/template metadata; and
- one deployment and its task state.

Receipts keep request path/query, status, bounded response size, response
digest, provenance, and redaction flags only. No API key/OIDC material, raw
task logs, scripts, package bytes, prompted-variable values, or generic
deployment registry is retained. Result projections support
queued, running, succeeded, failed, canceled, paused, partial,
retention-gap, access-lost, and provider-unknown.

Layer 1 is recording/fixture/loopback/BLOCKED_ENV only. It never claims
Connected or native status and has no release creation, deployment
trigger/cancel/approve, variable or tenant mutation, runbook/worker control,
Mission adoption, Outcome authority, or kernel authority.

The API vocabulary is based on Octopus's official documentation:

- <https://octopus.com/docs/octopus-rest-api/examples/deployments/create-and-deploy-a-release>
- <https://octopus.com/docs/best-practices/deployments/releases-and-deployments>
- <https://octopus.com/docs/projects/deployment-process>
- <https://octopus.com/docs/octopus-rest-api/examples/deployments/deploy-release-with-prompted-variables>
