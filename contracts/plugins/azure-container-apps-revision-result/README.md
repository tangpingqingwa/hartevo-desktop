# Azure Container Apps revision result Layer 1

This standalone contract is a bounded, read-only evidence seam for one exact
tenant, subscription, resource group, Container App, and revision. It exposes
only app, exact-revision, revision-list, traffic, health, provisioning,
running, replica, timestamp, and redacted image-digest metadata.

It never retains or exposes templates, commands, arguments, environment
variables, secrets, managed identities, registries, volumes, probes, scale
rules, FQDNs, endpoints, logs, or raw provider errors. Opaque Entra handles
are hashed and zeroized at the boundary and are never serializable or
printable.

Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`. Their output is a
review-only proposal or local recording, never a durable provider receipt and
never Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, or Work
Product authority.

Official primary API basis:

- [Container Apps - Get](https://learn.microsoft.com/en-us/rest/api/containerapps/container-apps/get)
- [Container Apps Revisions - Get Revision](https://learn.microsoft.com/en-us/rest/api/containerapps/container-apps-revisions/get-revision)
- [Container Apps Revisions - List Revisions](https://learn.microsoft.com/en-us/rest/api/containerapps/container-apps-revisions/list-revisions)
