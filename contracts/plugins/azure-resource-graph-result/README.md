# Azure Resource Graph inventory result contract

This Layer-1 contract is a bounded, read-only Azure Resource Graph inventory
evidence and proposal seam. It is deliberately limited to an allowlisted
resource query AST, a tenant and subscription/management-group scope, and
digest-only selected properties. It is not arbitrary KQL, a resource mutation
API, a deployment or policy authority, a fleet-health claim, or a kernel
Outcome authority.

The checked-in Rust crate is a standalone nested workspace at
`hartevo-rs/azure-resource-graph-result-plugin`. Its test transports are
fixture, recording, loopback, and `BLOCKED_ENV`; none claims Connected, native,
or first-party status. Native Microsoft Entra resolution, native HTTPS,
durable provider receipts, independent repeat-read, and consented effects are
explicit Layer-2 gaps under host authority.
