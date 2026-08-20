# Azure Monitor Logs result contract

`azure-monitor-logs-result.v1.json` is the versioned Layer-1 contract for a
governed Azure Monitor Logs aggregate read proposal.

The contract binds one exact tenant, subscription, workspace, and table to
one Project/Mission/Work Product revision. It permits only a typed,
parameterized aggregate KQL AST with a mandatory bounded time window. The
projection keeps schema types and bounded aggregate cells, and exposes
deterministic SHA-256 digests for the scope, query template, query,
parameters, time window, schema, row set, result, and registration.

The provider seam only accepts `fixture`, `recording`, `loopback`, and
`blocked_env` provenance. Every one of those modes is explicitly
`connected=false`, `native=false`, and `firstParty=false`. The contract does
not grant Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, or
Work Product adoption authority.

The official API shape is the Azure Monitor Logs Query API `POST /v1/workspaces/{workspaceId}/query` with KQL and a time range. Native Entra and HTTPS execution, durable receipts, independent reconciliation, exact read-back, and verified adoption remain Layer 2.
