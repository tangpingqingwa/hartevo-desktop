# AWS Entity Resolution result Layer 1

This standalone contract is a bounded, metadata-only AWS Entity Resolution
read/proposal/record seam. It is below Hartevo Truth, Consent, Effect, Receipt,
Verification, Outcome, and durable Work Product authority.

The service surface is limited to `ListIdNamespaces`, `GetIdNamespace`,
`GetMatchingWorkflow`, `GetSchemaMapping`, and the dry-run `GetMatchId` lookup.
The latter is represented only as a proposal containing redacted match-group,
match-rule, and result digests. The crate never retains raw names, emails,
phones, source records, match IDs, identity-map bytes, or S3 output objects.

Source records are accepted only long enough to deterministically normalize and
fingerprint their bounded key/value map. Schema, namespace, and workflow
metadata retain typed counts, type labels, timestamps, and digests; customer
identifiers and provider payloads are not retained.

Every registration and proposal is bound to the exact account, region, schema
mapping, ID namespace, matching workflow, source-record fingerprint, Project,
Mission, and Work Product revision. Version, contract, provider, permission,
scope, and evidence digests reject drift. Registration transitions are
reversible while active/revoked and terminal after reversal.

Recording, fixture, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`. They are test and
boundary evidence only, never a Connected or first-party provider receipt.

## Layer-2 gaps

Native SigV4 resolution, live AWS Entity Resolution HTTPS, matching-workflow,
schema-mapping, or ID-namespace mutation, bulk matching jobs, identity-map
export, S3 output access, durable provider receipts, independent native
read-back, consented effects, identity certainty, causal attribution, and
verified Mission adoption remain Layer-2 work under host-owned kernel authority.
