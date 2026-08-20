# AWS Neptune graph-query result Layer-1 contract

This contract is a standalone read/proposal/recording boundary for one exact
Mission-scoped Amazon Neptune property-graph query. It binds the AWS account,
region, VPC endpoint, cluster, graph namespace, predeclared query-template
digest, parameter digest, Mission, Project, and Work Product revisions.

Only a parameterized, fixed-length `MATCH` node or relationship pattern with a
bounded numeric `LIMIT` is accepted. Writes, deletes, loads, S3 reads,
variable-length traversals, arbitrary query text, positional parameters, and
unbounded output are rejected before the provider seam.

`SecretReference` is an opaque, non-serializing SigV4 handle. Node and edge
identifiers, labels, properties, raw query text, signed headers, credentials,
and unbounded provider error text are not retained in Debug output, contracts,
receipts, or evidence. Projections contain stable digests and bounded counts.

Recording, fixture, loopback, and `BLOCKED_ENV` provenance always report
`connected=false`, `native=false`, and `first_party=false`. Layer-2 work is
required for native SigV4/HTTPS/VPC access, durable provider receipts,
independent repeat-read/reconciliation, and verified Work Product adoption.
