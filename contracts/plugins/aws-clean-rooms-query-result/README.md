# AWS Clean Rooms protected-query result Layer 1

This contract is a standalone, bounded metadata read/proposal/record seam for
AWS Clean Rooms protected-query processing. It is scoped to one AWS account,
region, collaboration, membership, analysis template, protected query,
privacy-budget reference, Project, Mission, and Work Product revision.

The provider models only `ListProtectedQueries` and `GetProtectedQuery`. It has
no start, update, or cancel operation, no SQL execution authority, no S3
access, and no member-data access. SQL text, member identities, privacy-budget
values, differential-privacy sensitivity values, result configuration, output
locations, and provider error text are digested or discarded before any
projection is serialized.

Recording, fixture, loopback, and `BLOCKED_ENV` transports are deterministic
test seams. All four are explicitly `connected=false`, `native=false`, and
`first_party=false`; none is a provider receipt or a claim of statistical
privacy, analytical truth, verified Work Product adoption, or a live AWS
connection.

Native SigV4 resolution, live AWS HTTPS, durable provider receipts, independent
query read-back, consented query effects, S3 result access, and kernel-owned
Truth/Consent/Effect/Receipt/Verification/Outcome authority remain Layer-2
gaps.
