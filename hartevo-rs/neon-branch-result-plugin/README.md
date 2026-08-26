# Hartevo Neon branch-result plugin

This is the EXT-NEON-01 Layer-1 root. It is a standalone Rust crate and a
typed, versioned contract for exact Neon organization/project/branch/endpoint/
database/role and Mission scope.

Layer 1 provides:

- capability probes and branch proposals with parent/child and point-in-time
  fences;
- bounded parameterized `SELECT`/`EXPLAIN SELECT` proposals;
- independent digest-only query, schema, and row-set receipts;
- Mission source-revision and registration-bound database-result adoption
  proposals; and
- deterministic fixture/loopback recording seams with reversible registration.

Fixture, loopback, and `BLOCKED_ENV` evidence never reports `Connected` or
native execution. The exact native gap is deliberate: live branch
create/delete, endpoint mutation, durable operation receipts, bounded
activation polling, live query/readback, independent repeatable-read digest
verification, ambiguous-create recovery, and durable Work Product adoption
remain Layer-2 work.

The crate has an empty local `[workspace]` and is not added to the repository
workspace. A later integration layer owns host wiring.
