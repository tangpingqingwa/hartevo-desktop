# EXT-MONTECARLO-01 — Layer-1 data-observability result

This contract and `hartevo-rs/montecarlo-observability-result-plugin` form a
standalone Layer-1 slice for bounded Monte Carlo incident, freshness, lineage,
and monitor observation proposals.

The crate accepts only opaque, scope-bound `SecretReference` handles. It never
resolves a token, performs native HTTP, queries a warehouse, returns raw rows or
lineage, mutates monitors, claims `Connected`/native execution, certifies data
quality, or adopts a Mission Outcome/Work Product. Recording, fixture, fake,
loopback, and `BLOCKED_ENV` transports all remain non-native.

The contract freezes the allowlisted read surface, bounds, digest inputs,
redacted receipt shape, reversible registration, and Layer-2 gaps. The nested
crate is deliberately absent from the root Cargo workspace so this PR touches
only the two exclusive prefixes named by Issue #760.

Scoped verification:

```text
cargo fmt --manifest-path hartevo-rs/montecarlo-observability-result-plugin/Cargo.toml -- --check
cargo test --manifest-path hartevo-rs/montecarlo-observability-result-plugin/Cargo.toml --locked
cargo clippy --manifest-path hartevo-rs/montecarlo-observability-result-plugin/Cargo.toml --locked --all-targets -- -D warnings
```
