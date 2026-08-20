# Azure Monitor Logs result plugin

This is a standalone nested Rust workspace for Issue #831
(`EXT-AZURE-MONITOR-LOGS-01`). It owns the typed Layer-1 contract and a
provider/service/Mission consumer vertical slice without joining the root
workspace or changing shared/core/application/catalog code.

The crate accepts only a typed, parameterized aggregate KQL AST with a
mandatory bounded RFC3339 time window. It binds tenant, subscription,
workspace, table, Project, Mission, Work Product, revisions, permission and
consent digests, query-template/parameter/time-window digests, and an opaque
non-serializing Entra `SecretReference` into a reversible/revocable
registration.

`fixture`, `recording`, `loopback`, and `BLOCKED_ENV` are always
`connected=false`, `native=false`, and `first_party=false`. Results retain
only bounded aggregate schema/cells and deterministic digests. No result can
claim Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, or
Work Product adoption authority.

Scoped local gates:

```text
cargo fmt --check --manifest-path hartevo-rs/azure-monitor-logs-result-plugin/Cargo.toml
cargo test --locked --manifest-path hartevo-rs/azure-monitor-logs-result-plugin/Cargo.toml --all-targets
cargo clippy --locked --manifest-path hartevo-rs/azure-monitor-logs-result-plugin/Cargo.toml --all-targets -- -D warnings
```
