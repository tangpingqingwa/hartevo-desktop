# Hartevo Figma design-result plugin — Layer 1

This crate is a standalone, read/recording-only boundary for Figma design
results. It exposes typed file, version, node, bounded-export, provider, and
Mission-consumer paths without changing the Hartevo workspace manifest or
connecting a live Figma account.

Layer 1 deliberately provides:

- team, Figma project, Hartevo project, Mission, file, node, and exact version
  scope;
- opaque `SecretReference` authentication for OAuth, personal-access-token,
  and plan-access-token transport seams;
- version/digest/scope-bound reversible registration;
- deterministic fixture and loopback transports plus an explicit
  `BLOCKED_ENV` transport;
- exact-byte SHA-256 fencing for bounded PNG/JPG/SVG/PDF export payloads;
- redacted receipts and revision-bound, proposal-only Work Product adoption.

Fixture, loopback, and `BLOCKED_ENV` evidence always has `connected == false`
and `native == false`. The crate contains no file/comment/branch/variable/
permission/webhook mutation, no durable external receipt, no independent
readback, and no verified native Work Product adoption. Those are Layer-2
gaps.

Run the crate independently from the repository root:

```text
cargo fmt --manifest-path hartevo-rs/figma-design-plugin/Cargo.toml --all -- --check
cargo test --manifest-path hartevo-rs/figma-design-plugin/Cargo.toml --locked --all-targets
cargo clippy --manifest-path hartevo-rs/figma-design-plugin/Cargo.toml --locked --all-targets -- -D warnings
```
