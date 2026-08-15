# Canny feedback result — Layer 1

This contract is a standalone, read-only Layer-1 proposal boundary for bounded Canny board, post, comment, status, category, roadmap, and aggregate-vote feedback evidence. The provider shape follows Canny's documented POST API, but this crate deliberately stops before credential resolution, HTTPS execution, or any connected/native claim.

`SecretReference` is an opaque API-key handle. Only a scope-bound digest, credential revision, and revocation state cross the boundary; the supplied reference and bearer material are never retained or serialized. Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are explicitly non-native.

The evidence model retains bounded IDs as digests, allowlisted post statuses, aggregate vote counts, bounded counts, and strict redaction metadata. Raw API bodies, comment text, board/category/roadmap labels, author/voter identity, user PII, URLs, tokens, feedback mutation, Jira/project mutation, causal demand claims, Work Product adoption, and Outcome/Truth authority are outside Layer 1.

Registrations bind plugin and contract version, provider definition, every scope revision, the opaque secret reference, and a deterministic registration digest. Revoke returns a deterministic reversible revocation receipt and all reads fail closed after revocation. Idempotency is request-digest bound; a conflicting reuse of a key is rejected.

## Scoped verification

```bash
cargo fmt --manifest-path hartevo-rs/canny-feedback-result-plugin/Cargo.toml -- --check
cargo test --manifest-path hartevo-rs/canny-feedback-result-plugin/Cargo.toml --locked --all-targets --all-features
cargo clippy --manifest-path hartevo-rs/canny-feedback-result-plugin/Cargo.toml --locked --all-targets --all-features -- -D warnings
python3 -m json.tool contracts/plugins/canny-feedback-result/canny-feedback-result.v1.json >/dev/null
git diff --check
```

Layer-2 gaps remain native opaque-secret resolution, native Canny authentication and HTTPS execution, durable provider receipts, independent reread/reconciliation, consented feedback effects, verified Work Product adoption, and any kernel Outcome/Truth authority.

The official API reference documents the read and write surface: [The Canny API](https://help.canny.io/en/articles/4195400-the-canny-api) and [Canny API Reference](https://developers.canny.io/api-reference). This Layer-1 contract allowlists reads only.
