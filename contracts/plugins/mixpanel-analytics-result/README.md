# Mixpanel analytics result — Layer 1

This contract is a standalone, read-only Layer-1 proposal boundary for bounded Mixpanel Insights saved-report aggregates. Its provider shape follows the official [Mixpanel developer documentation](https://mixpanel.com/developer/) and the documented [Query Saved Report endpoint](https://docs.mixpanel.com/reference/insights-query): `GET /api/query/insights` with `project_id`, optional `workspace_id`, and `bookmark_id`.

Layer 1 does not resolve a credential, connect to Mixpanel, perform HTTPS, or claim first-party/native authority. The `SecretReference` accepts an opaque project-token handle and stores only a digest, scope fence, credential revision, and revocation state. Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are explicitly non-native.

Only bounded aggregate counts keyed by allowlisted event labels and normalized date buckets are retained. Raw API bodies, raw events, event properties, user identifiers, profile data, ingestion, identity mutation, replay, causal claims, Work Product adoption, and Outcome/Truth authority are rejected or unavailable. Every registration, request, provider evidence, and proposal is bound to version, contract/provider/scope digests, Mission and Work Product revisions, and an idempotency digest. Registration and secret revocation fail closed.

The crate is intentionally independent of the root workspace and owns only this contract directory and `hartevo-rs/mixpanel-analytics-result-plugin/`.

## Scoped verification

```bash
cargo fmt --manifest-path hartevo-rs/mixpanel-analytics-result-plugin/Cargo.toml -- --check
cargo test --manifest-path hartevo-rs/mixpanel-analytics-result-plugin/Cargo.toml --locked --all-targets --all-features
cargo clippy --manifest-path hartevo-rs/mixpanel-analytics-result-plugin/Cargo.toml --locked --all-targets --all-features -- -D warnings
python3 -m json.tool contracts/plugins/mixpanel-analytics-result/mixpanel-analytics-result.v1.json >/dev/null
git diff --check
```

Layer-2 gaps remain native opaque-secret resolution, native Basic-auth/service-account resolution, HTTPS execution, durable provider receipts, repeat-read reconciliation, and verified Work Product adoption.
