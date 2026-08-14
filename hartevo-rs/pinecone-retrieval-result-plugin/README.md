# Hartevo Pinecone retrieval-result Layer 1

This is a standalone nested Cargo workspace for `EXT-PINECONE-01-L1/v1`.
It exposes a typed `PineconeRetrievalResultService`, `PineconeProvider`, and
`MissionPineconeRetrievalConsumer` seam for bounded query/fetch evidence.

The scope is exact and includes cloud, region, project, index, HTTPS host,
namespace, Mission scope, consent reference, and index revision. Queries use
an allowlisted model, finite dimension-bounded vector, bounded `top_k`, and a
closed typed filter AST. Metadata, IDs, scores, read units, revisions,
response digests, and replay fences are bounded and verified.

Layer 1 intentionally has no live Pinecone transport, API-key or service-
account resolution, upsert/delete/namespace mutation, arbitrary filter DSL,
durable receipt, Memory persistence, generic catalog, or native/connected
claim. Fixture, recording, fake, loopback, and `BLOCKED_ENV` modes all remain
`connected=false`, `native=false`, `NativeStatus::BlockedEnv`.

Run the scoped gates from this directory or the repository root:

```text
cargo fmt --manifest-path hartevo-rs/pinecone-retrieval-result-plugin/Cargo.toml -- --check
cargo test --manifest-path hartevo-rs/pinecone-retrieval-result-plugin/Cargo.toml --locked --all-targets
cargo clippy --manifest-path hartevo-rs/pinecone-retrieval-result-plugin/Cargo.toml --locked --all-targets -- -D warnings
```
