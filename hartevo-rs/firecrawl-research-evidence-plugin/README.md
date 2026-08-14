# Hartevo Firecrawl research-evidence plugin

This is the standalone Layer 1 root for Issue #376 (`EXT-FIRECRAWL-01`). The
machine-readable contract lives at
`contracts/plugins/firecrawl-research-evidence/firecrawl-research-evidence.v1.json`.

The crate exposes typed `FirecrawlResearchEvidenceService`, `FirecrawlProvider`,
and `MissionFirecrawlResearchConsumer` seams. A Mission is bound to an exact
Project/Mission/Work Product revision, an exact HTTPS host/URL allowlist, a
bounded scrape or crawl job, Markdown-only content options, permission
revision, and reversible registration digest. Evidence is limited to bounded
Markdown, title/content-type metadata, snippet/citation digests, job/page and
extraction-schema digests. Proposals and local recording receipts retain no
raw Markdown.

Fixture, recording, fake, loopback, and blocked-environment seams are local
evidence only. They always report `connected=false`, `native=false`, and
`first_party=false`; the crate never performs live Firecrawl HTTPS, resolves a
real API key, opens a browser, follows arbitrary URLs, visits login pages,
executes code, writes externally, or adopts a Work Product.

Layer 2 gaps remain explicitly typed: host-owned API-key resolution, native
scrape/crawl and status polling, durable provider receipts, independent
read-back, and verified adoption.

Run the scoped gates from this directory or the repository root:

```text
cargo fmt --manifest-path hartevo-rs/firecrawl-research-evidence-plugin/Cargo.toml -- --check
cargo test --manifest-path hartevo-rs/firecrawl-research-evidence-plugin/Cargo.toml --locked --all-targets
cargo clippy --manifest-path hartevo-rs/firecrawl-research-evidence-plugin/Cargo.toml --locked --all-targets -- -D warnings
```
