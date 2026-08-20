# Crossref research result Layer 1

This contract freezes a read-only, proposal-only Crossref scholarly metadata
result seam for Hartevo Issue #699. It is deliberately not a search engine,
citation-truth authority, source-quality authority, bibliography store, or
kernel Outcome/Receipt/Verification authority.

The provider surface is based on the public Crossref REST API:

- `https://api.crossref.org/`
- `GET /works`
- `GET /works/{doi}`

Layer 1 only accepts fixture, recording, loopback, and `BLOCKED_ENV` transport
implementations. All four provenance values report `connected=false`,
`native=false`, and `first_party=false`. Query terms, DOI values, titles,
credentials, and raw response bodies are not emitted in evidence, proposals,
or receipts; bounded digests and metadata counts are emitted instead.

The Rust crate in `hartevo-rs/crossref-research-result-plugin/` is a standalone
nested workspace and is not wired into the Hartevo kernel or root workspace.
