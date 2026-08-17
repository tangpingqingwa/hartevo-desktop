# OpenAlex research-result contract

This Layer-1 contract is a bounded, read-only, redacted evidence and proposal
seam for OpenAlex work, author, institution, concept, and citation metadata.
It is not a ranking engine, full-text reader, author-identity authority,
citation-truth authority, research-Truth authority, Work Product authority, or
Outcome authority.

The Rust implementation is a standalone nested workspace at
`hartevo-rs/openalex-research-result-plugin`. Its only transport seams are
fixture, recording, loopback, and `BLOCKED_ENV`. Native API-key resolution,
live HTTPS, durable provider receipts, independent readback, and verified
Work Product/Outcome adoption remain Layer-2 gaps.

The allowlist is intentionally limited to OpenAlex metadata GET shapes for
`/works`, `/authors`, `/institutions`, and the legacy `/concepts` entity, plus
bounded citation projections through OpenAlex work filters. Search terms,
filters, entity identifiers, cursors, titles, abstracts, and credentials are
accepted only at redacting boundaries and are represented in Layer-1 evidence
by opaque digests or bounded numeric metadata.

Official API reference: https://developers.openalex.org/api-reference/introduction
