# PubMed research result Layer 1

This contract freezes a read-only, proposal-only biomedical publication
evidence seam for EXT-PUBMED-01 (Issue #734). It is deliberately not a
clinical-advice, diagnosis, treatment, citation-truth, publication-quality,
ranking, full-text, abstract-retention, kernel Receipt, Verification,
Work Product, or Outcome authority.

The provider surface is based on the NCBI Entrez E-utilities:

- `https://eutils.ncbi.nlm.nih.gov/entrez/eutils`
- `GET /esearch.fcgi`
- `GET /esummary.fcgi`
- `GET /efetch.fcgi` (metadata projection only)
- `GET /elink.fcgi`

Layer 1 accepts only fixture, recording, fake, loopback, and `BLOCKED_ENV`
transport implementations. All five provenance values report
`connected=false`, `native=false`, and `first_party=false`. Query terms,
PMIDs, PMCIDs, MeSH terms, credentials, WebEnv/query keys, titles, abstracts,
full text, raw response bodies, and provider payloads are never emitted in
evidence, proposals, or receipts; bounded digests and metadata counts are
emitted instead.

Opaque cursor and history bindings are digest-bound to the query and scope.
Registration, consent, revision, and idempotency digests are verified before
reads and proposal projection. Registration revoke/restore is reversible and
rotates its digest and revision. A replay or tamper condition fails closed.

The Rust crate in `hartevo-rs/pubmed-research-result-plugin/` is a standalone
nested workspace and is not wired into the Hartevo kernel, root workspace,
application, desktop, catalog, UI, storage, or hosted CI.
