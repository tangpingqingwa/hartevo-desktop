# GitHub Secret Scanning Result Layer 1

This directory defines the `EXT-GITHUB-SECRET-SCANNING-01` boundary. The
contract and the standalone Rust crate are a read/proposal/record seam only.

The provider is limited to bounded repository and organization alert reads,
with `hide_secret=true` on every request. Evidence retains alert metadata and
digests for commit/ref/path regions; it never retains literal secrets, token
values, raw location context, code, comments, or reviewer identity.

Fixture, recording, loopback, and `BLOCKED_ENV` provenance are always
`connected=false`, `native=false`, and `first_party=false`.
