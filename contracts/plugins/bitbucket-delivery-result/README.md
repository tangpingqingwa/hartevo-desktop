# Bitbucket delivery-result contract

This Layer-1 contract is a bounded, read-only evidence seam for Bitbucket
Cloud repository, pull-request, commit-status, pipeline, and deployment
metadata. It is a Mission-scoped proposal input, not a merge, approval,
decline, trigger, rollback, generic CI, source/diff/comment, artifact, or
Outcome authority.

The typed Rust crate is a standalone nested workspace at
`hartevo-rs/bitbucket-delivery-result-plugin`. Its test transports are fixture,
recording, fake, and loopback; the native boundary is explicitly
`BLOCKED_ENV`. None of those modes claims Connected, native, or first-party
status.

The provider allowlist is derived from the Bitbucket Cloud REST reference:
<https://developer.atlassian.com/cloud/bitbucket/rest/>. Native OAuth/API-token
resolution, live HTTPS, durable provider receipts, independent readback,
consented effects, and verified Work Product/Outcome adoption remain Layer-2
gaps.
