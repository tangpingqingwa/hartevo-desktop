# YouTube channel root: phase-one read-only boundary

This root owns the shared typed channel request/identity boundary and one
provider vertical: authenticated YouTube Data API and YouTube Analytics reads.
It does not copy the generic Connector SDK lifecycle, create a central
registry, or own an Effect/publish path. TikTok and Reddit are sibling roots
with their own provider-specific ownership.

The YouTube surface is deliberately limited to read contracts:

- `channels.list` with `mine=true` establishes the exact OAuth account/channel,
  uploads playlist, and provider ETag.
- `videos.list` and `commentThreads.list` preserve exact content identity,
  revision/ETag, visibility, moderation/removal classification, and observation
  time.
- `reports.query` retains Analytics metrics, dimensions, rows, and channel
  identity without pretending Analytics requests consume YouTube Data API
  units.
- Every request carries an opaque credential reference and explicit OAuth
  scope; authorization, quota, rate-limit, revocation, and malformed-response
  outcomes are typed and fail closed.

CHANNEL-02 (#132) owns incremental cursor/checkpoint evidence and
webhook-hint/poll reconciliation on top of this root. It must consume these
exact identities rather than create a second provider contract. Reddit
controlled effects and TikTok reads remain separate product roots.

Fixtures and loopback HTTP tests prove deterministic contract behavior only.
They do not establish a Connected integration. Without external OAuth
credentials and provider approval, the live boundary remains
`BLOCKED_ENV`/`Disconnected`; no browser-scraping fallback is implied.

This is phase one and read-only. Any later publish/reply behavior must cross a
separate consent/effect boundary and cannot be inferred from these adapters.
