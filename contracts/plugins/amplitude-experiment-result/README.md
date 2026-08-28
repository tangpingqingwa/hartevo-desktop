# Amplitude experiment-result Layer 1

This contract is a standalone, proposal-only evidence slice for a Mission that
has already bound an Amplitude project, experiment, variants, metric,
exposure window, segment, Work Product, and revision fence.

The only provider path in the allowlist is the documented Dashboard REST saved
chart read, `GET /api/3/chart/{chart_id}/csv`. The Rust provider turns bounded
fixture/recording/loopback responses into normalized variant exposure counts,
metric values, provider-reported confidence/decision metadata, freshness, and
incomplete-data states. It never accepts arbitrary analytics queries, event
exports, raw user identifiers, or mutation operations.

All Layer-1 transports are explicitly `native: false` and `connected: false`.
`BLOCKED_ENV` means native credential/HTTPS authority is unavailable; it is not
evidence of an Amplitude connection or a successful experiment result. Native
credential resolution, native HTTPS, durable provider receipts, independent
read-back, experiment mutation, kernel Outcome persistence, and verified Work
Product adoption remain Layer-2 host-owned gaps.
