# RudderStack event-quality result contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
RudderStack source metadata, tracking-plan versions, schema-violation
aggregates, destination delivery health, and governance metrics. It is not an
event collector, payload archive, destination writer, transformation engine,
tracking-plan mutation API, identity authority, or Mission Outcome/Truth
authority.

The Rust implementation is a standalone nested Cargo workspace at
`hartevo-rs/rudderstack-event-quality-plugin`. Its transports are fixture,
recording, loopback, and `BLOCKED_ENV`; native API-token resolution, native
HTTPS, durable provider receipts, independent readback, and verified adoption
remain Layer-2 gaps.
