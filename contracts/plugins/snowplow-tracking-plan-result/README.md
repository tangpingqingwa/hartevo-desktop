# Snowplow tracking-plan evidence contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
Snowplow Event Studio tracking plans, event specifications, and change history.
It is not a Snowplow event collector, telemetry reader, identity store,
tracking-plan editor, subscription manager, replay engine, or Outcome
authority.

The checked-in Rust crate is a standalone nested workspace at
`hartevo-rs/snowplow-tracking-plan-result-plugin`. Its transports are limited to
fixture, recording, loopback, and `BLOCKED_ENV`; native HTTPS and credential
resolution remain explicit Layer-2 gaps. Raw event payloads, schemas, names,
authors, organization IDs, tracking-plan IDs, event-spec IDs, and credentials
are reduced to bounded digests before they cross the provider or Mission
consumer boundary.

Official provider references:

- [Managing tracking plans via the API](https://docs.snowplow.io/docs/event-studio/tracking-plans/api/)
- [Managing event specifications via the API](https://docs.snowplow.io/docs/event-studio/programmatic-management/event-specifications-api/)
- [Introduction to Snowplow events](https://docs.snowplow.io/docs/fundamentals/events/)
