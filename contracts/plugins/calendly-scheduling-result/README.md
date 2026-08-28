# Calendly scheduled meeting-result contract

This directory defines the versioned Layer-1 contract for the Calendly
scheduled meeting-result capability. The Rust crate in
`hartevo-rs/calendly-scheduling-result-plugin` is a standalone nested
workspace; it does not edit Hartevo's root workspace or add host wiring.

The capability reads one bounded organization/user, event type, scheduled
event, and invitee-status projection from controlled fixture, recording, or
loopback data. It can also record redacted webhook change signals for
`invitee.created`, `invitee.canceled`, and no-show transitions. A result keeps
only opaque Calendly resource URIs, time/location metadata, state, bounded
attendance counts, and SHA-256 digests of tracking or provider fields. It
never retains invitee names, email addresses, custom answers, cancellation
text, booking links, join URLs, access tokens, or raw webhook payloads.

Layer 1 is read/proposal/recording-only. It has no calendar authority and no
booking or external-write operation: it cannot create or cancel invitees,
reschedule bookings, mark a no-show, create/delete a webhook subscription,
resolve live PAT/OAuth credentials, or claim a native Calendly connection.
Registrations are bound to the plugin version, contract, provider and
implementation revisions, permission lease, and exact Project/Mission/Work
Product scope. They can be revoked or unmounted and fail closed on drift.

The API vocabulary is based on the official Calendly API v2 and scheduled
event webhook documentation:

- <https://developer.calendly.com/getting-started>
- <https://developer.calendly.com/receive-data-from-scheduled-events-in-real-time-with-webhook-subscriptions>
- <https://developer.calendly.com/track-and-report-on-all-scheduled-events-across-your-organization>
