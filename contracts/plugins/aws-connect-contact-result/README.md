# Amazon Connect contact-result Layer 1

This contract is a bounded, metadata-only Amazon Connect read/proposal/record
seam. It is intentionally below Hartevo Truth, Consent, Effect, Receipt,
Verification, Work Product, and Outcome authority.

The typed boundary is restricted to `SearchContacts`, `DescribeContact`, and
an allowlisted, digest-only `GetContactAttributes` projection. Every request is
bound to one AWS account, region, Connect instance, contact, queue, agent,
channel, required UTC time window, Project, Mission revision, and Work Product
revision. Search pages are at most 100 contacts and continuation tokens are
opaque and digest-bound to the exact query.

Only recording, fixture, loopback, and `BLOCKED_ENV` transports are available.
They never claim Connected, native, first-party, or durable provider evidence.
The contract retains lifecycle timestamps, assignment/channel classes,
disconnect-reason classes, and attribute key/value digests only. It does not
retain phone numbers, email addresses, transcripts, recordings, arbitrary
attribute keys or values, or raw provider messages.

Layer 1 does not send, transfer, disconnect, schedule, record, evaluate, or
mutate contacts. It has no native credential resolution, live HTTPS, durable
receipt, independent read-back, or verified Work Product/Outcome adoption.
