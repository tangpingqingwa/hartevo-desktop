# GCP Spanner database result Layer-1 contract

This standalone contract exposes a bounded, read-only management-plane seam
for one exact Google Cloud Spanner instance, database, and optionally
referenced long-running operation. It retains only bounded state, timestamps,
dialect, configuration/encryption posture digests, and deterministic request,
response, registration, and evidence digests.

The crate deliberately has no SQL session, DDL/DML, schema or row path, IAM or
label reader, endpoint or key-name retention, backup/restore effect, instance
scaling, create/drop operation, kernel Truth/Consent/Effect/Receipt/Verification/
Outcome authority, or durable provider receipt claim. OAuth and service-account
handles are opaque `SecretReference` values; the raw handle is never
serialized or displayed.

Recording, fixture, fake, loopback, and `BLOCKED_ENV` transports always report
`connected=false`, `native=false`, and `first_party=false`. Native credential
resolution, live HTTPS, durable provider receipt, independent repeat-read
reconciliation, and verified Mission/Work Product adoption remain Layer-2
gaps.
