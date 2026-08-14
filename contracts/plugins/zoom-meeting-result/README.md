# Zoom meeting result contract

`contract.v1.json` is the versioned Layer-1 contract for the Zoom meeting
decision-artifact capability. The Rust crate beside this contract is a
standalone nested workspace so its lockfile and gates do not alter Hartevo's
root workspace.

Layer 1 is bounded, read/projection/proposal-only. It accepts an opaque OAuth
`SecretReference`, projects meeting and cloud-recording/transcript/summary
metadata, and emits a deterministic non-mutating decision-artifact proposal.
It never stores or serializes OAuth material, signed download URLs, transcript
text, participant details, or media bytes. A metadata fingerprint is not a
content-byte digest and does not claim that content was read or verified.

The logical read capabilities are meeting occurrence metadata, cloud recording
metadata, transcript metadata, and meeting-summary metadata. The permitted
Zoom scope alternatives are `meeting:read`/`meeting:read:admin`,
`recording:read`/`recording:read:admin`, and
`meeting_summary:read`/`meeting_summary:read:admin`; no write or content-byte
scope is requested. Native Layer-2 must revalidate the current Marketplace
scope grant before any live transport is introduced.

The recording and fake providers are controlled test transports. They cannot
report native, first-party, or connected status. The `BLOCKED_ENV` provider is
the honest state for native OAuth/HTTPS/content access until a separate Layer-2
design is authorized.
