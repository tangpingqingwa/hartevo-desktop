# YouTube controlled publish effect plugin

This is the first-layer `YOUTUBE-EFFECT-01` provider plugin. It is a standalone
`channel-adapters` crate and owns only YouTube provider-bound publish contracts,
transport requests, durable checkpoints, and deterministic tests. It does not
own Effect authority, approval authority, credential storage, application
wiring, or the shared Connector SDK.

The provider boundary models the official read-before-write flow:

- authenticated channel probe through `channels.list?mine=true`;
- resumable `videos.insert` upload with title, visibility, and optional schedule;
- `videos.list` readback and verification of the provider receipt.

Every draft is bound to tenant, business, account, channel, provider generation,
asset SHA-256 digest, approval revision, and idempotency key. Dispatch always
probes first, then persists the upload session, exact byte offset, provider
receipt, and readback evidence. Reopening a checkpoint resumes the same opaque
session at the persisted offset; ambiguous upload starts enter reconciliation
instead of silently creating a second publish.

Quota exhaustion, provider reset observations, credential expiry, rotation,
revocation, and unmount fail closed. Provider reset receipts never invent a
wait or a new video. Mission consumers accept only fresh, complete,
production-provenance evidence with an exact provider/account/channel/generation
binding. A production transport must explicitly implement the
`YouTubeProductionTransport` marker; fixture and controlled-provider evidence
can exercise deterministic worlds but can never become first-party evidence.

The real entrypoint requires `HARTEVO_YOUTUBE_REAL_PUBLISH=1` and an opaque
`HARTEVO_YOUTUBE_SECRET_REFERENCE`. Without both, it returns
`BlockedEnvironment`; no local fake provider is presented as YouTube.

## Second-layer receipt/readback verification

The `YouTubeAuthorizedPublishEffect` boundary records an already-authorized
publish decision without granting authority or holding a secret. The
`YouTubePublishVerificationService` consumes that typed Effect and the exact
provider receipt, then issues only a `videos.list` readback. Receipt,
verification, and outcome evidence preserve the Effect/plugin revisions,
tenant/business/account/channel/provider-generation binding, request and
idempotency digests, provider request/response digests, and exact video state.

The verification checkpoint is durable and deterministic. A 429 persists the
provider reset receipt; reopen/retry repeats only readback, while processing
returns `Pending`. It becomes `Completed` only after a fresh, exact video and
channel readback confirms title, visibility, schedule, and ready status.
Effect expiry, plugin/effect/scope or credential drift, revoke/unmount,
private/public or channel mismatch, and readback mismatch invalidate or reject
the checkpoint without publishing again. Fixture and controlled evidence remain
non-production, and the real verification gate stays `BlockedEnvironment`
until an explicitly enabled production transport and secret reference exist.
