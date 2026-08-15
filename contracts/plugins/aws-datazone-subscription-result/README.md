# Amazon DataZone subscription-result Layer 1

This standalone contract is a bounded, digest-only read/proposal/record/verify
seam for an Amazon DataZone catalog asset and its subscription-request state.
It is below Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome,
and Work Product authority.

The provider boundary names only `GetAsset`,
`GetSubscriptionRequestDetails`, `GetSubscription`, and
`ListSubscriptionRequests`. The crate has recording, fixture, loopback, and
`BLOCKED_ENV` transports only. None is Connected, native, first-party, or a
durable provider receipt.

The projection preserves asset/listing and subscription-request/subscription
status, revision, request-reason, and reviewer-role digests, bounded timestamps,
and exact AWS account, region, DataZone domain/project/asset/listing/request/
subscription/grant/revision scope together with exact Project/Mission/Work
Product bindings. It does not retain raw schemas, metadata forms, principals,
data-access permissions, subscription-grant effects, names, descriptions,
request reasons, decision comments, or credential material.

A complete projection is external provider-state evidence only. It is not a
subscription approval, access grant, data-read authorization, business
verification, or adoptable Work Product. Native SigV4 resolution, live
DataZone HTTPS, durable provider receipts, grant/access readback, consented
subscription effects, and verified Mission adoption remain Layer-2 work.

## Layer-2 gaps

Native SigV4 and credential resolution; live DataZone HTTPS; durable provider
receipts; independent data-access/grant readback; subscription-request create,
accept, reject, cancel, or revoke effects; raw schema/form inspection; principal
identity resolution; and Hartevo Outcome or Work Product adoption remain
explicitly unimplemented.
