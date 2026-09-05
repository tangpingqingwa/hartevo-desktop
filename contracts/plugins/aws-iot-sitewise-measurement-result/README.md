# AWS IoT SiteWise measurement-result Layer 1

This contract is a bounded, read-only, proposal-and-recording seam for one
AWS IoT SiteWise asset property and one exact Project/Mission/Work Product
scope. It allowlists only `ListAssets`, `DescribeAsset`,
`DescribeAssetProperty`, and `GetAssetPropertyValueHistory`.

The provider retains no raw telemetry. Measurement samples are consumed into
point, timestamp, value, quality, aggregate, min/max, and evidence digests;
the public proposal contains only redacted projections and bounded counts.
Time-window, quality, ascending-order, opaque-cursor, point-count, page-count,
and response-byte fences fail closed.

`SecretReference` is an opaque, scope-bound SigV4 handle digest. It is never
serialized or printed and Layer 1 never resolves it. Registration binds the
plugin, contract, provider revision/digest, exact allowlisted permissions,
consent, scope, secret reference digest, and registration revision. Revocation
and reversal change the registration digest and prevent stale proposals from
crossing the Mission consumer fence.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deterministic
or explicitly blocked and always report `connected=false`, `native=false`,
and `first_party=false`. There is no native HTTPS, credential resolution,
ingestion, asset/model/property mutation, gateway/device control, provider
receipt, physical-causality claim, Hartevo Outcome adoption, or verified Work
Product adoption. Those are explicit Layer-2 gaps.
