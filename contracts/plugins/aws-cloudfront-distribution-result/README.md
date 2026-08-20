# AWS CloudFront distribution result Layer 1

This standalone contract is a bounded, read-only CloudFront distribution
identity/configuration posture seam below Hartevo Truth, Consent, Effect,
Receipt, Verification, Outcome, and Work Product authority.

The provider names only the CloudFront `ListDistributions`, `GetDistribution`,
and `GetDistributionConfig` reads. `ListDistributions` uses a bounded opaque
marker; `GetDistributionConfig` is accepted only when its ETag digest matches
the distribution read and the registered configuration revision fence.

The projection retains distribution identity, status, enabled state,
last-modified time, ETag/config revision digests, alias/origin/TLS/WAF/cache
metadata digests, pagination completeness, and redacted request/cost receipts.
It never retains raw distribution configurations, policy bodies, origin
payloads, custom headers, viewer requests, signed URLs/cookies, or credential
material.

Recording, fixture, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`; they are not
first-party provider receipts. A ready projection is external provider-state
evidence only and is not an availability certification or verified adoption.

## Layer-2 gaps

Native SigV4 resolution and live CloudFront HTTPS; durable provider receipts;
independent edge URL/read-back reconciliation; UpdateDistribution,
CreateInvalidation, cache invalidation, origin/behavior/certificate/WAF
mutation; signed URL or signed cookie generation; viewer-request capture; raw
policy/config export; consented effects; production availability
certification; and verified Mission Work Product adoption remain Layer-2 work.
