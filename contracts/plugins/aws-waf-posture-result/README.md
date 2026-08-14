# AWS WAF posture result — Layer 1

This contract is a bounded, read/proposal/record/verify seam for deciding
whether explicitly allowlisted resources are associated with an explicitly
allowlisted AWS WAF web ACL. It binds AWS account, region, CloudFront or
regional scope, web ACL and resource revisions, Mission, Project, Work
Product, permission, secret-reference, provider, contract, and evidence
digests.

The only provider operations are `ListWebACLs`, `GetWebACL`, and
`ListResourcesForWebACL`. Pagination is opaque and bounded. Evidence projects
default action, rule/action-class counts, association identity, and lock-token
or revision digests. It never retains rule statements, IP sets, request bodies,
sampled requests, raw provider payloads, raw cursors, secrets, or unbounded WAF
logs.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are deterministic
Layer-1 seams. They are always `connected=false`, `native=false`, and
`first_party=false`; `BLOCKED_ENV` is not a native provider. Registration and
recording are reversible, digest-fenced, and fail closed on scope or revision
drift, lock-token drift, cursor replay or loops, partial/unknown/access-loss,
throttle/timeout, tampering, replay conflicts, and revocation.

The Mission consumer emits a security/deployment decision proposal only. It
does not adopt Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome,
or Work Product authority. Layer 2 must add host-owned credentials, native
SigV4/live HTTPS, durable receipts, independent native read-back, explicit
consented effects, and verified Work Product adoption before any WAF mutation
or deployment promotion can be considered.
