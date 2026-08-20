# AWS Firewall Manager policy-compliance result — Layer 1

This contract is a bounded, redacted read/proposal/record/verify seam for
AWS Firewall Manager control-plane policy and member-account compliance
posture. It owns `ListPolicies`, `GetPolicy`, `ListComplianceStatus`, and
`GetComplianceDetail` request fences only.

The scope is exact and digest-bound: organization, administrator account,
region, explicit policy allowlist, explicit member-account allowlist,
resource-type allowlist, Mission, Project, Work Product, permission snapshot,
consent expiry, and revisions. AWS identifiers, resource identifiers,
violation categories, and pagination tokens are represented in evidence by
digests; policy documents, managed rule-group bodies, raw violation metadata,
account PII, credentials, and data-plane rule content are not representable in
the public evidence model.

Fixture, fake, recording, loopback, and `BLOCKED_ENV` transports always report
`connected=false`, `native=false`, and `first_party=false`. A complete result
is external provider evidence and a Mission decision proposal, not a
certification, effective authorization, remediation/effect, durable native
receipt, independent native reread, Truth authority, or adopted Outcome or
Work Product.

Native SigV4 resolution, live HTTPS, durable provider receipt, independent
compliance reread/reconciliation, consented remediation/effects, certification,
and verified Mission Work Product adoption remain Layer-2 host authority.
