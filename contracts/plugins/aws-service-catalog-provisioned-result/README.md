# AWS Service Catalog provisioned-product result — Layer 1

This standalone contract is a bounded, metadata-only
`SearchProvisionedProducts`, `DescribeProvisionedProduct`, `ListRecordHistory`,
and selected `DescribeRecord` read/proposal/record/verify seam. It remains
below Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome, and
verified Work Product authority.

The contract binds account, region, access level, portfolio, product and
artifact revisions, provisioned-product revision, record revision, Project,
Mission, and Work Product scope. Identifiers are digested at the boundary.
Search and history cursors are opaque and bound to the complete request
filter, scope, page size, and page number. Search pages are limited to 100
items and history pages to 20 items.

Projections retain only lifecycle status, bounded timestamps, record type,
coarse error class, revision fences, and digests for tags and outputs. Raw
parameter values, physical IDs, launch-role ARNs, resource outputs,
templates, provider messages, and PII are not retained.

Only recording, fixture, loopback, and `BLOCKED_ENV` transports are exposed;
all are `connected=false`, `native=false`, and `first_party=false`. Layer 1
does not resolve credentials, sign SigV4, use HTTPS, provision or mutate
products, retain durable provider receipts, perform independent read-back, or
adopt a Work Product or Outcome. Those are explicit Layer-2 gaps requiring a
separate authorization and host-owned Effect/Receipt/Verification boundary.
