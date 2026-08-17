# AWS Marketplace entitlement result contract

This directory is the contract root for `EXT-AWS-MARKETPLACE-ENTITLEMENT-01`.
The companion crate is a standalone Layer-1 boundary at
`hartevo-rs/aws-marketplace-entitlement-result-plugin`.

Layer 1 exposes only a bounded, review-only `GetEntitlements` proposal/read/
record/verify seam. Customer account identifiers, customer identifiers, license
ARNs, entitlement dimensions, raw entitlement values, credentials, and raw
pagination tokens are converted to digests at construction and are not retained
or serialized. The contract and provider are explicitly non-connected,
non-native, and non-first-party.

`ResolveCustomer`, `MeterUsage`, purchase, agreement, deployment, and
entitlement mutation remain forbidden Layer-2 exits. Native SigV4/HTTPS,
host-owned Consent/Effect/Receipt/Verification, independent native reread, and
verified Work Product adoption are also outside this root.
