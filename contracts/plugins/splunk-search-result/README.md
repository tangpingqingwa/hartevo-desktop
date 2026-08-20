# Splunk saved-search result contract

This Layer-1 contract is a bounded, read-only seam for inspecting the status
and aggregate projection of one already-running, explicitly scoped Splunk
saved-search job. It does not create, dispatch, cancel, or mutate searches;
accept arbitrary SPL; administer Splunk; retain raw events; or make a kernel
Truth, Consent, Effect, Receipt, Verification, or Outcome claim.

The checked-in Rust crate is a standalone nested workspace at
`hartevo-rs/splunk-search-result-plugin`. Its only transports are fixture,
recording, loopback, and `BLOCKED_ENV`. Each transport reports
`connected=false`, `native=false`, and `first_party=false`. Native HTTPS,
token/OAuth resolution, durable receipts, independent rereads, and verified
Mission adoption remain explicit Layer-2 gaps.

The provider is limited to the read-only Splunk Search Job status and results
endpoints for the registered SID. The projection keeps bounded status/timing,
field schema, aggregate cells, and deterministic search/SID/page/result
digests. String cell values are represented by digests; raw events, `_raw`,
source/host values, credentials, SPL, and PII are not retained.
