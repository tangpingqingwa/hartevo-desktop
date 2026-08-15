# CrowdStrike Falcon detection-result Layer 1

This contract is a bounded, read/proposal/recording/verification seam for
CrowdStrike Falcon `QueryDetects` and `GetDetectSummaries`. It is scoped to an
exact customer/cid, host/group selection, detection/alert selection, severity
and status filters, FQL digest, time window, and Project/Mission/Work Product
revision fences.

The nested Rust crate is intentionally independent of the root workspace. Its
only transports are fixture, recording, loopback, and `BLOCKED_ENV`; all four
are explicitly `connected=false`, `native=false`, and `first_party=false`.
The crate never resolves Falcon OAuth material, performs HTTPS, changes a
detection, assigns or tags a host, adds comments, quarantines a host, or
creates a durable native provider receipt.

Process command lines, user email, full host identifiers, raw device metadata,
and raw technique payloads are not retained. The typed projection keeps only
bounded digests and safe enums. Partial, empty, access-loss, provider-unknown,
tampered, stale, and revoked states are non-adoptable review evidence.

Native OAuth resolution, live Falcon HTTPS, independent native readback,
durable provider receipts, consented response effects, verified Work Product
adoption, and Hartevo Truth/Consent/Effect/Receipt/Verification/Outcome
authority remain explicit Layer-2 gaps.
