# Semgrep security-result plugin contract

This directory owns the standalone Layer-1 contract for Issue #371
(EXT-SEMGREP-01).

`SemgrepSecurityResultService` binds the exact API host, organization,
project, repository, ref, scan, commit, finding/rule allowlists, and Hartevo
Project/Mission/Work Product revisions. `SemgrepProvider` reads bounded
project, scan, Code/Supply Chain finding, and Secrets finding evidence through
a transport with no mutation methods. `MissionSemgrepSecurityConsumer`
validates the digest-fenced security decision proposal and records a local
consumption/replay projection without adopting a kernel Outcome.

The model covers Open, Reviewing, To Fix, Fixed, Ignored, Removed,
Provisionally Ignored, and Unknown finding statuses; Semgrep SAST, Secrets,
and SCA/reachability types; redacted rule/location metadata; branch, commit,
scan, finding, and rule revision drift; bounded pagination; duplicate/replay;
access loss; provider failures; stale Mission revisions; tamper, redaction,
and truncation failures; reversible unmount; and terminal revocation.

Only opaque API-token/OIDC `SecretReference` digests are recordable. Fixture,
fake, recording, loopback, and `BLOCKED_ENV` transports always report
`connected=false`, `native=false`, and `first_party=false`. No raw source,
secret value, unbounded finding export, finding triage/ignore write, code
mutation, PR/Jira write, tool execution, or generic security-registry
authority is represented.

The standalone nested Cargo workspace is at
`hartevo-rs/semgrep-security-result-plugin/`. Its receipt is an explicitly
non-durable recording. Native API-token/OIDC resolution, live Semgrep API
reads, durable provider receipts, independent scan reconciliation, and
verified Work Product adoption remain Layer-2 gaps.

Primary Semgrep references:

- [Semgrep API v1](https://semgrep.dev/api/v1/docs)
- [Semgrep findings and triage states](https://semgrep.dev/docs/for-developers/resolve-findings-through-app)
- [Semgrep Secrets triage](https://semgrep.dev/docs/semgrep-secrets/view-triage)
