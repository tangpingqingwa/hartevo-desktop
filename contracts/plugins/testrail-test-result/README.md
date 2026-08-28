# TestRail governed test-run result — Layer 1

This contract is a deliberately narrow read/proposal/recording boundary. It binds a Mission release or delivery objective to one TestRail host, project, suite, section, exact run revision, bounded test/result set, status allowlist, defect metadata, and a commit-or-release source reference.

The only provider paths are:

- `GET /api/v2/get_run/{run_id}`
- `GET /api/v2/get_tests/{run_id}`
- `GET /api/v2/get_results_for_run/{run_id}`

Pagination, response bytes, duplicate IDs, offset progression, status IDs, and source-version binding are bounded and fail closed. Result comments, defect keys, build/version values, attachments, screenshots, raw payloads, and API-key material do not enter the typed projection. Only redacted metadata and deterministic digests are retained.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are explicit non-native evidence. They always report `connected=false`, `native=false`, `first_party=false`, and `verified=false`. The Mission consumer emits a non-mutating proposal and a local replay-fenced recording; it has no adoption, Truth, Consent, Effect, Receipt, Verification, Outcome, UI, or kernel authority.

The API-key `SecretReference` is opaque and intentionally has no `Serialize` or `Deserialize` implementation. Layer 2 owns approved resolution and any native TestRail journey.
