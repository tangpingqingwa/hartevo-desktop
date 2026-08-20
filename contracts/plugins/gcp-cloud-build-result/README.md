# Google Cloud Build result contract

This Layer-1 contract is a bounded, read-only evidence and proposal seam for
the official Google Cloud Build `projects.builds.list` and
`projects.builds.get` methods. It binds a Google Cloud project, location,
build selector, trigger, source repository/commit, Hartevo Project/Mission/
Work Product revisions, and an explicit read-only consent and permission
scope.

The checked-in Rust crate is a standalone nested workspace at
`hartevo-rs/gcp-cloud-build-result-plugin`. It exposes typed
`GcpCloudBuildResultService`, `GcpCloudBuildProvider`, and
`MissionGcpBuildConsumer` seams. Fixture, recording, loopback, and
`BLOCKED_ENV` transports are deliberately `connected=false`, `native=false`,
and `firstParty=false`.

Only bounded build metadata is normalized: provider status, source and commit,
duration, trigger, artifact metadata, and step/result digests. Raw logs,
steps, arguments, environment variables, tokens, secret values, and
unbounded artifact bytes are never retained or serialized. Registration and
evidence digests fence contract/provider/permission/scope/version drift,
replay, tampering, pagination loops, and stale Mission revisions.

Layer 1 does not create, cancel, retry, or trigger builds; read arbitrary logs;
deploy artifacts; claim build correctness; or adopt kernel Truth, Outcome, or
Work Product authority. Native credential resolution, HTTPS, durable provider
receipts, independent read-back/reconciliation, consented build effects, and
verified Work Product adoption remain Layer-2 exits.
