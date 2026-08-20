# Jenkins build-result Layer-1 contract

This root defines a bounded, read-only Jenkins Remote Access JSON result seam
for one exact controller/folder/job/build and one Hartevo
Project/Mission/Work Product scope. It normalizes controller, folder, job,
branch, build, commit, test-summary, and artifact-metadata reads into typed
evidence and a proposal-only Mission projection.

The provider allowlist is GET-only. It never triggers, stops, replays,
rebuilds, configures, installs plugins, mutates Jenkins, reads console logs,
retains raw artifacts, retains source or script output, resolves credentials,
or claims kernel, Outcome, Truth, or Work Product authority.

The Rust crate is a standalone nested workspace at
`hartevo-rs/jenkins-build-result-plugin`. Its only transports are fixture,
recording, loopback, and `BLOCKED_ENV`; none is native HTTPS or Connected
evidence. Native credential resolution and live Jenkins readback remain
Layer-2 gaps.

Opaque `SecretReference` and cursor values retain only scoped digests. Source
JSON is reduced before it crosses the provider boundary, and request/response
receipts retain digests, sizes, status, and allowlisted operation names only.

The allowlist follows Jenkins’ [Remote Access API](https://www.jenkins.io/doc/book/using/remote-access-api/),
with this Layer-1 root intentionally limited to bounded GET JSON reads.
