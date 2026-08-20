# AWS CodeArtifact provenance-result Layer 1

This contract is a standalone, bounded metadata read/proposal/recording seam
for AWS CodeArtifact package versions. It is scoped to one account, region,
domain, repository, format, optional namespace, package, version, Mission,
Project, and Work Product binding.

The provider exposes only `ListPackageVersions`,
`DescribePackageVersion`, and an optional bounded
`ListPackageVersionDependencies` read. It retains package-version origin,
status, revision and asset metadata, plus a digest/count summary of dependency
metadata. It never retains package bytes, raw dependency graphs, credentials,
publish/delete/status mutation capability, or arbitrary provider payloads.

Only recording, fixture, loopback, and `BLOCKED_ENV` transports are available.
All four are explicitly non-Connected, non-native, non-first-party, and do not
produce a durable provider receipt. A completed proposal is review-only
external provider-state evidence; it cannot become Hartevo Truth, Receipt,
Verification, Outcome, or Work Product authority.

Native SigV4 resolution, live HTTPS, durable provider receipts, independent
package-byte/read-back verification, and consented package effects remain
Layer-2 work. Fixture, recording, loopback, and `BLOCKED_ENV` paths never claim
Connected or native evidence.
