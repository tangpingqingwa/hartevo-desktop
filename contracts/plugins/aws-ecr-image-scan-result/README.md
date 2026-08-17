# AWS ECR image scan result contract

This standalone Layer-1 contract exposes bounded, read-only evidence for one
digest-pinned Amazon ECR image. The only provider seams are the official
`DescribeImages` and `DescribeImageScanFindings` reads. The result is suitable
for a Mission proposal, but it is not a deployment gate, a vulnerability
remediation authority, a receipt, or a kernel Outcome.

The Rust crate at `hartevo-rs/aws-ecr-image-scan-result-plugin` keeps registry,
account, region, repository, image digest, scan type, scan revision, Inspector
finding revision, Project, Mission, Work Product, permission, and scope
bindings explicit. SigV4 credentials and provider pagination are opaque. CVE,
package, and fix values are reduced to bounded digests and typed status data;
raw layers, image bytes, tags, paths, URLs, attributes, PII, credentials, and
provider response bodies are not retained.

Fixture, recording, loopback, and `BLOCKED_ENV` transports all report
`connected=false` and `native=false`. Native SigV4 resolution/HTTPS, live AWS
execution, durable native receipts, independent read-back, consented
deployment effects, remediation, and verified adoption remain Layer-2 gaps.
This evidence is intentionally distinct from Snyk project snapshots and
GitHub CodeQL code analysis.
