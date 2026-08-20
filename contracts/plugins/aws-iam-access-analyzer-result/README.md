# AWS IAM Access Analyzer result — Layer 1

This contract and the nested Rust workspace at
`hartevo-rs/aws-iam-access-analyzer-result-plugin` provide a standalone,
below-kernel vertical slice for reviewing bounded AWS IAM Access Analyzer
evidence before an external effect.

The slice binds the exact AWS account, Region, analyzer ARN and type, policy
type/resource type and revision, resource scope, Mission, Project, Consent,
permission snapshot, provider capability revision, and opaque SigV4/IAM
credential reference. It supports only bounded `ListFindingsV2` reads and
`ValidatePolicy` reads. Filters and pagination cursors are digest-bound to the
same scope and request configuration.

The provider accepts recording, fake, loopback, and `BLOCKED_ENV` transports.
It never resolves credentials, creates an analyzer, archives a finding,
attaches or mutates a policy, runs a paid check implicitly, or exposes raw
policy documents, principals, finding bodies, or secret material. Policy text,
principals, action names, conditions, finding details, and learning links are
represented only by bounded counts, locations, and digests. Empty findings do
not prove that access is safe, least privilege, or approved.

Evidence has explicit complete, empty-not-proof, partial, provider-unknown,
and blocked-environment states. Registration and consumer bindings are
version-, provider-, contract-, permission-, scope-, and evidence-digest
fenced, reversible, and revocable. The Mission consumer produces a review
candidate only; it does not adopt Truth or an Outcome and does not certify
least privilege.

Native SigV4 resolution, live HTTPS, durable provider receipts, independent
read-back, consented IAM effects, and kernel Verification/Outcome adoption are
Layer-2 exits.

Primary API references:

- [ListFindingsV2](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListFindingsV2.html)
- [ValidatePolicy](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html)
- [FindingSummaryV2](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_FindingSummaryV2.html)
- [IAM Access Analyzer findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html)
