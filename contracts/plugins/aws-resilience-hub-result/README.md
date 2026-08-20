# AWS Resilience Hub result Layer 1

This standalone contract is a bounded read/proposal/record/verify seam for
AWS Resilience Hub application assessment posture. It covers only
`ListApps`, `DescribeApp`, `ListAppAssessments`, and `DescribeAppAssessment`.

The typed scope binds one AWS account and region, one application and
application version, one assessment and resiliency policy, and the owning
Mission, Project, and Work Product revisions. Application and assessment
allowlists are explicit and are digest-bound to the scope. The projection
retains only status, compliance, bounded resiliency score, RPO/RTO posture,
drift, bounded risk categories, timestamps, and digests. It never retains
resource ARNs, recommendation text, raw provider messages, tags, account PII,
or credentials.

Recording, fixture, fake, loopback, and `BLOCKED_ENV` transports are always
`connected=false`, `native=false`, and `first_party=false`. Layer 1 has no
assessment start, resource import, recommendation acceptance, policy
mutation, failover/recovery effect, durable native receipt, independent native
reread, or verified Mission adoption. Native SigV4/HTTPS and host-owned
Consent/Effect/Receipt/Verification remain Layer-2 work.
